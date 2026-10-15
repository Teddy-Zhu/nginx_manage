package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	legoacme "github.com/go-acme/lego/v5/acme"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type TransferAccount struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	Environment   string `json:"environment"`
	PrivateKey    []byte `json:"private_key"`
	AccountURL    string `json:"account_url"`
	Registration  []byte `json:"registration"`
	TermsAgreedAt int64  `json:"terms_agreed_at"`
}
type TransferProfile struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Notes         string   `json:"notes"`
	AccountID     string   `json:"account_id"`
	CredentialID  string   `json:"credential_id"`
	CertificateID string   `json:"certificate_id"`
	ChallengeType string   `json:"challenge_type"`
	Domains       []string `json:"domains"`
}
type TransferAutomation struct {
	Accounts []TransferAccount `json:"accounts"`
	Profiles []TransferProfile `json:"profiles"`
}

func (s *Service) ExportAutomation(ctx context.Context, tx *sql.Tx) (TransferAutomation, error) {
	out := TransferAutomation{Accounts: []TransferAccount{}, Profiles: []TransferProfile{}}
	var busy int
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM acme_accounts WHERE state!='ready')+(SELECT COUNT(*) FROM acme_profiles WHERE state IN ('issuing','recovery_required'))").Scan(&busy); err != nil {
		return out, err
	}
	if busy > 0 {
		return out, fault.Conflict("须先完成账户注册、签发与恢复后再导出 ACME 配置")
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,name,email,environment,private_key,account_url,registration,terms_agreed_at FROM acme_accounts ORDER BY id")
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var a TransferAccount
		var key, registration []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Email, &a.Environment, &key, &a.AccountURL, &registration, &a.TermsAgreedAt); err != nil {
			rows.Close()
			return out, err
		}
		a.PrivateKey, err = s.Vault.Open(key, "acme:account:"+a.ID+":key")
		if err != nil {
			rows.Close()
			return out, err
		}
		a.Registration, err = s.Vault.Open(registration, "acme:account:"+a.ID+":registration")
		if err != nil {
			rows.Close()
			return out, err
		}
		out.Accounts = append(out.Accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT id,name,notes,COALESCE(account_id,''),COALESCE(credential_id,''),COALESCE(certificate_id,''),challenge_type,domains FROM acme_profiles WHERE state!='archived' ORDER BY id")
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var p TransferProfile
		var domains string
		if err := rows.Scan(&p.ID, &p.Name, &p.Notes, &p.AccountID, &p.CredentialID, &p.CertificateID, &p.ChallengeType, &domains); err != nil {
			return out, err
		}
		if err := json.Unmarshal([]byte(domains), &p.Domains); err != nil {
			return out, err
		}
		out.Profiles = append(out.Profiles, p)
	}
	return out, rows.Err()
}

func accountTransferFingerprint(a TransferAccount) (string, error) {
	invalid := fault.Invalid("迁移 ACME 账户材料或 CA 绑定无效")
	if !transferUUID.MatchString(a.ID) || !validName(a.Name) || len(a.Email) > 254 || len(a.PrivateKey) > 4096 || len(a.Registration) > 64<<10 || a.TermsAgreedAt <= 0 {
		return "", invalid
	}
	email, err := mail.ParseAddress(a.Email)
	if err != nil || email.Address != a.Email {
		return "", invalid
	}
	private, err := x509.ParsePKCS8PrivateKey(a.PrivateKey)
	if err != nil {
		return "", invalid
	}
	key, ok := private.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", invalid
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", invalid
	}
	directoryURL, err := directory(a.Environment)
	if err != nil {
		return "", invalid
	}
	base, err := url.Parse(directoryURL)
	if err != nil {
		return "", invalid
	}
	account, err := url.Parse(a.AccountURL)
	if err != nil || account.Scheme != "https" || account.Host != base.Host || account.User != nil || account.RawQuery != "" || account.Fragment != "" || !strings.HasPrefix(account.Path, "/acme/acct/") || len(a.AccountURL) > 2048 {
		return "", invalid
	}
	accountNumber := strings.TrimPrefix(account.Path, "/acme/acct/")
	if accountNumber == "" || len(accountNumber) > 32 || strings.Trim(accountNumber, "0123456789") != "" {
		return "", invalid
	}
	var registration legoacme.ExtendedAccount
	if json.Unmarshal(a.Registration, &registration) != nil || registration.Location != a.AccountURL {
		return "", invalid
	}
	return secure.Hash(der), nil
}

func ValidateTransferAutomation(in TransferAutomation, credentials []TransferCredential, certificates map[string]string) error {
	if len(in.Accounts) > limits.ACMEAccounts || len(in.Profiles) > limits.Certificates {
		return fault.Invalid("ACME 迁移数量超过限制")
	}
	accounts := map[string]bool{}
	keys := map[string]bool{}
	creds := map[string]bool{}
	profiles := map[string]bool{}
	certs := map[string]bool{}
	for _, c := range credentials {
		creds[c.ID] = true
	}
	for _, a := range in.Accounts {
		fingerprint, err := accountTransferFingerprint(a)
		if err != nil {
			return err
		}
		key := a.Environment + ":" + fingerprint
		if accounts[a.ID] || keys[key] {
			return fault.Invalid("ACME 账户存在重复")
		}
		accounts[a.ID] = true
		keys[key] = true
	}
	for _, p := range in.Profiles {
		if !transferUUID.MatchString(p.ID) || profiles[p.ID] || !validName(p.Name) || !utf8.ValidString(p.Notes) || len(p.Notes) > 2048 || strings.ContainsRune(p.Notes, 0) || !accounts[p.AccountID] {
			return fault.Invalid("ACME 签发配置或账户引用无效")
		}
		profiles[p.ID] = true
		if p.CertificateID != "" {
			if certificates[p.CertificateID] == "" || certs[p.CertificateID] {
				return fault.Invalid("ACME 证书引用缺失或重复")
			}
			certs[p.CertificateID] = true
		}
		names, err := normalizeDomains(p.Domains)
		if err != nil {
			return err
		}
		if p.ChallengeType == "dns-01" {
			if !creds[p.CredentialID] {
				return fault.Invalid("ACME DNS 凭据引用缺失")
			}
		} else if p.ChallengeType == "http-01" {
			if p.CredentialID != "" {
				return fault.Invalid("HTTP-01 不使用 DNS 凭据")
			}
			for _, name := range names {
				if strings.HasPrefix(name, "*.") {
					return fault.Invalid("HTTP-01 不支持通配域名")
				}
			}
		} else {
			return fault.Invalid("迁移验证方式无效")
		}
	}
	return nil
}

func (s *Service) ImportAutomation(ctx context.Context, tx *sql.Tx, in TransferAutomation, credentials []TransferCredential, certIDs, credentialIDs map[string]string) error {
	if err := ValidateTransferAutomation(in, credentials, certIDs); err != nil {
		return err
	}
	accounts := map[string]string{}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles").Scan(&count); err != nil {
		return err
	}
	if count+len(in.Profiles) > limits.ACMEProfiles {
		return fault.Conflict("目标 ACME 签发配置容量不足")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles WHERE state!='archived'").Scan(&count); err != nil {
		return err
	}
	if count+len(in.Profiles) > limits.Certificates {
		return fault.Conflict("目标活跃 ACME 签发配置容量不足")
	}
	for _, a := range in.Accounts {
		fingerprint, err := accountTransferFingerprint(a)
		if err != nil {
			return err
		}
		var id, state, accountURL string
		err = tx.QueryRowContext(ctx, "SELECT id,state,account_url FROM acme_accounts WHERE environment=? AND key_fingerprint=?", a.Environment, fingerprint).Scan(&id, &state, &accountURL)
		if err == nil {
			if state != "ready" || accountURL != a.AccountURL {
				return fault.Conflict("目标同一 ACME 账户尚未就绪或 CA 身份冲突")
			}
			accounts[a.ID] = id
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_accounts").Scan(&count); err != nil {
			return err
		}
		if count >= limits.ACMEAccounts {
			return fault.Conflict("目标 ACME 账户容量不足")
		}
		id = secure.ID()
		taskID := secure.ID()
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'migration.acme.account',?,'succeeded','imported',?,?,?)", taskID, id, secure.ID(), now, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_accounts(id,name,email,environment,version,private_key,key_fingerprint,registration,account_url,state,task_id,terms_agreed_at,created_at,updated_at) VALUES(?,?,?,?,1,?,?,?,?,'ready',?,?,?,?)", id, a.Name, a.Email, a.Environment, s.Vault.Seal(a.PrivateKey, "acme:account:"+id+":key"), fingerprint, s.Vault.Seal(a.Registration, "acme:account:"+id+":registration"), a.AccountURL, taskID, a.TermsAgreedAt, now, now); err != nil {
			return err
		}
		accounts[a.ID] = id
	}
	for _, p := range in.Profiles {
		id := secure.ID()
		names, err := normalizeDomains(p.Domains)
		if err != nil {
			return err
		}
		domains, err := json.Marshal(names)
		if err != nil {
			return err
		}
		accountID := accounts[p.AccountID]
		certID := certIDs[p.CertificateID]
		now := time.Now().Unix()
		var environment string
		if err := tx.QueryRowContext(ctx, "SELECT environment FROM acme_accounts WHERE id=?", accountID).Scan(&environment); err != nil {
			return err
		}
		state := "idle"
		if certID != "" {
			state = "issued"
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_profiles(id,name,notes,version,account_id,credential_id,environment,domains,certificate_id,state,created_at,updated_at,challenge_type,http01_confirmed,auto_renew,auto_deploy) VALUES(?,?,?,1,?,NULLIF(?,''),?,?,NULLIF(?,''),?,?,?,?,0,0,0)", id, p.Name, p.Notes, accountID, credentialIDs[p.CredentialID], environment, string(domains), certID, state, now, now, p.ChallengeType); err != nil {
			return err
		}
		if certID != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE certificates SET source='acme' WHERE id=?", certID); err != nil {
				return err
			}
		}
	}
	return nil
}
