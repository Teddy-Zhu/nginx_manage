package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type reader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const accountColumns = "id,name,email,environment,version,key_fingerprint,account_url,state,task_id,last_error,retry_after,terms_agreed_at,created_at,updated_at"
const credentialColumns = "id,name,provider,version,field_names,created_at,updated_at"

func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	err := row.Scan(&a.ID, &a.Name, &a.Email, &a.Environment, &a.Version, &a.KeyFingerprint, &a.AccountURL, &a.State, &a.TaskID, &a.LastError, &a.RetryAfter, &a.TermsAgreedAt, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func account(ctx context.Context, q reader, id string) (Account, error) {
	a, err := scanAccount(q.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM acme_accounts WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, fault.NotFound("ACME 账户不存在")
	}
	return a, err
}

func (s *Service) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+accountColumns+" FROM acme_accounts ORDER BY created_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanCredential(row interface{ Scan(...any) error }) (DNSCredential, error) {
	var c DNSCredential
	var names string
	if err := row.Scan(&c.ID, &c.Name, &c.Provider, &c.Version, &names, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	err := json.Unmarshal([]byte(names), &c.FieldNames)
	return c, err
}

func credential(ctx context.Context, q reader, id string) (DNSCredential, error) {
	c, err := scanCredential(q.QueryRowContext(ctx, "SELECT "+credentialColumns+" FROM dns_credentials WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, fault.NotFound("DNS 凭据不存在")
	}
	return c, err
}

func (s *Service) Credentials(ctx context.Context) ([]DNSCredential, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+credentialColumns+" FROM dns_credentials ORDER BY created_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSCredential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Changes, their audit record and the replayable response commit together. No
// CA or DNS request is made while holding a database transaction.
func (s *Service) change(ctx context.Context, p auth.Principal, requestID, key, action, id string, in any, apply func(*sql.Tx) (ChangeResult, error)) (ChangeResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return ChangeResult{}, err
	}
	if key == "" || len(key) > 128 {
		return ChangeResult{}, fault.Invalid("幂等键无效")
	}
	encoded, err := json.Marshal(struct {
		Action, ID string
		Input      any
	}{action, id, in})
	if err != nil {
		return ChangeResult{}, err
	}
	digest := secure.Hash(encoded)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ChangeResult{}, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != digest {
			return ChangeResult{}, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, err := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if err != nil {
			return ChangeResult{}, err
		}
		var out ChangeResult
		err = json.Unmarshal(plain, &out)
		return out, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ChangeResult{}, err
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return ChangeResult{}, err
	}
	if !enabled {
		return ChangeResult{}, fault.Conflict("Nginx 配置模块已停用")
	}
	out, err := apply(tx)
	if err != nil {
		return out, err
	}
	response, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return out, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, p.ID, action, out.ID, now); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func validName(name string) bool {
	return utf8.ValidString(name) && strings.TrimSpace(name) != "" && len(name) <= 128 && !strings.ContainsAny(name, "\x00\r\n")
}

func queueAccount(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count >= limits.QueuedTasks {
		return "", fault.Conflict("任务队列已满")
	}
	taskID := secure.ID()
	now := time.Now().Unix()
	_, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'acme.account.register',?,'queued','queued',?,?,?)", taskID, id, secure.ID(), now, now)
	return taskID, err
}

func (s *Service) CreateAccount(ctx context.Context, p auth.Principal, requestID, key string, in AccountInput) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.accounts.create", "", in, func(tx *sql.Tx) (ChangeResult, error) {
		email, err := mail.ParseAddress(in.Email)
		if !validName(in.Name) || err != nil || email.Address != in.Email || len(in.Email) > 254 || !in.TermsAgreed || (in.Environment != "production" && in.Environment != "staging") {
			return ChangeResult{}, fault.Invalid("账户名称、邮箱、CA 环境或服务条款确认无效")
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_accounts").Scan(&count); err != nil {
			return ChangeResult{}, err
		}
		if count >= limits.ACMEAccounts {
			return ChangeResult{}, fault.Conflict("ACME 账户数量已达上限")
		}
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return ChangeResult{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return ChangeResult{}, err
		}
		pub, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			return ChangeResult{}, err
		}
		id := secure.ID()
		taskID, err := queueAccount(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		now := time.Now().Unix()
		_, err = tx.ExecContext(ctx, "INSERT INTO acme_accounts(id,name,email,environment,version,private_key,key_fingerprint,state,task_id,terms_agreed_at,created_at,updated_at) VALUES(?,?,?,?,1,?,?,'pending',?,?,?,?)", id, in.Name, in.Email, in.Environment, s.Vault.Seal(der, "acme:account:"+id+":key"), secure.Hash(pub), taskID, now, now, now)
		if err != nil {
			return ChangeResult{}, err
		}
		a, err := account(ctx, tx, id)
		return ChangeResult{ID: id, Account: &a, TaskID: taskID}, err
	})
}

func (s *Service) AccountAction(ctx context.Context, p auth.Principal, requestID, key, id, action string, in AccountAction) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.accounts."+action, id, in, func(tx *sql.Tx) (ChangeResult, error) {
		a, err := account(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		if a.Version != in.BaseVersion {
			return ChangeResult{}, fault.Conflict("ACME 账户已变化，请重新加载")
		}
		if a.State == "pending" || a.State == "registering" {
			return ChangeResult{}, fault.Conflict("账户注册任务尚未结束")
		}
		if action == "delete" {
			var refs int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles WHERE account_id=?", id).Scan(&refs); err != nil {
				return ChangeResult{}, err
			}
			if refs > 0 {
				return ChangeResult{}, fault.Conflict("仍有签发配置引用此 ACME 账户，请先停用签发配置")
			}
			_, err := tx.ExecContext(ctx, "DELETE FROM acme_accounts WHERE id=?", id)
			return ChangeResult{ID: id, Deleted: true}, err
		}
		if action != "register" || a.State != "failed" || !in.TermsAgreed {
			return ChangeResult{}, fault.Invalid("仅失败账户可确认服务条款后重试")
		}
		now := time.Now().Unix()
		if now < a.RetryAfter {
			return ChangeResult{}, fault.Conflict("尚未到达允许重试时间，请稍后刷新")
		}
		taskID, err := queueAccount(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE acme_accounts SET state='pending',task_id=?,terms_agreed_at=?,updated_at=?,version=version+1 WHERE id=?", taskID, now, now, id)
		if err != nil {
			return ChangeResult{}, err
		}
		a, err = account(ctx, tx, id)
		return ChangeResult{ID: id, Account: &a, TaskID: taskID}, err
	})
}

func validateSecrets(provider string, secrets map[string]string) ([]string, error) {
	var fields []CredentialField
	for _, definition := range DNSProviders() {
		if definition.ID == provider {
			fields = definition.Fields
			break
		}
	}
	if fields == nil {
		return nil, fault.Invalid("不支持的 DNS 提供商")
	}
	allowed := map[string]bool{}
	for _, field := range fields {
		allowed[field.Key] = true
		if field.Required && secrets[field.Key] == "" {
			return nil, fault.Invalid("缺少 DNS 凭据必填字段：" + field.Label)
		}
	}
	names := []string{}
	for key, value := range secrets {
		if !allowed[key] || value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fault.Invalid("DNS 凭据包含未知、空白或过长字段")
		}
		names = append(names, key)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Service) WriteCredential(ctx context.Context, p auth.Principal, requestID, key, id, action string, in DNSInput) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.dns_credentials."+action, id, in, func(tx *sql.Tx) (ChangeResult, error) {
		var prior DNSCredential
		if action == "create" {
			if in.BaseVersion != 0 {
				return ChangeResult{}, fault.Invalid("新凭据基础版本须为零")
			}
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_credentials").Scan(&count); err != nil {
				return ChangeResult{}, err
			}
			if count >= limits.DNSCredentials {
				return ChangeResult{}, fault.Conflict("DNS 凭据数量已达上限")
			}
			id = secure.ID()
		} else {
			var err error
			prior, err = credential(ctx, tx, id)
			if err != nil {
				return ChangeResult{}, err
			}
			if in.BaseVersion != prior.Version {
				return ChangeResult{}, fault.Conflict("DNS 凭据已变化，请重新加载")
			}
		}
		if action == "delete" {
			var refs int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles WHERE credential_id=?", id).Scan(&refs); err != nil {
				return ChangeResult{}, err
			}
			if refs > 0 {
				return ChangeResult{}, fault.Conflict("仍有签发配置引用此 DNS 凭据，请先停用签发配置")
			}
			_, err := tx.ExecContext(ctx, "DELETE FROM dns_credentials WHERE id=?", id)
			return ChangeResult{ID: id, Deleted: true}, err
		}
		if action != "create" && action != "update" {
			return ChangeResult{}, fault.Invalid("DNS 凭据操作无效")
		}
		if !validName(in.Name) || (action == "update" && in.Provider != prior.Provider) {
			return ChangeResult{}, fault.Invalid("凭据名称无效或提供商发生变化")
		}
		// An omitted secrets map retains the encrypted credentials on update.
		// A supplied map replaces all fields, so optional tokens can be removed.
		if in.Secrets == nil && action == "create" {
			return ChangeResult{}, fault.Invalid("新凭据须提供完整字段")
		}
		if in.Secrets != nil {
			names, err := validateSecrets(in.Provider, in.Secrets)
			if err != nil {
				return ChangeResult{}, err
			}
			plain, err := json.Marshal(in.Secrets)
			if err != nil {
				return ChangeResult{}, err
			}
			fields, _ := json.Marshal(names)
			now := time.Now().Unix()
			sealed := s.Vault.Seal(plain, "acme:dns:"+id)
			if action == "create" {
				_, err = tx.ExecContext(ctx, "INSERT INTO dns_credentials(id,name,provider,version,secrets,field_names,created_at,updated_at) VALUES(?,?,?,1,?,?,?,?)", id, in.Name, in.Provider, sealed, string(fields), now, now)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE dns_credentials SET name=?,version=version+1,secrets=?,field_names=?,updated_at=? WHERE id=?", in.Name, sealed, string(fields), now, id)
			}
			if err != nil {
				return ChangeResult{}, err
			}
		} else {
			if _, err := tx.ExecContext(ctx, "UPDATE dns_credentials SET name=?,version=version+1,updated_at=? WHERE id=?", in.Name, time.Now().Unix(), id); err != nil {
				return ChangeResult{}, err
			}
		}
		c, err := credential(ctx, tx, id)
		return ChangeResult{ID: id, Credential: &c}, err
	})
}
