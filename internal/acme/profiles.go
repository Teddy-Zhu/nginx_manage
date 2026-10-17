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
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type Profile struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Notes            string       `json:"notes"`
	Version          int64        `json:"version"`
	AccountID        string       `json:"account_id"`
	CredentialID     string       `json:"credential_id"`
	ChallengeType    string       `json:"challenge_type"`
	HTTP01Confirmed  bool         `json:"http01_confirmed"`
	OrderUnconfirmed bool         `json:"order_unconfirmed"`
	Environment      string       `json:"environment"`
	Domains          []string     `json:"domains"`
	CertificateID    string       `json:"certificate_id"`
	State            string       `json:"state"`
	CurrentOrderID   string       `json:"current_order_id"`
	TaskID           string       `json:"task_id"`
	LastError        string       `json:"last_error"`
	RetryAfter       int64        `json:"retry_after"`
	CreatedAt        int64        `json:"created_at"`
	UpdatedAt        int64        `json:"updated_at"`
	AutoRenew        bool         `json:"auto_renew"`
	AutoDeploy       bool         `json:"auto_deploy"`
	DeployAfter      int64        `json:"deploy_after"`
	DeploymentError  string       `json:"deployment_error"`
	Renewal          RenewalState `json:"renewal"`
}
type ProfileInput struct {
	Name            string   `json:"name"`
	Notes           string   `json:"notes"`
	AccountID       string   `json:"account_id"`
	CredentialID    string   `json:"credential_id"`
	ChallengeType   string   `json:"challenge_type"`
	HTTP01Confirmed bool     `json:"http01_confirmed"`
	Domains         []string `json:"domains"`
}
type IssueInput struct {
	BaseVersion          int64 `json:"base_version"`
	NewOrder             bool  `json:"new_order"`
	AcknowledgeUncertain bool  `json:"acknowledge_uncertain"`
}
type ArchiveInput struct {
	BaseVersion          int64 `json:"base_version"`
	AcknowledgeUncertain bool  `json:"acknowledge_uncertain"`
}
type OrderView struct {
	ID                   string          `json:"id"`
	TaskID               string          `json:"task_id"`
	OrderURL             string          `json:"order_url"`
	CertificateURL       string          `json:"certificate_url"`
	CertificateVersionID string          `json:"certificate_version_id"`
	Automatic            bool            `json:"automatic"`
	Terminal             bool            `json:"terminal"`
	State                string          `json:"state"`
	Stage                string          `json:"stage"`
	LastError            string          `json:"last_error"`
	CreatedAt            int64           `json:"created_at"`
	DNSRecords           []DNSRecordView `json:"dns_records"`
	ChallengeType        string          `json:"challenge_type"`
	HTTP01State          string          `json:"http01_state"`
	HTTP01Revision       string          `json:"http01_revision"`
	HTTP01ExpiresAt      int64           `json:"http01_expires_at"`
}
type DNSRecordView struct {
	FQDN      string `json:"fqdn"`
	State     string `json:"state"`
	LastError string `json:"last_error"`
}

const profileColumns = "p.id,p.name,p.notes,p.version,COALESCE(p.account_id,''),COALESCE(p.credential_id,''),p.environment,p.domains,COALESCE(p.certificate_id,''),p.state,p.current_order_id,COALESCE((SELECT task_id FROM acme_orders WHERE id=p.current_order_id),''),p.last_error,p.retry_after,p.created_at,p.updated_at,p.auto_renew,p.auto_deploy,p.deploy_after,p.deployment_error,p.challenge_type,p.http01_confirmed,EXISTS(SELECT 1 FROM acme_orders u WHERE u.id=p.current_order_id AND u.submit_started=1 AND u.order_url='' AND u.certificate_version_id IS NULL)"

func scanProfile(row interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	var domains string
	err := row.Scan(&p.ID, &p.Name, &p.Notes, &p.Version, &p.AccountID, &p.CredentialID, &p.Environment, &domains, &p.CertificateID, &p.State, &p.CurrentOrderID, &p.TaskID, &p.LastError, &p.RetryAfter, &p.CreatedAt, &p.UpdatedAt, &p.AutoRenew, &p.AutoDeploy, &p.DeployAfter, &p.DeploymentError, &p.ChallengeType, &p.HTTP01Confirmed, &p.OrderUnconfirmed)
	if err == nil {
		err = json.Unmarshal([]byte(domains), &p.Domains)
	}
	return p, err
}
func profile(ctx context.Context, q reader, id string) (Profile, error) {
	p, err := scanProfile(q.QueryRowContext(ctx, "SELECT "+profileColumns+" FROM acme_profiles p WHERE p.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		err = fault.NotFound("ACME 签发配置不存在")
	}
	if err == nil {
		p.Renewal, err = renewal(ctx, q, id)
	}
	return p, err
}
func (s *Service) Profiles(ctx context.Context, limit, offset int64) ([]Profile, error) {
	if limit < 1 || limit > limits.PageSize || offset < 0 {
		return nil, fault.Invalid("分页参数无效")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+profileColumns+" FROM acme_profiles p ORDER BY CASE p.state WHEN 'archived' THEN 1 ELSE 0 END,p.created_at,p.id LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Renewal, err = renewal(ctx, s.DB, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func normalizeDomains(names []string) ([]string, error) {
	if len(names) == 0 || len(names) > 64 {
		return nil, fault.Invalid("申请域名须为 1 至 64 项")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		wildcard := strings.HasPrefix(name, "*.")
		base := strings.TrimPrefix(name, "*.")
		ascii, err := idna.Lookup.ToASCII(base)
		ascii = strings.ToLower(ascii)
		if err != nil || len(ascii) > 253 || net.ParseIP(ascii) != nil || !strings.Contains(ascii, ".") || strings.HasSuffix(ascii, ".") {
			return nil, fault.Invalid("须提供有效公网域名，通配符只允许位于最左侧")
		}
		for _, label := range strings.Split(ascii, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fault.Invalid("域名标签无效")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, fault.Invalid("域名标签无效")
				}
			}
		}
		if wildcard {
			ascii = "*." + ascii
		}
		if len(ascii) > 253 {
			return nil, fault.Invalid("申请域名不得超过 253 字节")
		}
		if seen[ascii] {
			return nil, fault.Invalid("申请域名存在重复")
		}
		seen[ascii] = true
		out = append(out, ascii)
	}
	sort.Strings(out)
	return out, nil
}
func (s *Service) CreateProfile(ctx context.Context, p auth.Principal, requestID, key string, in ProfileInput) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.profiles.create", "", in, func(tx *sql.Tx) (ChangeResult, error) {
		domains, err := normalizeDomains(in.Domains)
		if err != nil {
			return ChangeResult{}, err
		}
		if !validName(in.Name) || !utf8.ValidString(in.Notes) || len(in.Notes) > 2048 || strings.ContainsRune(in.Notes, 0) {
			return ChangeResult{}, fault.Invalid("名称或备注无效")
		}
		a, err := account(ctx, tx, in.AccountID)
		if err != nil {
			return ChangeResult{}, err
		}
		if a.State != "ready" {
			return ChangeResult{}, fault.Conflict("须先完成 ACME 账户注册")
		}
		switch in.ChallengeType {
		case "dns-01":
			if in.HTTP01Confirmed {
				return ChangeResult{}, fault.Invalid("DNS-01 不使用 HTTP-01 确认")
			}
			if _, err := credential(ctx, tx, in.CredentialID); err != nil {
				return ChangeResult{}, err
			}
		case "http-01":
			if !in.HTTP01Confirmed || in.CredentialID != "" {
				return ChangeResult{}, fault.Invalid("HTTP-01 须确认公网 80 端口与域名指向，且不使用 DNS 凭据")
			}
			for _, domain := range domains {
				if strings.HasPrefix(domain, "*.") {
					return ChangeResult{}, fault.Invalid("HTTP-01 不支持通配域名，请使用 DNS-01")
				}
			}
		default:
			return ChangeResult{}, fault.Invalid("验证方式须为 dns-01 或 http-01")
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles WHERE state!='archived'").Scan(&count); err != nil {
			return ChangeResult{}, err
		}
		if count >= limits.Certificates {
			return ChangeResult{}, fault.Conflict("ACME 签发配置数量已达上限")
		}
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles").Scan(&count); err != nil {
			return ChangeResult{}, err
		}
		if count >= limits.ACMEProfiles {
			return ChangeResult{}, fault.Conflict("ACME 签发配置已达保留上限")
		}
		id := secure.ID()
		raw, _ := json.Marshal(domains)
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_profiles(id,name,notes,version,account_id,credential_id,environment,domains,state,created_at,updated_at,challenge_type,http01_confirmed) VALUES(?,?,?,1,?,NULLIF(?,''),?,?,'idle',?,?,?,?)", id, in.Name, in.Notes, in.AccountID, in.CredentialID, a.Environment, string(raw), now, now, in.ChallengeType, in.HTTP01Confirmed); err != nil {
			return ChangeResult{}, err
		}
		out, err := profile(ctx, tx, id)
		return ChangeResult{ID: id, Profile: &out}, err
	})
}
func (s *Service) QueueIssue(ctx context.Context, p auth.Principal, requestID, key, id string, in IssueInput) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.profiles.issue", id, in, func(tx *sql.Tx) (ChangeResult, error) {
		return s.queueIssue(ctx, tx, id, in, false)
	})
}

func (s *Service) queueIssue(ctx context.Context, tx *sql.Tx, id string, in IssueInput, automatic bool) (ChangeResult, error) {
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return ChangeResult{}, err
	}
	if !enabled {
		return ChangeResult{}, fault.Conflict("Nginx 配置模块已停用")
	}
	item, err := profile(ctx, tx, id)
	if err != nil {
		return ChangeResult{}, err
	}
	if item.Version != in.BaseVersion {
		return ChangeResult{}, fault.Conflict("签发配置已变化，请刷新")
	}
	if automatic && (!item.AutoRenew || item.Renewal.Paused || item.CertificateID == "" || item.Renewal.RenewAt > time.Now().Unix() || item.State == "recovery_required") {
		return ChangeResult{}, fault.Conflict("自动续期条件已变化")
	}
	if item.State == "archived" || item.State == "issuing" {
		return ChangeResult{}, fault.Conflict("签发配置已停用或已有在途任务")
	}
	if item.ChallengeType == "http-01" {
		var busy int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('nginx.apply','nginx.validate','nginx.restore') AND state IN ('queued','running','compensating','recovery_required')").Scan(&busy); err != nil {
			return ChangeResult{}, err
		}
		if busy > 0 {
			return ChangeResult{}, fault.Conflict("HTTP-01 须等待 Nginx 操作完成或恢复")
		}
	}
	if time.Now().Unix() < item.RetryAfter {
		return ChangeResult{}, fault.Conflict("尚未到达允许重试时间")
	}
	a, err := account(ctx, tx, item.AccountID)
	if err != nil {
		return ChangeResult{}, err
	}
	if a.State != "ready" {
		return ChangeResult{}, fault.Conflict("ACME 账户尚未就绪")
	}
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required') AND NOT (kind='acme.issue' AND resource_id=? AND state='recovery_required')", id).Scan(&pending); err != nil {
		return ChangeResult{}, err
	}
	if pending >= limits.QueuedTasks {
		return ChangeResult{}, fault.Conflict("任务队列已满")
	}
	orderID := item.CurrentOrderID
	if !in.NewOrder && orderID != "" {
		var state string
		var terminal bool
		if err := tx.QueryRowContext(ctx, "SELECT t.state,o.terminal FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.id=?", orderID).Scan(&state, &terminal); err != nil {
			return ChangeResult{}, err
		}
		if terminal {
			var pending int
			if err := tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM acme_dns_records WHERE order_id=? AND state!='cleaned')+(SELECT COUNT(*) FROM acme_orders WHERE id=? AND http01_state IN ('unknown','active'))", orderID, orderID).Scan(&pending); err != nil {
				return ChangeResult{}, err
			}
			if pending == 0 {
				return ChangeResult{}, fault.Conflict("原订单已失效，须明确创建新订单")
			}
		}
		if state == "succeeded" {
			return ChangeResult{}, fault.Conflict("已有签发结果，申请新版本须明确创建新订单")
		}
	} else {
		var records int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_dns_records r JOIN acme_orders o ON o.id=r.order_id WHERE o.profile_id=? AND r.state!='cleaned'", id).Scan(&records); err != nil {
			return ChangeResult{}, err
		}
		if records > 0 {
			return ChangeResult{}, fault.Conflict("仍有未清理验证记录，请先恢复原任务")
		}
		if err := requireHTTP01Clean(ctx, tx, id); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM acme_dns_locks WHERE order_id IN (SELECT id FROM acme_orders WHERE profile_id=?)", id); err != nil {
			return ChangeResult{}, err
		}
		uncertain, err := unconfirmedOrder(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		if (item.State == "recovery_required" || uncertain) && !in.AcknowledgeUncertain {
			return ChangeResult{}, fault.Conflict("须确认原订单可能已在 CA 创建，才可建立新订单")
		}
		var retained, total int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders WHERE profile_id=? AND pruned_at=0", id).Scan(&retained); err != nil {
			return ChangeResult{}, err
		}
		if retained >= limits.CertificateVersions {
			return ChangeResult{}, fault.Conflict("签发订单已达保留上限，须先处理历史保留")
		}
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders WHERE pruned_at=0").Scan(&total); err != nil {
			return ChangeResult{}, err
		}
		if total >= limits.ACMEOrders {
			return ChangeResult{}, fault.Conflict("签发订单总数已达保留上限")
		}
		orderID = ""
	}
	now := time.Now().Unix()
	taskID := secure.ID()
	// Explicit recovery supersedes the old task without rewriting its history.
	if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='cancelled',stage='explicit_recovery',lease_until=NULL,updated_at=? WHERE resource_id=? AND kind='acme.issue' AND state='recovery_required'", now, id); err != nil {
		return ChangeResult{}, err
	}
	if orderID != "" {
		// The original order keeps its key, CSR and credential snapshot. Old task
		// history is preserved; the new task explicitly adopts that same order.
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'acme.issue',?,'queued','queued',?,?,?)", taskID, id, secure.ID(), now, now); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE acme_orders SET task_id=?,automatic=?,updated_at=? WHERE id=?", taskID, automatic, now, orderID); err != nil {
			return ChangeResult{}, err
		}
	} else {
		var count int
		if item.CertificateID == "" {
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&count); err != nil {
				return ChangeResult{}, err
			}
			if count >= limits.Certificates {
				return ChangeResult{}, fault.Conflict("证书数量已达上限")
			}
		} else {
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id=? AND pruned_at=0", item.CertificateID).Scan(&count); err != nil {
				return ChangeResult{}, err
			}
			if count >= limits.CertificateVersions {
				return ChangeResult{}, fault.Conflict("证书版本数量已达保留上限")
			}
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return ChangeResult{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ChangeResult{}, err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: item.Domains}, key)
		if err != nil {
			return ChangeResult{}, err
		}
		provider, plain := "", []byte("{}")
		if item.ChallengeType == "dns-01" {
			c, err := credential(ctx, tx, item.CredentialID)
			if err != nil {
				return ChangeResult{}, err
			}
			provider = c.Provider
			var encrypted []byte
			if err := tx.QueryRowContext(ctx, "SELECT secrets FROM dns_credentials WHERE id=?", c.ID).Scan(&encrypted); err != nil {
				return ChangeResult{}, err
			}
			plain, err = s.Vault.Open(encrypted, "acme:dns:"+c.ID)
			if err != nil {
				return ChangeResult{}, err
			}
		}
		replaces, err := s.replacesID(ctx, tx, item)
		if err != nil {
			return ChangeResult{}, err
		}
		orderID = secure.ID()
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'acme.issue',?,'queued','queued',?,?,?)", taskID, id, secure.ID(), now, now); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_orders(id,profile_id,task_id,account_id,provider,credentials,private_key,csr,created_at,updated_at,automatic,replaces_id,challenge_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", orderID, id, taskID, a.ID, provider, s.Vault.Seal(plain, "acme:order:"+orderID+":dns"), s.Vault.Seal(der, "acme:order:"+orderID+":key"), s.Vault.Seal(csr, "acme:order:"+orderID+":csr"), now, now, automatic, replaces, item.ChallengeType); err != nil {
			return ChangeResult{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET state='issuing',version=version+1,current_order_id=?,last_error='',retry_after=0,updated_at=? WHERE id=?", orderID, now, id); err != nil {
		return ChangeResult{}, err
	}
	out, err := profile(ctx, tx, id)
	return ChangeResult{ID: id, Profile: &out, TaskID: taskID}, err
}

func (s *Service) ArchiveProfile(ctx context.Context, p auth.Principal, requestID, key, id string, in ArchiveInput) (ChangeResult, error) {
	return s.change(ctx, p, requestID, key, "acme.profiles.archive", id, in, func(tx *sql.Tx) (ChangeResult, error) {
		item, err := profile(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		if item.Version != in.BaseVersion {
			return ChangeResult{}, fault.Conflict("签发配置已变化，请刷新")
		}
		if item.State == "issuing" {
			return ChangeResult{}, fault.Conflict("须先结束在途签发任务")
		}
		uncertain, err := unconfirmedOrder(ctx, tx, id)
		if err != nil {
			return ChangeResult{}, err
		}
		if (item.State == "recovery_required" || uncertain) && !in.AcknowledgeUncertain {
			return ChangeResult{}, fault.Conflict("须确认保留远端不确定结果并停止恢复，才可停用配置")
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_dns_records r JOIN acme_orders o ON o.id=r.order_id WHERE o.profile_id=? AND r.state!='cleaned'", id).Scan(&count); err != nil {
			return ChangeResult{}, err
		}
		if count > 0 {
			return ChangeResult{}, fault.Conflict("须先清理验证记录")
		}
		if err := requireHTTP01Clean(ctx, tx, id); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM acme_dns_locks WHERE order_id IN (SELECT id FROM acme_orders WHERE profile_id=?)", id); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='cancelled',stage='profile_archived',lease_until=NULL,updated_at=? WHERE resource_id=? AND kind='acme.issue' AND state='recovery_required'", time.Now().Unix(), id); err != nil {
			return ChangeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE acme_profiles SET state='archived',version=version+1,account_id=NULL,credential_id=NULL,auto_renew=0,auto_deploy=0,updated_at=? WHERE id=?", time.Now().Unix(), id); err != nil {
			return ChangeResult{}, err
		}
		out, err := profile(ctx, tx, id)
		return ChangeResult{ID: id, Profile: &out}, err
	})
}
func (s *Service) Orders(ctx context.Context, id string) ([]OrderView, error) {
	if _, err := profile(ctx, s.DB, id); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT o.id,o.task_id,o.order_url,o.certificate_url,COALESCE(o.certificate_version_id,''),t.state,t.stage,t.last_error,o.created_at,o.automatic,o.terminal,o.challenge_type,o.http01_state,o.http01_revision,o.http01_expires_at FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.profile_id=? AND o.pruned_at=0 ORDER BY o.created_at DESC,o.id", id)
	if err != nil {
		return nil, err
	}
	out := []OrderView{}
	for rows.Next() {
		var o OrderView
		o.DNSRecords = []DNSRecordView{}
		if err := rows.Scan(&o.ID, &o.TaskID, &o.OrderURL, &o.CertificateURL, &o.CertificateVersionID, &o.State, &o.Stage, &o.LastError, &o.CreatedAt, &o.Automatic, &o.Terminal, &o.ChallengeType, &o.HTTP01State, &o.HTTP01Revision, &o.HTTP01ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		records, err := s.DB.QueryContext(ctx, "SELECT fqdn,state,last_error FROM acme_dns_records WHERE order_id=? ORDER BY fqdn,id", out[i].ID)
		if err != nil {
			return nil, err
		}
		for records.Next() {
			var r DNSRecordView
			if err := records.Scan(&r.FQDN, &r.State, &r.LastError); err != nil {
				records.Close()
				return nil, err
			}
			out[i].DNSRecords = append(out[i].DNSRecords, r)
		}
		err = records.Err()
		records.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func requireHTTP01Clean(ctx context.Context, q reader, id string) error {
	var count int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders WHERE profile_id=? AND http01_state IN ('unknown','active')", id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fault.Conflict("HTTP-01 临时材料尚未确认清理，请恢复原任务")
	}
	return nil
}

func unconfirmedOrder(ctx context.Context, q reader, id string) (bool, error) {
	var count int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders o JOIN acme_profiles p ON p.current_order_id=o.id WHERE p.id=? AND o.submit_started=1 AND o.order_url='' AND o.certificate_version_id IS NULL", id).Scan(&count)
	return count > 0, err
}
