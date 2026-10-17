package certificates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type Service struct {
	DB    *sql.DB
	Vault *secure.Vault
}
type Input struct {
	BaseVersion   int64  `json:"base_version"`
	Name          string `json:"name"`
	Notes         string `json:"notes"`
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}
type Version struct {
	ID              string  `json:"id"`
	Ordinal         int64   `json:"ordinal"`
	Summary         Summary `json:"summary"`
	CreatedAt       int64   `json:"created_at"`
	CertificatePath string  `json:"certificate_path"`
	PrivateKeyPath  string  `json:"private_key_path"`
	Environment     string  `json:"environment"`
}
type Binding struct {
	VersionID       string `json:"version_id"`
	RevisionID      string `json:"revision_id"`
	RevisionVersion int64  `json:"revision_version"`
	RevisionState   string `json:"revision_state"`
	ResourceID      string `json:"resource_id"`
	FileID          string `json:"file_id"`
	Purpose         string `json:"purpose"`
}
type Certificate struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Notes                string    `json:"notes"`
	Version              int64     `json:"version"`
	LatestVersionID      string    `json:"latest_version_id"`
	Source               string    `json:"source"`
	CreatedAt            int64     `json:"created_at"`
	UpdatedAt            int64     `json:"updated_at"`
	Versions             []Version `json:"versions"`
	Bindings             []Binding `json:"bindings"`
	HistoricalReferences int64     `json:"historical_references"`
	BindingsTruncated    bool      `json:"bindings_truncated"`
}
type Result struct {
	Certificate *Certificate `json:"certificate"`
	Deleted     bool         `json:"deleted"`
}

type reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Service) list(ctx context.Context, q reader, id string, detail bool) ([]Certificate, error) {
	out := []Certificate{}
	query := "SELECT id,name,notes,version,latest_version_id,source,created_at,updated_at FROM certificates"
	args := []any{}
	if id != "" {
		query += " WHERE id=?"
		args = append(args, id)
	}
	query += " ORDER BY created_at,id"
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c Certificate
		c.Versions = []Version{}
		c.Bindings = []Binding{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Notes, &c.Version, &c.LatestVersionID, &c.Source, &c.CreatedAt, &c.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		c := &out[i]
		versions, err := q.QueryContext(ctx, "SELECT id,ordinal,summary,created_at,environment FROM certificate_versions WHERE certificate_id=? AND pruned_at=0 AND (id=? OR ?) ORDER BY ordinal DESC", c.ID, c.LatestVersionID, detail)
		if err != nil {
			return nil, err
		}
		for versions.Next() {
			var v Version
			var data string
			if err := versions.Scan(&v.ID, &v.Ordinal, &data, &v.CreatedAt, &v.Environment); err != nil {
				versions.Close()
				return nil, err
			}
			if err := json.Unmarshal([]byte(data), &v.Summary); err != nil {
				versions.Close()
				return nil, err
			}
			v.CertificatePath = Path(c.ID, v.ID, "fullchain")
			v.PrivateKeyPath = Path(c.ID, v.ID, "privatekey")
			c.Versions = append(c.Versions, v)
		}
		err = versions.Err()
		versions.Close()
		if err != nil {
			return nil, err
		}
		bindingLimit := 11
		if detail {
			bindingLimit = 101
		}
		bindings, err := q.QueryContext(ctx, `SELECT DISTINCT cr.version_id,cr.revision_id,r.version,
 CASE WHEN cr.revision_id=h.desired_revision AND cr.revision_id=h.applied_revision THEN 'desired_applied' WHEN cr.revision_id=h.applied_revision THEN 'applied' WHEN cr.revision_id=h.desired_revision THEN 'desired' ELSE 'history' END,
 cr.resource_id,cr.file_id,cr.purpose FROM nginx_certificate_references cr JOIN config_revisions r ON r.id=cr.revision_id CROSS JOIN config_head h WHERE h.id=1 AND cr.certificate_id=? AND (cr.revision_id=h.desired_revision OR cr.revision_id=h.applied_revision) ORDER BY r.version DESC,cr.resource_id,cr.purpose LIMIT ?`, c.ID, bindingLimit)
		if err != nil {
			return nil, err
		}
		for bindings.Next() {
			var b Binding
			if err := bindings.Scan(&b.VersionID, &b.RevisionID, &b.RevisionVersion, &b.RevisionState, &b.ResourceID, &b.FileID, &b.Purpose); err != nil {
				bindings.Close()
				return nil, err
			}
			c.Bindings = append(c.Bindings, b)
		}
		err = bindings.Err()
		bindings.Close()
		if err != nil {
			return nil, err
		}
		if len(c.Bindings) == bindingLimit {
			c.BindingsTruncated = true
			c.Bindings = c.Bindings[:bindingLimit-1]
		}
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM nginx_certificate_references cr CROSS JOIN config_head h WHERE h.id=1 AND cr.certificate_id=? AND cr.revision_id!=COALESCE(h.desired_revision,'') AND cr.revision_id!=COALESCE(h.applied_revision,'')", c.ID).Scan(&c.HistoricalReferences); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Service) List(ctx context.Context) ([]Certificate, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := s.list(ctx, tx, "", false)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
func (s *Service) Get(ctx context.Context, id string) (Certificate, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Certificate{}, err
	}
	defer tx.Rollback()
	out, err := s.list(ctx, tx, id, true)
	if err != nil {
		return Certificate{}, err
	}
	if len(out) != 1 {
		return Certificate{}, fault.NotFound("证书不存在")
	}
	return out[0], tx.Commit()
}
func (s *Service) Write(ctx context.Context, p auth.Principal, requestID, key, id, action string, in Input) (Result, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return Result{}, err
	}
	if key == "" || len(key) > 128 || in.BaseVersion < 0 {
		return Result{}, fault.Invalid("证书版本或幂等键无效")
	}
	if action != "create" && action != "replace" && action != "delete" {
		return Result{}, fault.Invalid("证书操作无效")
	}
	if action != "create" && !uuid.MatchString(id) {
		return Result{}, fault.Invalid("证书 ID 无效")
	}
	encoded, _ := json.Marshal(struct {
		ID, Action string
		Input      Input
	}{id, action, in})
	digest := secure.Hash(encoded)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	var prior string
	var response []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &response)
	if err == nil {
		if prior != digest {
			return Result{}, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, err := s.Vault.Open(response, "idempotency:"+p.ID+":"+key)
		if err != nil {
			return Result{}, err
		}
		var result Result
		err = json.Unmarshal(plain, &result)
		return result, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return Result{}, err
	}
	if !enabled {
		return Result{}, fault.Conflict("Nginx 配置模块已停用")
	}
	var version int64
	if action == "create" {
		if in.BaseVersion != 0 {
			return Result{}, fault.Invalid("新证书基础版本须为零")
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&count); err != nil {
			return Result{}, err
		}
		if count >= limits.Certificates {
			return Result{}, fault.Conflict("证书数量已达 128 个")
		}
		id = secure.ID()
	} else {
		if err := tx.QueryRowContext(ctx, "SELECT version FROM certificates WHERE id=?", id).Scan(&version); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Result{}, fault.NotFound("证书不存在")
			}
			return Result{}, err
		}
		if version != in.BaseVersion {
			return Result{}, fault.Conflict("证书已变化，请重新加载")
		}
	}
	result := Result{}
	now := time.Now()
	if action != "create" {
		var active int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_profiles WHERE certificate_id=? AND state!='archived'", id).Scan(&active); err != nil {
			return Result{}, err
		}
		if active > 0 {
			return Result{}, fault.Conflict("此证书仍由 ACME 签发配置管理，请先停用该签发配置")
		}
	}
	if action == "delete" {
		var refs int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nginx_certificate_references WHERE certificate_id=?", id).Scan(&refs); err != nil {
			return Result{}, err
		}
		if refs > 0 {
			return Result{}, fault.Conflict("当前或历史修订仍引用此证书，须保留以便应用与回滚")
		}
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_deployments WHERE certificate_id=?", id).Scan(&refs); err != nil {
			return Result{}, err
		}
		if refs > 0 {
			return Result{}, fault.Conflict("历史部署记录仍引用此证书，无法删除证书资源；可在历史维护中清理未使用的旧版本材料")
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM certificate_versions WHERE certificate_id=?", id); err != nil {
			return Result{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM certificates WHERE id=?", id); err != nil {
			return Result{}, err
		}
		result.Deleted = true
	} else {
		if !utf8.ValidString(in.Name) || !utf8.ValidString(in.Notes) || strings.TrimSpace(in.Name) == "" || len(in.Name) > 128 || len(in.Notes) > 2048 || strings.ContainsRune(in.Name, 0) || strings.ContainsRune(in.Notes, 0) {
			return Result{}, fault.Invalid("证书名称或备注无效")
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id=? AND pruned_at=0", id).Scan(&count); err != nil {
			return Result{}, err
		}
		if count >= limits.CertificateVersions {
			return Result{}, fault.Conflict("证书已达 32 个不可变版本，需先处理历史保留")
		}
		pair, err := Parse(in.FullchainPEM, in.PrivateKeyPEM)
		if err != nil {
			return Result{}, fault.Invalid(err.Error())
		}
		if err := pair.Validate(now); err != nil {
			return Result{}, fault.Invalid(err.Error())
		}
		versionID := secure.ID()
		summary, err := json.Marshal(pair.Summary)
		if err != nil {
			return Result{}, err
		}
		if action == "create" {
			_, err = tx.ExecContext(ctx, "INSERT INTO certificates(id,name,notes,version,latest_version_id,source,created_at,updated_at) VALUES(?,?,?,?,?,'manual',?,?)", id, in.Name, in.Notes, 1, versionID, now.Unix(), now.Unix())
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE certificates SET name=?,notes=?,source='manual',version=version+1,latest_version_id=?,updated_at=? WHERE id=?", in.Name, in.Notes, versionID, now.Unix(), id)
		}
		if err != nil {
			return Result{}, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO certificate_versions(id,certificate_id,ordinal,fullchain,private_key,summary,created_at) VALUES(?,?,?,?,?,?,?)", versionID, id, version+1, s.Vault.Seal([]byte(pair.ChainPEM), purpose(id, versionID, "chain")), s.Vault.Seal([]byte(pair.KeyPEM), purpose(id, versionID, "key")), string(summary), now.Unix())
		if err != nil {
			return Result{}, err
		}
		all, err := s.list(ctx, tx, id, true)
		if err != nil {
			return Result{}, err
		}
		for i := range all {
			if all[i].ID == id {
				result.Certificate = &all[i]
				break
			}
		}
		if result.Certificate == nil {
			return Result{}, errors.New("certificate resource missing after import")
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		return Result{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(body, "idempotency:"+p.ID+":"+key), now.Unix()); err != nil {
		return Result{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, p.ID, "certificates."+action, id, now.Unix()); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{}, err
	}
	return result, nil
}
func purpose(id, version, part string) string {
	return "certificate:" + id + ":" + version + ":" + part
}
func (s *Service) Materials(ctx context.Context, q reader, paths []string) ([]Material, error) {
	unique := map[string]Material{}
	total := 0
	for _, name := range paths {
		id, version, _, ok := Reference(name)
		if !ok {
			if IsSystemCA(name) {
				continue
			}
			return nil, fault.Invalid("证书路径未登记为受管不可变版本")
		}
		if prior, seen := unique[version]; seen {
			if prior.CertificateID != id {
				return nil, fault.Invalid("证书版本与资源不匹配")
			}
			continue
		}
		var chain, key []byte
		var environment string
		if err := q.QueryRowContext(ctx, "SELECT CASE WHEN length(fullchain)<=? THEN fullchain ELSE NULL END,CASE WHEN length(private_key)<=? THEN private_key ELSE NULL END,substr(environment,1,33) FROM certificate_versions WHERE certificate_id=? AND id=? AND pruned_at=0", limits.CertificateMaterialBytes+64, limits.CertificateMaterialBytes+64, id, version).Scan(&chain, &key, &environment); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fault.Invalid("证书版本不存在或材料已清理")
			}
			return nil, err
		}
		plainChain, err := s.Vault.Open(chain, purpose(id, version, "chain"))
		if err != nil {
			return nil, err
		}
		plainKey, err := s.Vault.Open(key, purpose(id, version, "key"))
		if err != nil {
			return nil, err
		}
		total += len(plainChain) + len(plainKey)
		if total > limits.CertificateBundleBytes {
			return nil, fault.Invalid("配置引用的证书材料超过 1 MiB")
		}
		unique[version] = Material{CertificateID: id, VersionID: version, FullchainPEM: string(plainChain), PrivateKeyPEM: string(plainKey), Environment: environment}
	}
	out := make([]Material, 0, len(unique))
	for _, material := range unique {
		out = append(out, material)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VersionID < out[j].VersionID })
	return out, nil
}
