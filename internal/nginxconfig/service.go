package nginxconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

var ErrConflict = errors.New("修订已变化，请重新加载后保存")
var ErrInvalid = errors.New("配置未通过校验；可保存为独立草稿")
var ErrNotFound = errors.New("资源不存在")

type Service struct {
	DB              *sql.DB
	Vault           *secure.Vault
	Policy          Policy
	RequireFeatures func(context.Context, []string) error
	Certificates    *certificates.Service
}
type SaveRequest struct {
	BaseVersion int64  `json:"base_version"`
	Files       []File `json:"files"`
	Draft       bool   `json:"draft"`
	Validate    bool   `json:"validate"`
	Apply       bool   `json:"apply"`
}
type SaveResult struct {
	Tree   Tree   `json:"tree"`
	TaskID string `json:"task_id,omitempty"`
}

func (s *Service) Current(ctx context.Context) (Tree, error) {
	return s.snapshot(ctx, dbgen.New(s.DB))
}

// Snapshot participates in the caller's consistent logical export transaction.
func (s *Service) Snapshot(ctx context.Context, tx *sql.Tx) (Tree, error) {
	return s.snapshot(ctx, dbgen.New(tx))
}

func (s *Service) snapshot(ctx context.Context, q *dbgen.Queries) (Tree, error) {
	head, err := q.GetConfigHead(ctx)
	if err != nil {
		return Tree{}, err
	}
	if !head.DesiredRevision.Valid {
		p, err := Parse(InitialFiles(), s.Policy)
		if err != nil {
			return Tree{}, err
		}
		p.Tree.State = "unsaved"
		p.Tree.Version = head.Version
		return p.Tree, nil
	}
	tree, err := s.get(ctx, head.DesiredRevision.String, q)
	tree.Version = head.Version
	return tree, err
}

func (s *Service) Get(ctx context.Context, id string) (Tree, error) {
	return s.get(ctx, id, dbgen.New(s.DB))
}
func (s *Service) get(ctx context.Context, id string, q *dbgen.Queries) (Tree, error) {
	r, err := q.GetRevision(ctx, id)
	if err == sql.ErrNoRows {
		return Tree{}, ErrNotFound
	}
	if err != nil {
		return Tree{}, err
	}
	tree := Tree{RevisionID: r.ID, Version: r.Version, State: r.State, Files: []File{}, Resources: []Resource{}, Diagnostics: []Diagnostic{}}
	if err := json.Unmarshal([]byte(r.Diagnostics), &tree.Diagnostics); err != nil {
		return tree, err
	}
	files, err := q.GetRevisionFiles(ctx, id)
	if err != nil {
		return tree, err
	}
	for _, f := range files {
		plain, err := s.Vault.Open(f.Content, "nginx:"+id+":"+f.ID)
		if err != nil {
			return tree, fmt.Errorf("decrypt configuration: %w", err)
		}
		tree.Files = append(tree.Files, File{f.ID, f.Path, string(plain), f.Sha256})
	}
	bindings, err := q.GetRevisionBindings(ctx, id)
	if err != nil {
		return tree, err
	}
	for _, b := range bindings {
		plain, err := s.Vault.Open(b.Projection, "projection:"+id+":"+b.ResourceID)
		if err != nil {
			return tree, err
		}
		var resource Resource
		if err := json.Unmarshal(plain, &resource); err != nil {
			return tree, err
		}
		tree.Resources = append(tree.Resources, resource)
	}
	tree.AccessLists = accessLists(tree.Files)
	parsed, parseErr := Parse(tree.Files, s.Policy)
	if parseErr != nil {
		return tree, parseErr
	}
	tree.WAFPolicies = parsed.Tree.WAFPolicies
	tree.ModulePaths = parsed.Tree.ModulePaths
	return tree, nil
}

func (s *Service) Save(ctx context.Context, principal auth.Principal, requestID, key string, in SaveRequest) (SaveResult, error) {
	encoded, err := json.Marshal(in)
	if err != nil {
		return SaveResult{}, err
	}
	return s.save(ctx, principal, requestID, key, in, secure.Hash(encoded))
}

func (s *Service) save(ctx context.Context, principal auth.Principal, requestID, key string, in SaveRequest, digest string) (SaveResult, error) {
	return s.saveLinked(ctx, principal, requestID, key, in, digest, false, nil)
}

// Certificate deployment links its task in the same transaction as the revision.
func (s *Service) saveLinked(ctx context.Context, principal auth.Principal, requestID, key string, in SaveRequest, digest string, requireApplied bool, link func(*sql.Tx, SaveResult) error) (SaveResult, error) {
	return s.savePrepared(ctx, principal, requestID, key, in, digest, requireApplied, nil, link)
}

// SaveImported inserts dependencies and links the migration in the same commit
// as its revision and execution intent. Imported material never bypasses Parse.
func (s *Service) SaveImported(ctx context.Context, principal auth.Principal, requestID, key, planID string, in SaveRequest, prepare func(*sql.Tx) error, link func(*sql.Tx, SaveResult) error) (SaveResult, error) {
	if err := principal.Require("backup.restore"); err != nil {
		return SaveResult{}, err
	}
	raw, err := json.Marshal(struct {
		PlanID string
		Input  SaveRequest
	}{planID, in})
	if err != nil {
		return SaveResult{}, err
	}
	return s.savePrepared(ctx, principal, requestID, key, in, secure.Hash(raw), false, prepare, link)
}

func (s *Service) savePrepared(ctx context.Context, principal auth.Principal, requestID, key string, in SaveRequest, digest string, requireApplied bool, prepare func(*sql.Tx) error, link func(*sql.Tx, SaveResult) error) (SaveResult, error) {
	if err := principal.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	if key == "" || len(key) > 128 {
		return SaveResult{}, fault.Invalid("需要 1–128 字节 Idempotency-Key")
	}
	if in.BaseVersion < 0 {
		return SaveResult{}, fault.Invalid("基础修订版本无效")
	}
	if in.Draft && (in.Validate || in.Apply) {
		return SaveResult{}, fault.Invalid("草稿不能进入执行队列")
	}
	if in.Validate && in.Apply {
		return SaveResult{}, fault.Invalid("请选择校验或应用")
	}
	// Replay is checked before parsing and before the optimistic version check.
	if result, found, err := s.replay(ctx, principal.ID, key, digest); found || err != nil {
		return result, err
	}
	p, err := Parse(in.Files, s.Policy)
	if err != nil {
		return SaveResult{}, fault.Invalid(err.Error())
	}
	if !in.Draft {
		if len(p.Tree.Diagnostics) > 0 {
			return SaveResult{Tree: p.Tree}, ErrInvalid
		}
		if err := principal.Require(p.RequiredScopes...); err != nil {
			return SaveResult{}, err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return SaveResult{}, err
	}
	defer tx.Rollback()
	var migrating int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required')").Scan(&migrating); err != nil {
		return SaveResult{}, err
	}
	if migrating > 0 {
		return SaveResult{}, fault.Conflict("迁移正在应用或等待恢复，暂不能修改 Nginx 配置")
	}
	if prepare != nil {
		if err := prepare(tx); err != nil {
			return SaveResult{}, err
		}
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return SaveResult{}, err
	}
	if !enabled {
		return SaveResult{}, fault.Conflict("Nginx 配置模块已停用")
	}
	var version int64
	var parent, applied sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT version,desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&version, &parent, &applied); err != nil {
		return SaveResult{}, err
	}
	if version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	if requireApplied && (!parent.Valid || parent.String != applied.String) {
		return SaveResult{}, fault.Conflict("存在待应用的 Nginx 配置，须先处理后再部署证书")
	}
	if !in.Draft {
		if err := s.requireRevisionScopes(ctx, principal, parent.String, dbgen.New(tx)); err != nil {
			return SaveResult{}, err
		}
		if in.Apply && applied.String != parent.String {
			if err := s.requireRevisionScopes(ctx, principal, applied.String, dbgen.New(tx)); err != nil {
				return SaveResult{}, err
			}
		}
	}
	var certificateUses []CertificateUse
	if !in.Draft {
		certificateUses, err = s.validateCertificates(ctx, tx, p)
		if err != nil {
			return SaveResult{}, err
		}
	}
	var next int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0)+1 FROM config_revisions").Scan(&next); err != nil {
		return SaveResult{}, err
	}
	if next <= version {
		next = version + 1
	}
	id := secure.ID()
	state := "desired"
	if in.Draft {
		state = "draft"
	}
	if err := insertRevision(ctx, tx, s.Vault, s.Policy.Version, p, id, parent, next, state, principal.ID, time.Now().Unix(), certificateUses); err != nil {
		return SaveResult{}, err
	}
	if !in.Draft {
		if _, err := tx.ExecContext(ctx, "UPDATE config_head SET desired_revision=?,version=? WHERE id=1 AND version=?", id, next, in.BaseVersion); err != nil {
			return SaveResult{}, err
		}
	}
	result := SaveResult{Tree: p.Tree}
	if in.Validate || in.Apply {
		result.TaskID, err = enqueue(ctx, tx, id, in.Apply)
		if err != nil {
			return SaveResult{}, err
		}
	}

	if link != nil {
		if err := link(tx, result); err != nil {
			return SaveResult{}, err
		}
	}
	response, err := json.Marshal(result)
	if err != nil {
		return SaveResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", principal.ID, key, digest, s.Vault.Seal(response, "idempotency:"+principal.ID+":"+key), time.Now().Unix()); err != nil {
		return SaveResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'saved',?)", secure.ID(), requestID, principal.ID, "nginx.save."+state, id, time.Now().Unix()); err != nil {
		return SaveResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SaveResult{}, err
	}
	return result, nil
}

func (s *Service) replay(ctx context.Context, principal, key, digest string) (SaveResult, bool, error) {
	var want string
	var response []byte
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", principal, key).Scan(&want, &response)
	if err == sql.ErrNoRows {
		return SaveResult{}, false, nil
	}
	if err != nil {
		return SaveResult{}, false, err
	}
	if want != digest {
		return SaveResult{}, true, fault.Conflict("同一幂等键不能用于不同请求")
	}
	plain, err := s.Vault.Open(response, "idempotency:"+principal+":"+key)
	if err != nil {
		return SaveResult{}, true, err
	}
	var result SaveResult
	err = json.Unmarshal(plain, &result)
	return result, true, err
}

func (s *Service) Patch(ctx context.Context, p auth.Principal, requestID, key, resourceID string, base int64, changes map[string][]string, metadata *ResourceMetadata) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	encoded, err := json.Marshal(struct {
		Action, ID string
		Base       int64
		Changes    map[string][]string
		Metadata   *ResourceMetadata
	}{"patch", resourceID, base, changes, metadata})
	if err != nil {
		return SaveResult{}, err
	}
	digest := secure.Hash(encoded)
	if result, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return result, err
	}
	if len(changes) == 0 && metadata == nil {
		return SaveResult{}, fault.Invalid("没有待保存的字段")
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != base {
		return SaveResult{}, ErrConflict
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return SaveResult{}, fault.Invalid(err.Error())
	}
	files, err := parsed.Patch(resourceID, changes, metadata)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SaveResult{}, err
		}
		return SaveResult{}, fault.Invalid(err.Error())
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: base, Files: files}, digest)
}

func (s *Service) requireRevisionScopes(ctx context.Context, p auth.Principal, id string, q *dbgen.Queries) error {
	if id == "" || p.Require("security.write") == nil {
		return nil
	}
	tree, err := s.get(ctx, id, q)
	if err != nil {
		return err
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) > 0 {
		return p.Require("security.write")
	}
	return p.Require(parsed.RequiredScopes...)
}
