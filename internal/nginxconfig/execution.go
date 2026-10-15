package nginxconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

func enqueue(ctx context.Context, tx *sql.Tx, revision string, apply bool) (string, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count >= limits.QueuedTasks {
		return "", fault.Conflict("任务队列已满")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('nginx.apply','nginx.validate') AND state IN ('queued','running','compensating','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", fault.Conflict("已有 Nginx 操作等待完成或恢复")
	}
	var expected sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT applied_revision FROM config_head WHERE id=1").Scan(&expected); err != nil {
		return "", err
	}
	id, kind := secure.ID(), "nginx.validate"
	if apply {
		kind = "nginx.apply"
	}
	now := time.Now().Unix()
	_, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,revision_id,expected_revision,state,stage,operation_id,created_at,updated_at) VALUES(?,?,?,?,?,'queued','queued',?,?,?)", id, kind, revision, revision, expected.String, secure.ID(), now, now)
	return id, err
}

type ApplySavedRequest struct {
	BaseVersion int64 `json:"base_version"`
}

// ApplySaved does not create or render a different business revision. The
// operation uses the same immutable tree as raw and form-based saves.
func (s *Service) ApplySaved(ctx context.Context, p auth.Principal, requestID, key string, in ApplySavedRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	if key == "" || len(key) > 128 || in.BaseVersion < 0 {
		return SaveResult{}, fault.Invalid("请求版本或幂等键无效")
	}
	encoded, _ := json.Marshal(struct {
		Action string
		Input  ApplySavedRequest
	}{"apply", in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	if tree.RevisionID == "" || tree.State != "desired" {
		return SaveResult{}, fault.Invalid("请先保存有效配置")
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) > 0 {
		return SaveResult{}, ErrInvalid
	}
	if err := p.Require(parsed.RequiredScopes...); err != nil {
		return SaveResult{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return SaveResult{}, err
	}
	defer tx.Rollback()
	var version int64
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT version FROM config_head WHERE id=1").Scan(&version); err != nil {
		return SaveResult{}, err
	}
	if version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return SaveResult{}, err
	}
	if !enabled {
		return SaveResult{}, fault.Conflict("Nginx 配置模块已停用")
	}
	task, err := enqueue(ctx, tx, tree.RevisionID, true)
	if err != nil {
		return SaveResult{}, err
	}
	out := SaveResult{Tree: tree, TaskID: task}
	response, err := json.Marshal(out)
	if err != nil {
		return SaveResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), time.Now().Unix()); err != nil {
		return SaveResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'queued',?)", secure.ID(), requestID, p.ID, "nginx.apply", tree.RevisionID, time.Now().Unix()); err != nil {
		return SaveResult{}, err
	}
	return out, tx.Commit()
}
