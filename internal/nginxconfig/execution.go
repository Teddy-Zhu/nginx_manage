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
	"nginxpanel/internal/storage/dbgen"
)

func enqueue(ctx context.Context, tx *sql.Tx, revision string, apply bool) (string, error) {
	kind := "nginx.validate"
	if apply {
		kind = "nginx.apply"
	}
	return enqueueOperation(ctx, tx, revision, kind, "")
}

func enqueueOperation(ctx context.Context, tx *sql.Tx, revision, kind, snapshot string) (string, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running','waiting_confirmation','compensating','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count >= limits.QueuedTasks {
		return "", fault.Conflict("任务队列已满")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('nginx.apply','nginx.validate','nginx.restore') AND state IN ('queued','running','compensating','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", fault.Conflict("已有 Nginx 操作等待完成或恢复")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.challenge_type='http-01' AND t.state IN ('queued','running','recovery_required')").Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", fault.Conflict("HTTP-01 验证或材料恢复尚未完成，暂不能执行 Nginx 操作")
	}
	var expected sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT applied_revision FROM config_head WHERE id=1").Scan(&expected); err != nil {
		return "", err
	}
	id := secure.ID()
	now := time.Now().Unix()
	_, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,revision_id,expected_revision,restore_snapshot,state,stage,operation_id,created_at,updated_at) VALUES(?,?,?,?,?,?,'queued','queued',?,?,?)", id, kind, revision, revision, expected.String, snapshot, secure.ID(), now, now)
	return id, err
}

type ApplySavedRequest struct {
	BaseVersion int64 `json:"base_version"`
}

type RestoreRequest struct {
	BaseVersion int64  `json:"base_version"`
	Snapshot    string `json:"snapshot"`
}

// ApplySaved does not create or render a different business revision. The
// operation uses the same immutable tree as raw and form-based saves.
func (s *Service) ApplySaved(ctx context.Context, p auth.Principal, requestID, key string, in ApplySavedRequest) (SaveResult, error) {
	return s.executeSaved(ctx, p, requestID, key, RestoreRequest{BaseVersion: in.BaseVersion}, nil)
}

// Replay precedes inspection; the inspected applied revision is checked again
// inside the configuration transaction before the recovery task is recorded.
func (s *Service) RestoreManaged(ctx context.Context, p auth.Principal, requestID, key string, in RestoreRequest, inspect func() (string, error)) (SaveResult, error) {
	if len(in.Snapshot) != 64 || inspect == nil {
		return SaveResult{}, fault.Invalid("恢复快照无效")
	}
	return s.executeSaved(ctx, p, requestID, key, in, inspect)
}

func (s *Service) executeSaved(ctx context.Context, p auth.Principal, requestID, key string, in RestoreRequest, inspect func() (string, error)) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	kind := "nginx.apply"
	if inspect != nil {
		if err := p.Require("security.write"); err != nil {
			return SaveResult{}, err
		}
		kind = "nginx.restore"
	}
	if key == "" || len(key) > 128 || in.BaseVersion < 0 {
		return SaveResult{}, fault.Invalid("请求版本或幂等键无效")
	}
	encoded, _ := json.Marshal(struct {
		Action string
		Input  RestoreRequest
	}{kind, in})
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
	var inspectedRevision string
	if inspect != nil {
		inspectedRevision, err = inspect()
		if err != nil {
			return SaveResult{}, err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return SaveResult{}, err
	}
	defer tx.Rollback()
	var version int64
	var applied sql.NullString
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT version,applied_revision FROM config_head WHERE id=1").Scan(&version, &applied); err != nil {
		return SaveResult{}, err
	}
	if version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	if inspect != nil && applied.String != inspectedRevision {
		return SaveResult{}, fault.Conflict("已生效修订已变化，请重新检查外部快照")
	}
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='nginx-config'").Scan(&enabled); err != nil {
		return SaveResult{}, err
	}
	if !enabled {
		return SaveResult{}, fault.Conflict("Nginx 配置模块已停用")
	}
	if err := s.requireRevisionScopes(ctx, p, applied.String, dbgen.New(tx)); err != nil {
		return SaveResult{}, err
	}
	if _, err := s.validateCertificates(ctx, tx, parsed); err != nil {
		return SaveResult{}, err
	}
	task, err := enqueueOperation(ctx, tx, tree.RevisionID, kind, in.Snapshot)
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
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'queued',?)", secure.ID(), requestID, p.ID, kind, tree.RevisionID, time.Now().Unix()); err != nil {
		return SaveResult{}, err
	}
	return out, tx.Commit()
}
