package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type pushJob struct {
	Task                 PushTask
	Payload              pushPayload
	Owner                string
	RemoteStarted        bool
	Version, NextAttempt int64
	Attempts             int64
}

var errPushChanged = errors.New("migration push changed concurrently")

func pushPermission(p auth.Principal) error {
	return p.Require("backup.export", "backup.secrets", "config.secrets", "nodes.manage")
}
func validPushKey(key string) bool {
	return key != "" && len(key) <= 128 && !strings.ContainsAny(key, "\x00\r\n")
}
func (s *Service) readPush(ctx context.Context, id string, includePayload bool) (pushJob, error) {
	var j pushJob
	var raw, summary []byte
	err := s.DB.QueryRowContext(ctx, `SELECT p.principal,CASE WHEN ? THEN p.payload ELSE NULL END,p.summary,p.remote_started,p.version,p.next_attempt_at,p.expires_at,t.state,t.stage,t.last_error,t.updated_at,t.attempts FROM migration_pushes p JOIN tasks t ON t.id=p.task_id WHERE p.task_id=? AND t.kind='migration.push'`, includePayload, id).Scan(&j.Owner, &raw, &summary, &j.RemoteStarted, &j.Version, &j.NextAttempt, &j.Task.ExpiresAt, &j.Task.State, &j.Task.Stage, &j.Task.Error, &j.Task.UpdatedAt, &j.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return j, fault.NotFound("迁出任务不存在")
	}
	if err != nil {
		return j, err
	}
	plain, err := s.Vault.Open(summary, "migration-push-summary:"+id)
	if err != nil {
		return j, err
	}
	var out PushTask
	if err = decodeStrict(plain, &out); err != nil {
		return j, err
	}
	if out.ID != id {
		return j, errors.New("migration push identity mismatch")
	}
	out.State, out.Stage, out.Error, out.UpdatedAt, out.ExpiresAt = j.Task.State, j.Task.Stage, j.Task.Error, j.Task.UpdatedAt, j.Task.ExpiresAt
	j.Task = out
	if len(raw) != 0 {
		plain, err = s.Vault.Open(raw, "migration-push:"+id)
		if err != nil {
			return j, err
		}
		if err = decodeStrict(plain, &j.Payload); err != nil {
			return j, err
		}
	}
	return j, nil
}
func (s *Service) GetPush(ctx context.Context, p auth.Principal, id string) (PushTask, error) {
	if err := pushPermission(p); err != nil {
		return PushTask{}, err
	}
	if !validTransferID(id) {
		return PushTask{}, fault.Invalid("迁移标识无效")
	}
	j, err := s.readPush(ctx, id, false)
	if err != nil {
		return PushTask{}, err
	}
	if j.Owner != p.ID && !p.Has("auth.manage") {
		return PushTask{}, auth.ErrForbidden
	}
	return j.Task, nil
}
func (s *Service) ListPushes(ctx context.Context, p auth.Principal) ([]PushTask, error) {
	if err := pushPermission(p); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT task_id FROM migration_pushes p JOIN tasks t ON t.id=p.task_id WHERE p.principal=? OR ? ORDER BY t.created_at DESC,t.id DESC LIMIT 64", p.ID, p.Has("auth.manage"))
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []PushTask{}
	for _, id := range ids {
		task, e := s.GetPush(ctx, p, id)
		if e != nil {
			return nil, e
		}
		task.Plan = nil
		out = append(out, task)
	}
	return out, nil
}
func (s *Service) pushPrior(ctx context.Context, p auth.Principal, key, hash string) (PushTask, bool, error) {
	var prior string
	var sealed []byte
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return PushTask{}, false, nil
	}
	if err != nil {
		return PushTask{}, false, err
	}
	if prior != hash {
		return PushTask{}, true, fault.Conflict("同一幂等键不能用于不同请求")
	}
	raw, err := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
	if err != nil {
		return PushTask{}, true, err
	}
	var task PushTask
	if err = decodeStrict(raw, &task); err != nil {
		return task, true, err
	}
	task, err = s.GetPush(ctx, p, task.ID)
	return task, true, err
}
func (s *Service) pushReceipt(ctx context.Context, tx *sql.Tx, p auth.Principal, key, hash string, task PushTask) error {
	raw, err := json.Marshal(task)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, hash, s.Vault.Seal(raw, "idempotency:"+p.ID+":"+key), time.Now().Unix())
	return err
}
func pushAudit(ctx context.Context, tx *sql.Tx, principal, requestID, id, action, outcome string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), requestID, principal, action, id, outcome, time.Now().Unix())
	return err
}
func (s *Service) savePush(ctx context.Context, j *pushJob) error { return s.savePushWith(ctx, j, nil) }
func (s *Service) savePushWith(ctx context.Context, j *pushJob, after func(*sql.Tx) error) error {
	raw := []byte{}
	var err error
	if !pushTerminal(j.Task.State) {
		raw, err = json.Marshal(j.Payload)
		if err != nil {
			return err
		}
		if len(raw) > MaxRequestBytes-256 {
			return fault.Invalid("迁出暂存材料超过限制")
		}
		raw = s.Vault.Seal(raw, "migration-push:"+j.Task.ID)
	}
	j.Task.UpdatedAt = time.Now().Unix()
	summary, err := json.Marshal(j.Task)
	if err != nil {
		return err
	}
	if len(summary) > maxPushSummaryBytes-256 {
		return fault.Invalid("迁出结果超过大小限制")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var retained int64
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM migration_plans)+(SELECT COALESCE(SUM(length(payload)),0) FROM migration_pushes WHERE task_id!=?)+(SELECT COALESCE(SUM(length(continuation)),0) FROM migration_pulls)", j.Task.ID).Scan(&retained); err != nil {
		return err
	}
	margin := int64(0)
	if after != nil {
		margin = 256
	}
	if retained+int64(len(raw))+margin > 128<<20 {
		return fault.Conflict("迁移暂存材料已达 128 MiB 保留配额")
	}
	result, err := tx.ExecContext(ctx, "UPDATE migration_pushes SET payload=?,summary=?,remote_started=?,expires_at=?,next_attempt_at=?,version=version+1 WHERE task_id=? AND version=?", raw, s.Vault.Seal(summary, "migration-push-summary:"+j.Task.ID), j.RemoteStarted, j.Task.ExpiresAt, j.NextAttempt, j.Task.ID, j.Version)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errPushChanged
	}
	var oldState, oldStage string
	if err = tx.QueryRowContext(ctx, "SELECT state,stage FROM tasks WHERE id=?", j.Task.ID).Scan(&oldState, &oldStage); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,attempts=?,submit_started=?,agent_accepted=?,updated_at=? WHERE id=?", j.Task.State, j.Task.Stage, j.Task.Error, j.Attempts, j.RemoteStarted, j.Task.Plan != nil, j.Task.UpdatedAt, j.Task.ID); err != nil {
		return err
	}
	if oldState != j.Task.State || oldStage != j.Task.Stage {
		if err = pushAudit(ctx, tx, "system:migration", j.Task.ID, j.Task.ID, "migration.push."+j.Task.Stage, j.Task.State); err != nil {
			return err
		}
	}
	if after != nil {
		if err = after(tx); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	j.Version++
	return nil
}
