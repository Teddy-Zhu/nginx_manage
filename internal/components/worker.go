package components

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.Agent != nil {
			call, cancel := context.WithTimeout(ctx, 12*time.Second)
			err := s.next(call)
			cancel()
			if err != nil && ctx.Err() == nil {
				if !reported {
					slog.Warn("组件任务对账失败", "error", err)
				}
				reported = true
			} else if err == nil {
				reported = false
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) next(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var id string
	err := s.DB.QueryRowContext(ctx, "SELECT id FROM tasks WHERE kind IN ('component.check','component.prepare','component.pull','component.software') AND state IN ('queued','running','recovery_required') AND stage<>'restore_isolated' AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=tasks.id) ORDER BY created_at,id LIMIT 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	task, err := dbgen.New(s.DB).GetTask(ctx, id)
	if err != nil {
		return err
	}
	var sealed []byte
	if err = s.DB.QueryRowContext(ctx, "SELECT payload FROM component_operations WHERE task_id=?", id).Scan(&sealed); err != nil {
		return err
	}
	raw, err := s.Vault.Open(sealed, "components:input:"+id)
	if err != nil {
		return s.update(ctx, task, "recovery_required", "input_unreadable", "组件任务输入无法解密，停止提交", nil, false)
	}
	var input Input
	if json.Unmarshal(raw, &input) != nil || input.Validate() != nil || task.Kind != "component."+input.Action {
		return s.update(ctx, task, "recovery_required", "input_invalid", "组件任务输入无效，停止提交", nil, false)
	}
	req := Request{Protocol: protocol.Agent, OperationID: task.OperationID, Input: input}
	op, err := s.Agent.ComponentOperation(ctx, task.OperationID)
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		// Persisting submission intent precedes IPC. Missing receipts after this point
		// are ambiguous even if Web never received the acceptance response.
		if task.SubmitStarted != 0 || task.AgentAccepted != 0 {
			return s.update(ctx, task, "recovery_required", "operation_missing", "已提交的组件操作记录缺失，须本机确认结果", nil, false)
		}
		result, e := s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=? AND submit_started=0 AND agent_accepted=0 AND state='queued'", time.Now().Unix(), id)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
		task.State = "running"
		op, err = s.Agent.SubmitComponent(ctx, req)
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			return s.update(ctx, task, "failed", "preflight_rejected", remote.Message, nil, false)
		}
	}
	if err != nil {
		return s.update(ctx, task, task.State, "agent_unconfirmed", "无法确认 Agent 状态，将继续查询原操作", nil, false)
	}
	if err = op.Validate(req); err != nil {
		return s.update(ctx, task, "recovery_required", "operation_mismatch", "Agent 组件操作身份或结果不一致", nil, false)
	}
	state := op.State
	if state == "queued" {
		state = "running"
	}
	return s.update(ctx, task, state, op.Stage, op.Error, &op, true)
}
func (s *Service) update(ctx context.Context, t dbgen.Task, state, stage, message string, op *Operation, accepted bool) error {
	var raw []byte
	var err error
	hash := t.ObservedRevision
	if op != nil {
		raw, err = json.Marshal(op)
		if err != nil {
			return err
		}
		if len(raw) > 60<<10 {
			return errors.New("组件结果超出持久化预算")
		}
		hash = secure.Hash(raw)
	}
	if t.State == state && t.Stage == stage && t.LastError == message && t.ObservedRevision == hash && (!accepted || t.AgentAccepted != 0) {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,observed_revision=?,agent_accepted=MAX(agent_accepted,?),lease_until=NULL,updated_at=? WHERE id=? AND state IN ('queued','running','recovery_required')", state, stage, bounded(message), hash, accepted, now, t.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if op != nil {
		if _, err = tx.ExecContext(ctx, "UPDATE component_operations SET result=? WHERE task_id=?", s.Vault.Seal(raw, "components:result:"+t.ID), t.ID); err != nil {
			return err
		}
	}
	if state != t.State && (state == "succeeded" || state == "failed" || state == "recovery_required") {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'component-worker','system',?,?,?,?)", secure.ID(), t.Kind, t.ID, state, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
