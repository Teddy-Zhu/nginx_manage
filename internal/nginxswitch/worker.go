package nginxswitch

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
					slog.Warn("组件切换任务对账失败", "error", err)
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
	t, _, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM nginx_switches i JOIN tasks t ON t.id=i.task_id WHERE t.state NOT IN ('succeeded','failed','rolled_back') AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=t.id) ORDER BY t.created_at,t.id LIMIT 1"))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	base, err := dbgen.New(s.DB).GetTask(ctx, t.ID)
	if err != nil {
		return err
	}
	op, err := s.Agent.NginxSwitch(ctx, t.OperationID)
	var prior *Operation
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		if base.SubmitStarted != 0 || base.AgentAccepted != 0 || t.Sequence != 1 {
			return s.store(ctx, t, base, "recovery_required", "operation_missing", "已提交的独立切换记录缺失，不能重建或假定未执行", nil, false)
		}
		if t.AuthorizationUntil <= time.Now().Unix() {
			return s.store(ctx, t, base, "failed", "authorization_expired", "切换授权已过期，尚未提交独立执行器", nil, false)
		}
	} else if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", remote.Message, nil, false)
		}
		return s.store(ctx, t, base, t.State, "agent_unconfirmed", "无法确认独立切换状态，继续核对原操作", nil, false)
	} else {
		if err = op.Validate(t.OperationID, t.Input); err != nil {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "切换回执与原任务不一致", nil, false)
		}
		if t.Result != nil && (op.ChildID != t.Result.ChildID || t.Result.IntentSHA256 != "" && op.IntentSHA256 != t.Result.IntentSHA256) {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "原切换子操作或准入快照已变化", nil, false)
		}
		prior = &op
		if op.Sequence > t.Sequence || op.Sequence == t.Sequence && (op.Command != t.Command || op.Authorization.AuthorizationUntil != t.AuthorizationUntil) {
			return s.store(ctx, t, base, "recovery_required", "control_mismatch", "独立切换授权序号与本地任务不一致，须本机核对", prior, true)
		}
		if Terminal(op.State) {
			message := op.Error
			if op.Sequence < t.Sequence {
				message = "控制操作未执行；已核实原切换的终态"
			}
			return s.store(ctx, t, base, op.State, op.Stage, message, prior, true)
		}
		if op.Sequence == t.Sequence && op.State != "queued" {
			return s.store(ctx, t, base, op.State, op.Stage, op.Error, prior, true)
		}
		if t.Stage == "control_rejected" {
			return s.store(ctx, t, base, "recovery_required", t.Stage, t.Error, prior, true)
		}
		if op.Active {
			return s.store(ctx, t, base, "running", op.Stage, op.Error, prior, true)
		}
		if t.AuthorizationUntil <= time.Now().Unix() {
			return s.store(ctx, t, base, "recovery_required", "authorization_expired", "授权已过期，仅观察原切换；继续执行须显式续办", prior, true)
		}
	}
	root, done, err := s.Maintenance.Held(t.Input.MaintenanceID)
	if err != nil {
		return s.store(ctx, t, base, "recovery_required", "maintenance_unconfirmed", "等待原维护会话重新确认，尚未提交新的控制操作", prior, prior != nil)
	}
	defer done()
	var seq int
	if err = s.DB.QueryRowContext(ctx, "SELECT sequence FROM nginx_switches WHERE task_id=?", t.ID).Scan(&seq); err != nil {
		return err
	}
	if seq != t.Sequence {
		return nil
	}
	if prior == nil {
		r, e := s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=? AND submit_started=0 AND agent_accepted=0", time.Now().Unix(), t.ID)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
	}
	req := Request{Protocol: protocol.Agent, OperationID: t.OperationID, Epoch: root.Epoch, Sequence: t.Sequence, Command: t.Command, Input: t.Input, AuthorizationUntil: t.AuthorizationUntil}
	op, err = s.Agent.SubmitNginxSwitch(ctx, req)
	if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			if prior == nil {
				return s.store(ctx, t, base, "failed", "preflight_rejected", remote.Message, nil, false)
			}
			return s.store(ctx, t, base, "recovery_required", "control_rejected", remote.Message, prior, true)
		}
		return s.store(ctx, t, base, "recovery_required", "agent_unconfirmed", "提交结果尚未确认，仅核对原切换记录", prior, prior != nil)
	}
	if err = op.Validate(t.OperationID, t.Input); err != nil || op.Sequence > t.Sequence || op.Sequence == t.Sequence && op.Authorization != req {
		return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "独立切换响应与原授权不一致", nil, false)
	}
	if prior != nil && (op.ChildID != prior.ChildID || prior.IntentSHA256 != "" && op.IntentSHA256 != prior.IntentSHA256) {
		return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "原切换子操作或准入快照已变化", nil, false)
	}
	if op.Sequence < t.Sequence && !Terminal(op.State) {
		return s.store(ctx, t, base, "recovery_required", "control_unconfirmed", "原切换控制尚未确认，将继续核对同一授权", &op, true)
	}
	state := op.State
	if state == "queued" {
		state = "running"
	}
	message := op.Error
	if op.Sequence < t.Sequence {
		message = "控制操作未执行；已核实原切换的终态"
	}
	return s.store(ctx, t, base, state, op.Stage, message, &op, true)
}

func (s *Service) store(ctx context.Context, t Task, base dbgen.Task, state, stage, message string, op *Operation, accepted bool) error {
	chars := []rune(message)
	if len(chars) > 500 {
		message = string(chars[:500])
	}
	var raw []byte
	hash := base.ObservedRevision
	if op != nil {
		var err error
		raw, err = json.Marshal(op)
		if err != nil {
			return err
		}
		if len(raw) > 28<<10 {
			return errors.New("切换回执超出持久化预算")
		}
		hash = secure.Hash(raw)
	}
	if base.State == state && base.Stage == stage && base.LastError == message && base.ObservedRevision == hash && (!accepted || base.AgentAccepted != 0) {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	r, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,observed_revision=?,agent_accepted=MAX(agent_accepted,?),updated_at=? WHERE id=? AND state NOT IN ('succeeded','failed','rolled_back') AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=tasks.id) AND EXISTS(SELECT 1 FROM nginx_switches WHERE task_id=? AND sequence=?)", state, stage, message, hash, accepted, now, t.ID, t.ID, t.Sequence)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if op != nil {
		if _, err = tx.ExecContext(ctx, "UPDATE nginx_switches SET result=? WHERE task_id=?", s.Vault.Seal(raw, "nginx-switch:result:"+t.ID), t.ID); err != nil {
			return err
		}
	}
	if state != base.State && (state == "succeeded" || state == "failed" || state == "rolled_back" || state == "recovery_required") {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'nginx-switch-worker','system','component.switch',?,?,?)", secure.ID(), t.ID, state, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
