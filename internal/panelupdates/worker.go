package panelupdates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	nextCleanup := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.Agent != nil {
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := s.next(call)
			cancel()
			if err == nil && time.Now().After(nextCleanup) {
				call, cancel = context.WithTimeout(ctx, 30*time.Second)
				err = s.refreshCleanup(call)
				cancel()
				nextCleanup = time.Now().Add(15 * time.Second)
			}
			if err != nil && ctx.Err() == nil {
				if !reported {
					slog.Warn("面板更新任务对账失败", "error", err)
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

func (s *Service) observed(ctx context.Context, t Task, base dbgen.Task, op Operation) error {
	if err := op.Validate(t.OperationID, t.Input); err != nil {
		return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "独立更新回执与原任务不一致", nil, false)
	}
	if t.Result != nil && t.Result.IntentSHA256 != op.IntentSHA256 {
		return s.store(ctx, t, base, "recovery_required", "intent_mismatch", "独立更新原意图已偏离，须本机恢复", nil, false)
	}
	message := op.Error
	if message == "" && op.Failure != "" {
		message = op.Failure
	}
	state := op.State
	if state == "queued" {
		state = "running"
	}
	// Root receipts survive application database compensation. Observing a later
	// root authorization never dispatches it again or fabricates a local request.
	if !op.Finalized && op.Authorization != t.Request && !op.Active {
		state = "recovery_required"
		if message == "" {
			message = "原授权尚未执行或已由独立事务推进，须显式续办"
		}
	}
	return s.store(ctx, t, base, state, op.Stage, message, &op, true)
}

func (s *Service) next(ctx context.Context) error {
	t, _, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE t.state NOT IN ('succeeded','failed','rolled_back','cancelled') ORDER BY t.created_at,t.id LIMIT 1"))
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
	op, err := s.Agent.PanelUpdate(ctx, t.OperationID)
	var prior *Operation
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		if t.dispatched || base.SubmitStarted != 0 || base.AgentAccepted != 0 || t.Sequence != 1 {
			return s.store(ctx, t, base, "recovery_required", "operation_missing", "曾提交的独立更新记录缺失，不能重建或假定未执行", nil, false)
		}
	} else if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", remote.Message, nil, false)
		}
		return s.store(ctx, t, base, t.State, "agent_unconfirmed", "无法确认独立更新状态，继续查询原事务", nil, false)
	} else {
		if err = op.Validate(t.OperationID, t.Input); err != nil {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "独立更新回执与原任务不一致", nil, false)
		}
		if t.Result != nil && t.Result.IntentSHA256 != op.IntentSHA256 {
			return s.store(ctx, t, base, "recovery_required", "intent_mismatch", "独立更新原意图已偏离，须本机恢复", nil, false)
		}
		prior = &op
		if op.Finalized || op.Authorization == t.Request || op.Active || op.Sequence >= t.Sequence {
			return s.observed(ctx, t, base, op)
		}
		if op.Sequence != t.Sequence-1 {
			return s.store(ctx, t, base, "recovery_required", "control_mismatch", "更新续办授权与独立事务序号不连续", prior, true)
		}
		if t.dispatched {
			return s.store(ctx, t, base, "recovery_required", "control_unconfirmed", "续办提交尚未确认，仅查询原事务；再次执行须显式授权", prior, true)
		}
	}
	if t.AuthorizationUntil <= time.Now().Unix() {
		state := "recovery_required"
		if prior == nil {
			state = "failed"
		}
		return s.store(ctx, t, base, state, "authorization_expired", "更新启动授权已过期，尚未提交本次授权", prior, prior != nil)
	}
	root, done, err := s.Maintenance.Held(t.Input.MaintenanceID)
	if err != nil {
		return s.store(ctx, t, base, "recovery_required", "maintenance_unconfirmed", "等待原维护会话确认，尚未提交更新授权", prior, prior != nil)
	}
	defer done()
	if root.Epoch != t.Request.Epoch {
		return s.store(ctx, t, base, "recovery_required", "epoch_changed", "维护授权已变化，须重新确认原更新续办", prior, prior != nil)
	}
	// Persist the attempt before contacting root, including in the snapshot that
	// may later replace this database. A lost response never recreates a root job.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(ctx, "UPDATE panel_update_requests SET dispatched=1 WHERE id=? AND dispatched=0 AND EXISTS(SELECT 1 FROM panel_updates WHERE task_id=? AND request_id=?)", t.requestID, t.ID, t.requestID)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	changed, err = tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=? AND state NOT IN ('succeeded','failed','rolled_back','cancelled')", time.Now().Unix(), t.ID)
	if err != nil {
		return err
	}
	n, err = changed.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return nil
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	op, err = s.Agent.SubmitPanelUpdate(ctx, t.Request)
	if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			// Only this root code proves rejection before parent publication while
			// holding the worker locks. All other submission failures stay uncertain.
			if prior == nil && remote.Code == "PANEL_UPDATE_REJECTED" {
				return s.store(ctx, t, base, "failed", "preflight_rejected", remote.Message, nil, false)
			}
			state, stage := "recovery_required", "control_rejected"
			if prior == nil {
				stage = "preflight_unconfirmed"
			}
			return s.store(ctx, t, base, state, stage, remote.Message, prior, prior != nil)
		}
		return s.store(ctx, t, base, "recovery_required", "agent_unconfirmed", "提交结果尚未确认，仅查询原更新记录", prior, prior != nil)
	}
	return s.observed(ctx, t, base, op)
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
		if len(raw) > 12<<10 {
			return errors.New("独立更新回执超出持久化预算")
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
	changed, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,observed_revision=?,agent_accepted=MAX(agent_accepted,?),updated_at=? WHERE id=? AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND EXISTS(SELECT 1 FROM panel_updates WHERE task_id=? AND request_id=?)", state, stage, message, hash, accepted, now, t.ID, t.ID, t.requestID)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if op != nil {
		pending := op.Cleanup.State != "done" || op.Active
		if _, err = tx.ExecContext(ctx, "UPDATE panel_updates SET result=?,cleanup_pending=? WHERE task_id=?", s.Vault.Seal(raw, "panel-update:result:"+t.ID), pending, t.ID); err != nil {
			return err
		}
	} else if state == "failed" || state == "cancelled" {
		if _, err = tx.ExecContext(ctx, "UPDATE panel_updates SET cleanup_pending=0 WHERE task_id=?", t.ID); err != nil {
			return err
		}
	}
	if state != base.State && (state == "succeeded" || state == "failed" || state == "rolled_back" || state == "recovery_required") {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'panel-update-worker','system','panel.update',?,?,?)", secure.ID(), t.ID, state, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// A terminal task only refreshes its root cleanup receipt. Cleanup cannot reopen
// maintenance or change the already persisted business outcome.
func (s *Service) refreshCleanup(ctx context.Context) error {
	t, _, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE i.cleanup_pending=1 AND t.state IN ('succeeded','failed','rolled_back') ORDER BY i.cleanup_checked_at,t.id LIMIT 1"))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = s.DB.ExecContext(ctx, "UPDATE panel_updates SET cleanup_checked_at=? WHERE task_id=? AND request_id=?", time.Now().Unix(), t.ID, t.requestID); err != nil {
		return err
	}
	op, err := s.Agent.PanelUpdate(ctx, t.OperationID)
	if err != nil {
		return err
	}
	if err = op.Validate(t.OperationID, t.Input); err != nil {
		return err
	}
	if t.Result == nil || op.IntentSHA256 != t.Result.IntentSHA256 || !op.Finalized || !op.ReleaseAcknowledged || op.State != t.State || op.Stage != t.Stage {
		return errors.New("终态更新的清理回执偏离原结果")
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if len(raw) > 12<<10 {
		return errors.New("独立更新清理回执超出持久化预算")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(ctx, "UPDATE tasks SET observed_revision=?,updated_at=? WHERE id=? AND state=? AND stage=? AND EXISTS(SELECT 1 FROM panel_updates WHERE task_id=? AND request_id=? AND cleanup_pending=1)", secure.Hash(raw), time.Now().Unix(), t.ID, t.State, t.Stage, t.ID, t.requestID)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	pending := op.Cleanup.State != "done" || op.Active
	if _, err = tx.ExecContext(ctx, "UPDATE panel_updates SET result=?,cleanup_pending=? WHERE task_id=?", s.Vault.Seal(raw, "panel-update:result:"+t.ID), pending, t.ID); err != nil {
		return err
	}
	if t.Result.Cleanup.State != op.Cleanup.State {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'panel-update-worker','system','panel.update.cleanup',?,?,?)", secure.ID(), t.ID, op.Cleanup.State, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
