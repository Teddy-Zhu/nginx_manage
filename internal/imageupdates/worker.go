package imageupdates

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
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.Agent != nil {
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := s.next(call)
			cancel()
			if err != nil && ctx.Err() == nil {
				if !reported {
					slog.Warn("面板镜像替换任务对账失败", "error", err)
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
		return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "面板镜像替换回执与原任务不一致", nil, false)
	}
	if t.Result != nil && t.Result.IntentSHA256 != op.IntentSHA256 {
		return s.store(ctx, t, base, "recovery_required", "intent_mismatch", "面板镜像替换原意图已偏离，须本机恢复", nil, false)
	}
	message := op.Error
	if message == "" && op.Failure != "" {
		message = op.Failure
	}
	state := op.State
	if state == "queued" {
		state = "running"
	}
	// Observing a root authorization never dispatches it again or fabricates
	// a replacement request after reconnecting.
	if !op.Finalized && op.Authorization != t.Request && !op.Active {
		state = "recovery_required"
		if message == "" {
			message = "原授权尚未执行或已由独立事务推进，须显式续办"
		}
	}
	return s.store(ctx, t, base, state, op.Stage, message, &op, true)
}

func (s *Service) next(ctx context.Context) error {
	t, _, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+taskColumns+taskJoin+"WHERE t.state NOT IN ('succeeded','failed','rolled_back','cancelled') AND t.stage<>'restore_isolated' AND NOT EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=t.id) ORDER BY t.created_at,t.id LIMIT 1"))
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
	op, err := s.Agent.PanelImageUpgrade(ctx, t.OperationID)
	var prior *Operation
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Status == 404 && remote.Code == "NOT_FOUND" {
		if t.dispatched || base.SubmitStarted != 0 || base.AgentAccepted != 0 || t.Sequence != 1 {
			return s.store(ctx, t, base, "recovery_required", "operation_missing", "曾提交的面板镜像替换记录缺失，不能重建或假定未执行", nil, false)
		}
	} else if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", remote.Message, nil, false)
		}
		return s.store(ctx, t, base, t.State, "agent_unconfirmed", "无法确认面板镜像替换状态，继续查询原事务", nil, false)
	} else {
		if err = op.Validate(t.OperationID, t.Input); err != nil {
			return s.store(ctx, t, base, "recovery_required", "operation_mismatch", "面板镜像替换回执与原任务不一致", nil, false)
		}
		if t.Result != nil && t.Result.IntentSHA256 != op.IntentSHA256 {
			return s.store(ctx, t, base, "recovery_required", "intent_mismatch", "面板镜像替换原意图已偏离，须本机恢复", nil, false)
		}
		prior = &op
		if op.Finalized || op.Authorization == t.Request || op.Active || op.Sequence >= t.Sequence {
			return s.observed(ctx, t, base, op)
		}
		if op.Sequence != t.Sequence-1 {
			return s.store(ctx, t, base, "recovery_required", "control_mismatch", "面板镜像替换续办授权与独立事务序号不连续", prior, true)
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
		return s.store(ctx, t, base, state, "authorization_expired", "面板镜像替换启动授权已过期，尚未提交本次授权", prior, prior != nil)
	}
	root, done, err := s.Maintenance.Held(t.Input.MaintenanceID)
	if err != nil {
		return s.store(ctx, t, base, "recovery_required", "maintenance_unconfirmed", "等待原维护会话确认，尚未提交面板镜像替换授权", prior, prior != nil)
	}
	defer done()
	if root.Epoch != t.Request.Epoch {
		return s.store(ctx, t, base, "recovery_required", "epoch_changed", "维护授权已变化，须重新确认原面板镜像替换续办", prior, prior != nil)
	}
	// Persist the attempt before contacting root. A lost response only queries
	// the original operation and cannot recreate or restart the root worker.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(ctx, "UPDATE panel_image_upgrade_requests SET dispatched=1 WHERE id=? AND dispatched=0 AND EXISTS(SELECT 1 FROM panel_image_upgrades WHERE task_id=? AND request_id=?)", t.requestID, t.ID, t.requestID)
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
	op, err = s.Agent.SubmitPanelImageUpgrade(ctx, t.Request)
	if err != nil {
		if errors.As(err, &remote) && (remote.Status == 400 || remote.Status == 409) {
			// Only this root code proves rejection before parent publication while
			// holding the worker locks. All other submission failures stay uncertain.
			if prior == nil && remote.Code == "PANEL_IMAGE_REJECTED" {
				return s.store(ctx, t, base, "failed", "preflight_rejected", remote.Message, nil, false)
			}
			state, stage := "recovery_required", "control_rejected"
			if prior == nil {
				stage = "preflight_unconfirmed"
			}
			return s.store(ctx, t, base, state, stage, remote.Message, prior, prior != nil)
		}
		return s.store(ctx, t, base, "recovery_required", "agent_unconfirmed", "提交结果尚未确认，仅查询原面板镜像替换记录", prior, prior != nil)
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
			return errors.New("面板镜像替换回执超出持久化预算")
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
	changed, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,observed_revision=?,agent_accepted=MAX(agent_accepted,?),updated_at=? WHERE id=? AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND EXISTS(SELECT 1 FROM panel_image_upgrades WHERE task_id=? AND request_id=?)", state, stage, message, hash, accepted, now, t.ID, t.ID, t.requestID)
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
		if _, err = tx.ExecContext(ctx, "UPDATE panel_image_upgrades SET result=? WHERE task_id=?", s.Vault.Seal(raw, "panel-image-upgrade:result:"+t.ID), t.ID); err != nil {
			return err
		}
	}

	if state != base.State && (state == "succeeded" || state == "failed" || state == "rolled_back" || state == "recovery_required") {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,'panel-image-upgrade-worker','system','panel.image',?,?,?)", secure.ID(), t.ID, state, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
