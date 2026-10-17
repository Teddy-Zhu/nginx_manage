package fail2ban

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

func (s *PolicyService) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for {
		if ctx.Err() != nil {
			return nil
		}
		if executor, ok := s.Agent.(JailsExecutor); ok {
			call, cancel := context.WithTimeout(ctx, 14*time.Second)
			err := s.nextJailTask(call, executor)
			cancel()
			if err != nil && ctx.Err() == nil {
				if !reported {
					slog.Warn("Fail2ban task reconciliation failed", "error", err)
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

func (s *PolicyService) nextJailTask(ctx context.Context, executor JailsExecutor) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var id string
	err := s.DB.QueryRowContext(ctx, "SELECT id FROM tasks WHERE kind IN ('fail2ban.apply','fail2ban.address','fail2ban.lifecycle','fail2ban.python','fail2ban.existing') AND state IN ('queued','running','compensating','recovery_required') ORDER BY created_at,id LIMIT 1").Scan(&id)
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
	if task.Stage == "restore_isolated" {
		return nil
	}
	if task.Kind == "fail2ban.existing" {
		existingExecutor, ok := s.Agent.(ExistingPolicyExecutor)
		if !ok {
			return fault.Unavailable("未连接已有 jail 执行器")
		}
		return s.nextExistingTask(ctx, existingExecutor, task)
	}
	if task.Kind == "fail2ban.python" {
		pythonExecutor, ok := s.Agent.(PythonTaskExecutor)
		if !ok {
			return fault.Unavailable("未连接 Python 依赖执行器")
		}
		return s.nextPythonTask(ctx, pythonExecutor, task)
	}
	if task.Kind == "fail2ban.lifecycle" {
		lifecycleExecutor, ok := s.Agent.(LifecycleExecutor)
		if !ok {
			return fault.Unavailable("未连接受管引擎执行器")
		}
		return s.nextLifecycleTask(ctx, lifecycleExecutor, task)
	}
	if task.Kind == "fail2ban.address" {
		addressExecutor, ok := s.Agent.(AddressExecutor)
		if !ok {
			return fault.Unavailable("未连接手动封禁执行器")
		}
		return s.nextAddressTask(ctx, addressExecutor, task)
	}
	var sealed []byte
	if err = s.DB.QueryRowContext(ctx, "SELECT payload FROM fail2ban_operations WHERE task_id=?", id).Scan(&sealed); err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_missing", "jail 应用材料缺失，停止重新提交", false)
	}
	plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+id)
	if err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_unreadable", "jail 应用材料无法解密，停止重新提交", false)
	}
	var payload jailTaskPayload
	if json.Unmarshal(plain, &payload) != nil || payload.Input.Validate() != nil || !payload.Request.Valid() || payload.Request.OperationID != task.OperationID || payload.Request.BaseID != payload.Input.BaseID || payload.Request.Target != payload.Input.Target || payload.Request.Policy.Hash() != payload.Input.PolicyHash {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_invalid", "jail 应用合同无法核对，停止重新提交", false)
	}
	normalized, err := payload.Request.Policy.Normalize()
	if err != nil || normalized.Hash() != payload.Request.Policy.Hash() {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_invalid", "jail 应用策略无效，停止重新提交", false)
	}
	operation, err := executor.Fail2banJailsOperation(ctx, task.OperationID)
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Code == "FAIL2BAN_JAIL_OPERATION_MISSING" {
		if task.AgentAccepted != 0 {
			return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_missing", "已接受的 jail 操作记录缺失，停止重新执行", false)
		}
		if task.SubmitStarted == 0 {
			if time.Now().Unix()-task.CreatedAt > 300 {
				return s.jailTaskUpdate(ctx, task, "failed", "authorization_expired", "jail 应用排队超过五分钟，请重新预览", false)
			}
			if err = s.moduleEnabled(ctx, s.DB); err != nil {
				return s.jailTaskUpdate(ctx, task, "failed", "module_disabled", err.Error(), false)
			}
			if err = s.migrationIdle(ctx, s.DB); err != nil {
				return s.jailTaskUpdate(ctx, task, "failed", "migration_pending", err.Error(), false)
			}
			view, e := s.Policy(ctx)
			if e != nil {
				return e
			}
			if view.Version != payload.Input.Version || view.Policy.Hash() != payload.Input.PolicyHash {
				return s.jailTaskUpdate(ctx, task, "cancelled", "superseded", "jail 期望版本已变化，未提交旧配置", false)
			}
			if _, err = s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=?", time.Now().Unix(), id); err != nil {
				return err
			}
			task.State, task.SubmitStarted = "running", 1
		}
		operation, err = executor.ApplyFail2banJails(ctx, payload.Request)
		if err != nil {
			submitErr := err
			operation, err = executor.Fail2banJailsOperation(ctx, task.OperationID)
			if errors.As(err, &remote) && remote.Code == "FAIL2BAN_JAIL_OPERATION_MISSING" {
				var rejected *fault.Error
				if errors.As(submitErr, &rejected) && (rejected.Status == 400 || rejected.Status == 403 || rejected.Status == 409) {
					return s.jailTaskUpdate(ctx, task, "failed", "agent_rejected", rejected.Message, false)
				}
				return s.jailTaskUpdate(ctx, task, "running", "submit_unconfirmed", "提交结果待确认，继续核对原操作", false)
			}
		}
	}
	if err != nil {
		return s.jailTaskUpdate(ctx, task, task.State, "reconciling", "无法确认 Agent jail 操作，保留原标识等待核对", false)
	}
	if operation.ID != task.OperationID || operation.AfterID != task.OperationID || operation.BeforeID != payload.Request.BaseID || operation.Target != payload.Request.Target || operation.RequestHash != payload.Request.Hash() {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_mismatch", "Agent jail 操作与冻结任务不一致", true)
	}
	switch operation.State {
	case "succeeded":
		if operation.Stage != "jails_confirmed" {
			return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_mismatch", "jail 成功记录缺少运行确认", true)
		}
	case "running", "compensating", "recovery_required", "failed":
	default:
		return s.jailTaskUpdate(ctx, task, "recovery_required", "unknown_state", "Agent jail 状态未知", true)
	}
	return s.jailTaskUpdate(ctx, task, operation.State, operation.Stage, operation.Error, true)
}

func (s *PolicyService) jailTaskUpdate(ctx context.Context, task dbgen.Task, state, stage, message string, accepted bool) error {
	return s.fail2banTaskUpdate(ctx, task, state, stage, message, accepted, nil)
}
func (s *PolicyService) fail2banTaskUpdate(ctx context.Context, task dbgen.Task, state, stage, message string, accepted bool, payload []byte) error {
	if payload == nil && task.State == state && task.Stage == stage && task.LastError == message && (!accepted || task.AgentAccepted != 0) {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,agent_accepted=MAX(agent_accepted,?),updated_at=? WHERE id=? AND state IN ('queued','running','compensating','recovery_required')", state, stage, message, accepted, time.Now().Unix(), task.ID); err != nil {
		return err
	}
	if payload != nil {
		if _, err = tx.ExecContext(ctx, "UPDATE fail2ban_operations SET payload=? WHERE task_id=?", s.Vault.Seal(payload, "fail2ban:operation:"+task.ID), task.ID); err != nil {
			return err
		}
	}
	if state == "succeeded" || state == "failed" || state == "cancelled" || state == "recovery_required" && task.State != state {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:fail2ban',?,?,?,?)", secure.ID(), task.OperationID, task.Kind, task.ID, state, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
