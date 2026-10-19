package fail2ban

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/storage/dbgen"
)

func (s *PolicyService) nextUpgradeTask(ctx context.Context, executor UpgradeExecutor, task dbgen.Task) error {
	var sealed []byte
	if err := s.DB.QueryRowContext(ctx, "SELECT payload FROM fail2ban_operations WHERE task_id=?", task.ID).Scan(&sealed); err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_missing", "Fail2ban 升级操作材料缺失，停止重新提交", false)
	}
	plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+task.ID)
	if err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_unreadable", "Fail2ban 升级操作材料无法解密，停止重新提交", false)
	}
	var payload upgradeTaskPayload
	if json.Unmarshal(plain, &payload) != nil || !payload.valid(task.OperationID) {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_invalid", "Fail2ban 升级操作合同无法核对，停止重新提交", false)
	}
	operation, err := executor.Fail2banUpgradeOperation(ctx, task.OperationID)
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Code == "FAIL2BAN_UPGRADE_OPERATION_MISSING" {
		if task.AgentAccepted != 0 {
			return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_missing", "已接受的Fail2ban 升级操作记录缺失，停止重新执行", false)
		}
		if task.SubmitStarted == 0 {
			if time.Now().Unix()-task.CreatedAt > 300 {
				return s.jailTaskUpdate(ctx, task, "failed", "authorization_expired", "Fail2ban 升级操作排队超过五分钟，请重新预览实例状态", false)
			}
			if err = s.moduleEnabled(ctx, s.DB); err != nil {
				return s.jailTaskUpdate(ctx, task, "failed", "module_disabled", err.Error(), false)
			}
			if err = s.migrationIdle(ctx, s.DB); err != nil {
				return s.jailTaskUpdate(ctx, task, "failed", "migration_pending", err.Error(), false)
			}
			if _, err = s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=?", time.Now().Unix(), task.ID); err != nil {
				return err
			}
			task.State, task.SubmitStarted = "running", 1
		}
		// Admission retries preserve the original ID. The root queue reserves a
		// stable child ID; immutable child receipts govern execution recovery.
		operation, err = executor.ChangeFail2banUpgrade(ctx, payload.Request)
		if err != nil {
			submitErr := err
			operation, err = executor.Fail2banUpgradeOperation(ctx, task.OperationID)
			if errors.As(err, &remote) && remote.Code == "FAIL2BAN_UPGRADE_OPERATION_MISSING" {
				var rejected *fault.Error
				if errors.As(submitErr, &rejected) && (rejected.Status == 400 || rejected.Status == 403 || rejected.Status == 409) {
					return s.jailTaskUpdate(ctx, task, "failed", "agent_rejected", rejected.Message, false)
				}
				return s.jailTaskUpdate(ctx, task, "running", "submit_unconfirmed", "提交结果待确认，继续核对原操作", false)
			}
		}
	}
	if err != nil {
		return s.jailTaskUpdate(ctx, task, task.State, "reconciling", "无法确认 Agent Fail2ban 升级操作，保留原标识等待核对", false)
	}
	if !operation.Valid() || operation.ID != task.OperationID || operation.RequestHash != payload.Request.Hash() || operation.Input != payload.Input {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_mismatch", "Agent Fail2ban 升级操作与冻结任务不一致", true)
	}
	payload.Result = &operation
	next, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if bytes.Equal(next, plain) {
		next = nil
	}
	return s.fail2banTaskUpdate(ctx, task, operation.State, operation.Stage, operation.Error, true, next)
}
