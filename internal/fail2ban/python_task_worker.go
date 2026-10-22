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

func (s *PolicyService) nextPythonTask(ctx context.Context, executor PythonTaskExecutor, task dbgen.Task) error {
	var sealed []byte
	if err := s.DB.QueryRowContext(ctx, "SELECT payload FROM fail2ban_operations WHERE task_id=?", task.ID).Scan(&sealed); err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_missing", "Python 依赖操作材料缺失，停止重新提交", false)
	}
	plain, err := s.Vault.Open(sealed, "fail2ban:operation:"+task.ID)
	if err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_unreadable", "Python 依赖操作材料无法解密，停止重新提交", false)
	}
	var payload pythonTaskPayload
	if json.Unmarshal(plain, &payload) != nil || !payload.valid(task.OperationID) {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_invalid", "Python 依赖操作合同无法核对，停止重新提交", false)
	}
	operation, err := executor.Fail2banPythonOperation(ctx, task.OperationID)
	var remote *fault.Error
	if errors.As(err, &remote) && remote.Code == "FAIL2BAN_PYTHON_OPERATION_MISSING" {
		if task.AgentAccepted != 0 {
			return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_missing", "已接受的 Python 依赖操作记录缺失，停止重新执行", false)
		}
		knownUnsent := task.SubmitStarted == 0
		if knownUnsent {
			if time.Now().Unix() < task.CreatedAt || time.Now().Unix()-task.CreatedAt > 300 {
				return s.jailTaskUpdate(ctx, task, "failed", "authorization_expired", "Python 依赖操作排队超过五分钟，请重新生成依赖计划", false)
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
		// Admission retries preserve the original ID. A durable root sent marker
		// prevents replaying repository refresh or package installation after interruption.
		operation, err = executor.ChangeFail2banPython(ctx, payload.Request)
		if err != nil {
			submitErr := err
			operation, err = executor.Fail2banPythonOperation(ctx, task.OperationID)
			if errors.As(err, &remote) && remote.Code == "FAIL2BAN_PYTHON_OPERATION_MISSING" {
				var rejected *fault.Error
				if knownUnsent && errors.As(submitErr, &rejected) && rejected.Status == 503 && rejected.Code == PythonTaskBusyCode {
					return s.pythonWaitForAdmission(ctx, task, sealed)
				}
				if errors.As(submitErr, &rejected) && (rejected.Status == 400 || rejected.Status == 403 || rejected.Status == 409) {
					return s.jailTaskUpdate(ctx, task, "failed", "agent_rejected", rejected.Message, false)
				}
				return s.jailTaskUpdate(ctx, task, "running", "submit_unconfirmed", "提交结果待确认，继续核对原操作", false)
			}
		}
	}
	if err != nil {
		return s.jailTaskUpdate(ctx, task, task.State, "reconciling", "无法确认 Agent Python 依赖操作，保留原标识等待核对", false)
	}
	if !ValidPythonTaskOperation(operation) || operation.ID != task.OperationID || operation.RequestHash != payload.Request.Hash() || operation.Input != payload.Input {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "operation_mismatch", "Agent Python 依赖操作与冻结任务不一致", true)
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

// Clear admission only for an explicit pre-acceptance refusal and an absent
// root record. Unknown submissions keep their marker and original identity.
func (s *PolicyService) pythonWaitForAdmission(ctx context.Context, task dbgen.Task, sealed []byte) error {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	result, err := s.DB.ExecContext(ctx, "UPDATE tasks SET state='queued',stage='waiting_for_admission',last_error='宿主机操作暂被占用，等待准入',submit_started=0,updated_at=? WHERE id=? AND agent_accepted=0 AND submit_started=1 AND stage!='restore_isolated' AND state IN ('queued','running','recovery_required') AND EXISTS(SELECT 1 FROM fail2ban_operations WHERE task_id=tasks.id AND payload=?)", time.Now().Unix(), task.ID, sealed)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err == nil && changed != 1 {
		err = errors.New("Python 依赖准入等待状态或请求材料变化")
	}
	return err
}
