package fail2ban

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/storage/dbgen"
)

func existingMissing(err error) bool {
	var remote *fault.Error
	return errors.As(err, &remote) && remote.Code == "FAIL2BAN_EXISTING_OPERATION_MISSING"
}

func (s *PolicyService) nextExistingTask(ctx context.Context, executor ExistingPolicyExecutor, task dbgen.Task) error {
	_, payload, err := s.existingTask(ctx, s.DB, task.ID)
	if err != nil {
		return s.jailTaskUpdate(ctx, task, "recovery_required", "payload_invalid", "已有 jail 任务材料无法核对，停止重新提交", false)
	}
	update := func(state, stage, message string, accepted bool) error {
		return s.existingTaskUpdate(ctx, task, payload, nil, state, stage, message, accepted)
	}
	operation, err := executor.Fail2banExistingPolicyOperation(ctx, task.OperationID)
	if existingMissing(err) {
		if task.AgentAccepted != 0 {
			return update("recovery_required", "operation_missing", "已接受的参数操作记录缺失，停止重新提交", false)
		}
		if payload.CancelGeneration > 0 {
			if task.SubmitStarted != 0 {
				return update("recovery_required", "cancel_unconfirmed", "提交已开始但原操作缺失，取消结果须本机核对", false)
			}
			return update("failed", "cancelled", "", false)
		}
		if task.SubmitStarted == 0 {
			if time.Now().Unix() < task.CreatedAt || time.Now().Unix()-task.CreatedAt > 300 {
				return update("failed", "authorization_expired", "参数请求排队超过五分钟，须重新预览", false)
			}
			if err = s.moduleEnabled(ctx, s.DB); err != nil {
				return update("failed", "module_disabled", err.Error(), false)
			}
			if err = s.migrationIdle(ctx, s.DB); err != nil {
				return update("failed", "migration_pending", err.Error(), false)
			}
		}
		started, latest, beginErr := s.existingBeginSubmit(ctx, task, payload)
		if beginErr != nil {
			return beginErr
		}
		payload = latest
		if !started {
			if task.SubmitStarted != 0 {
				return update("recovery_required", "cancel_unconfirmed", "提交已开始但原操作缺失，取消结果须本机核对", false)
			}
			return update("failed", "cancelled", "", false)
		}
		task.State, task.SubmitStarted = "running", 1
		operation, err = executor.SubmitFail2banExistingPolicy(ctx, payload.Request)
		if err != nil {
			submitErr := err
			operation, err = executor.Fail2banExistingPolicyOperation(ctx, task.OperationID)
			if existingMissing(err) {
				var rejected *fault.Error
				if errors.As(submitErr, &rejected) && (rejected.Status == 400 || rejected.Status == 403 || rejected.Status == 409) {
					return update("failed", "agent_rejected", rejected.Message, false)
				}
				return update("running", "submit_unconfirmed", "提交结果待确认，继续查询原操作", false)
			}
		}
	}
	if err != nil {
		return update(task.State, "reconciling", "无法确认 Agent 参数操作，保留原标识等待核对", false)
	}
	if !payload.matches(operation) {
		return update("recovery_required", "operation_mismatch", "Agent 参数操作与冻结请求不一致", true)
	}
	if payload.CancelGeneration > payload.CancelObserved {
		if operation.State == "succeeded" || operation.State == "failed" {
			payload.CancelObserved = payload.CancelGeneration
			if operation.State == "succeeded" {
				payload.CancelError = "原操作已经完成，恢复参数须新建预览和应用"
			}
		} else {
			next, cancelErr := executor.CancelFail2banExistingPolicy(ctx, task.OperationID)
			if cancelErr == nil {
				if !payload.matches(next) {
					return update("recovery_required", "operation_mismatch", "取消回执与原参数操作不一致", true)
				}
				if !next.CancelRequested && next.CancelError == "" && next.State != "succeeded" && next.State != "failed" {
					return update("recovery_required", "cancel_unconfirmed", "取消请求缺少受理依据，继续核对原操作", true)
				}
				operation = next
				payload.CancelObserved = payload.CancelGeneration
			} else {
				var rejected *fault.Error
				if errors.As(cancelErr, &rejected) && (rejected.Status == 400 || rejected.Status == 403 || rejected.Status == 409) {
					payload.CancelObserved, payload.CancelError = payload.CancelGeneration, rejected.Message
				}
			}
		}
	}
	if payload.CancelObserved == payload.CancelGeneration && payload.CancelGeneration > 0 {
		if operation.CancelError != "" {
			payload.CancelError = operation.CancelError
		}
		if operation.State == "succeeded" {
			payload.CancelError = "原操作已经完成，恢复参数须新建预览和应用"
		} else if operation.CancelRequested {
			payload.CancelError = ""
		}
	}
	return s.existingTaskUpdate(ctx, task, payload, &operation, operation.State, operation.Stage, operation.Error, true)
}

// Persist dispatch admission under the cancellation lock. A cancellation saved
// before this marker prevents the first submission and any unknown retry.
func (s *PolicyService) existingBeginSubmit(ctx context.Context, task dbgen.Task, original existingTaskPayload) (bool, existingTaskPayload, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	item, latest, err := s.existingTask(ctx, s.DB, task.ID)
	if err != nil {
		return false, latest, err
	}
	if latest.Request.Hash() != original.Request.Hash() || item.Stage == "restore_isolated" || item.State != "queued" && item.State != "running" && item.State != "recovery_required" {
		return false, latest, errors.New("已有 jail 请求或派发准入状态变化")
	}
	if latest.CancelGeneration > 0 {
		return false, latest, nil
	}
	if task.SubmitStarted == 0 {
		_, err = s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='agent_submit_pending',submit_started=1,attempts=attempts+1,updated_at=? WHERE id=?", time.Now().Unix(), task.ID)
	}
	return err == nil, latest, err
}

// Merge under the same lock as cancellation admission. An in-flight Agent read
// must never overwrite a newer durable cancellation generation.
func (s *PolicyService) existingTaskUpdate(ctx context.Context, task dbgen.Task, observed existingTaskPayload, operation *ExistingPolicyOperation, state, stage, message string, accepted bool) error {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	_, latest, err := s.existingTask(ctx, s.DB, task.ID)
	if err != nil {
		return err
	}
	if latest.Request.Hash() != observed.Request.Hash() {
		return errors.New("已有 jail 冻结请求发生变化")
	}
	before, _ := json.Marshal(latest)
	if operation != nil {
		latest.Result = operation
	}
	if latest.CancelGeneration == observed.CancelGeneration {
		latest.CancelObserved = max(latest.CancelObserved, observed.CancelObserved)
		latest.CancelError = observed.CancelError
	}
	if (state == "succeeded" || state == "failed") && latest.CancelGeneration > latest.CancelObserved {
		latest.CancelObserved = latest.CancelGeneration
		if state == "succeeded" {
			latest.CancelError = "原操作已经完成，恢复参数须新建预览和应用"
		}
	}
	after, _ := json.Marshal(latest)
	var next []byte
	if string(before) != string(after) {
		next = after
	}
	return s.fail2banTaskUpdate(ctx, task, state, stage, message, accepted, next)
}
