package migration

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"nginxpanel/internal/auth"
)

func (s *Service) nextPush(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	now := time.Now().Unix()
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT p.task_id FROM migration_pushes p JOIN tasks t ON t.id=p.task_id
 WHERE (t.state IN ('queued','running') AND p.next_attempt_at<=?)
 OR (t.state IN ('queued','running','waiting_confirmation','recovery_required') AND p.expires_at<=? AND t.stage!='grant_expired')
 ORDER BY t.created_at,t.id LIMIT 1`, now, now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	j, err := s.readPush(ctx, id, true)
	if err != nil {
		return err
	}
	if j.Task.ExpiresAt <= now {
		j.Payload.Input.Remote.APIKey = ""
		j.Task.Error = "本次迁出授权已过期，未将目标操作视为停止；请重新授权后核对原任务"
		j.Task.Stage = "grant_expired"
		if j.RemoteStarted {
			j.Task.State = "recovery_required"
		} else {
			j.Task.State = "failed"
			j.Task.Error = "迁出授权已过期，未向目标提交配置"
		}
		return s.savePush(ctx, &j)
	}
	if j.Attempts >= 128 {
		return s.pausePush(ctx, &j, "recovery_required", "request_budget", "迁出请求达到本次授权预算，请核对目标后重新授权")
	}
	j.Attempts++
	j.Task.State = "running"
	j.Task.Error = ""
	j.NextAttempt = now + 2
	if err = s.savePush(ctx, &j); err != nil {
		return err
	}
	deadline := min(time.Now().Add(35*time.Second).Unix(), j.Task.ExpiresAt)
	call, cancel := context.WithDeadline(ctx, time.Unix(deadline, 0))
	defer cancel()
	remote := j.Payload.Input.Remote
	switch j.Task.Stage {
	case "connecting":
		var receiver Receiver
		expectedNode := remote.NodeID
		if j.Task.TargetBound {
			expectedNode = j.Task.TargetNode
		}
		err = pushRPC(call, remote, expectedNode, http.MethodGet, "/migrations/receiver", "", nil, &receiver)
		if err != nil {
			return s.pushPeerFailure(ctx, &j, err)
		}
		if receiver.Schema != Schema || receiver.NodeID == s.NodeID || receiver.Version < 0 || len(receiver.Scopes) > 32 {
			return s.pushPeerFailure(ctx, &j, &pushPeerError{Identity: true})
		}
		if !j.Task.TargetBound {
			j.Task.TargetNode, j.Task.TargetBound = receiver.NodeID, true
			j.Task.TargetBaseVersion = receiver.Version
			if j.Payload.Input.BaseVersion != nil {
				j.Task.TargetBaseVersion = *j.Payload.Input.BaseVersion
			}
		}
		target := auth.Principal{Scopes: receiver.Scopes}
		required := []string{"backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"}
		if j.Payload.Input.Dependencies != nil {
			required = append(required, "components.manage")
		}
		if j.Payload.Input.EnableNginx || j.Payload.Input.Dependencies != nil && j.Payload.Input.Dependencies.Install != nil {
			required = append(required, "system.write")
		}
		if target.Require(required...) != nil {
			return s.pausePush(ctx, &j, "waiting_confirmation", "target_permissions", "目标 Key 缺少本次迁入所需权限，请补齐授权")
		}
		j.Task.Stage, j.Payload.ResumeStage = "preparing", "preparing"
		return s.savePush(ctx, &j)
	case "preparing":
		if !j.Task.TargetBound || !validTransferID(j.Task.TargetNode) {
			return s.pausePush(ctx, &j, "recovery_required", "invalid_binding", "目标身份绑定缺失，停止提交")
		}
		var plan Plan
		err = pushRPC(call, remote, j.Task.TargetNode, http.MethodGet, "/migrations/"+j.Task.ID, "", nil, &plan)
		var peer *pushPeerError
		if errors.As(err, &peer) && peer.Status == http.StatusNotFound {
			if j.Task.Plan != nil {
				return s.pausePush(ctx, &j, "recovery_required", "target_missing", "已确认的目标计划缺失，停止重新创建")
			}
			j.RemoteStarted = true
			if err = s.savePush(ctx, &j); err != nil {
				return err
			}
			transfer := j.Payload.Transfer
			transfer.Mappings = j.Payload.Input.Mappings
			transfer.Firewall = j.Payload.Input.Firewall
			transfer.Fail2ban = j.Payload.Input.Fail2ban
			transfer.BaseVersion = j.Task.TargetBaseVersion
			err = pushRPC(call, remote, j.Task.TargetNode, http.MethodPut, "/migrations/receive/"+j.Task.ID, "", transfer, &plan)
		}
		if err != nil {
			return s.pushPeerFailure(ctx, &j, err)
		}
		if err = s.acceptPushPlan(&j, plan); err != nil {
			return s.pushPeerFailure(ctx, &j, &pushPeerError{Identity: true})
		}
		if j.Payload.Input.Mode == "preview" {
			if plan.State != "planned" {
				return s.pausePush(ctx, &j, "recovery_required", "target_changed", "目标计划已有执行结果，与仅预检请求不符")
			}
			j.Task.State, j.Task.Stage = "succeeded", "preview"
			return s.savePush(ctx, &j)
		}
		if j.Payload.Input.Dependencies != nil {
			j.Task.Stage, j.Payload.ResumeStage = "dependencies", "dependencies"
			return s.savePush(ctx, &j)
		}
		j.Task.Stage, j.Payload.ResumeStage = "executing", "executing"
		return s.savePush(ctx, &j)
	case "dependencies":
		return s.pushDependencies(call, ctx, &j)
	case "executing", "observing":
		if !j.Task.TargetBound || j.Task.Plan == nil {
			return s.pausePush(ctx, &j, "recovery_required", "invalid_binding", "原目标计划缺失，停止重新提交")
		}
		var plan Plan
		err = pushRPC(call, remote, j.Task.TargetNode, http.MethodGet, "/migrations/"+j.Task.ID, "", nil, &plan)
		if err != nil {
			var peer *pushPeerError
			if errors.As(err, &peer) && peer.Status == http.StatusNotFound {
				return s.pausePush(ctx, &j, "recovery_required", "target_missing", "已确认的目标计划缺失，停止重新创建")
			}
			return s.pushPeerFailure(ctx, &j, err)
		}
		if err = s.acceptPushPlan(&j, plan); err != nil {
			return s.pushPeerFailure(ctx, &j, &pushPeerError{Identity: true})
		}
		if plan.State == "planned" {
			if j.Task.Stage == "observing" {
				return s.pausePush(ctx, &j, "recovery_required", "target_changed", "目标计划退回执行前状态，停止重新应用")
			}
			err = pushRPC(call, remote, j.Task.TargetNode, http.MethodPost, "/migrations/"+j.Task.ID+"/execute", "migration-push:"+j.Task.ID, ExecuteInput{Mode: j.Payload.Input.Mode, EnableNginx: j.Payload.Input.EnableNginx}, &plan)
			if err != nil {
				return s.pushPeerFailure(ctx, &j, err)
			}
			if err = s.acceptPushPlan(&j, plan); err != nil {
				return s.pushPeerFailure(ctx, &j, &pushPeerError{Identity: true})
			}
		}
		return s.observePush(ctx, &j)
	default:
		return s.pausePush(ctx, &j, "recovery_required", "unknown_stage", "迁出阶段无法确认，保留原任务等待恢复")
	}
}
func (s *Service) acceptPushPlan(j *pushJob, plan Plan) error {
	clean, err := sanitizePushPlan(plan, j.Payload.Input.Remote, j.Payload.Transfer.Passphrase)
	if err != nil {
		return err
	}
	if plan.ID != j.Task.ID || plan.SourceNode != s.NodeID || plan.BaseVersion != j.Task.TargetBaseVersion || plan.PackageSHA256 != j.Task.PackageSHA256 {
		return errors.New("target plan mismatch")
	}
	if err = acceptPushFail2ban(plan, j.Payload.Input, j.Task.Plan); err != nil {
		return err
	}
	if err = acceptPushFirewall(plan, j.Payload.Input, j.Task.Plan); err != nil {
		return err
	}
	switch plan.State {
	case "planned":
	case "draft", "saved", "applying", "succeeded", "failed", "rolled_back", "recovery_required":
	default:
		return errors.New("invalid target state")
	}
	if plan.RevisionID != "" && !validTransferID(plan.RevisionID) || plan.TaskID != "" && !validTransferID(plan.TaskID) {
		return errors.New("invalid target execution identity")
	}
	j.Task.Plan = &clean
	j.RemoteStarted = true
	return nil
}
func (s *Service) observePush(ctx context.Context, j *pushJob) error {
	plan := j.Task.Plan
	switch plan.State {
	case "draft", "saved":
		if j.Task.Mode == "draft" && plan.State == "draft" || j.Task.Mode == "save" && plan.State == "saved" {
			j.Task.State, j.Task.Stage = "succeeded", plan.State
			return s.savePush(ctx, j)
		}
	case "applying":
		if j.Task.Mode == "apply" && validTransferID(plan.TaskID) && validTransferID(plan.RevisionID) {
			j.Task.Stage, j.Payload.ResumeStage = "observing", "observing"
			j.NextAttempt = time.Now().Unix() + 5
			return s.savePush(ctx, j)
		}
	case "succeeded":
		if j.Task.Mode == "apply" && validTransferID(plan.TaskID) && validTransferID(plan.RevisionID) {
			j.Task.State, j.Task.Stage = "succeeded", "succeeded"
			return s.savePush(ctx, j)
		}
	case "rolled_back":
		j.Task.State, j.Task.Stage, j.Task.Error = "rolled_back", "rolled_back", "目标应用失败，目标已确认补偿"
		return s.savePush(ctx, j)
	case "failed":
		j.Task.State, j.Task.Stage, j.Task.Error = "failed", "failed", "目标计划已失败，未报告迁移成功"
		return s.savePush(ctx, j)
	case "recovery_required":
		return s.pausePush(ctx, j, "recovery_required", "target_recovery", "目标需要恢复；请在目标处理后核对原计划")
	}
	return s.pausePush(ctx, j, "recovery_required", "target_changed", "目标执行状态与本次迁出模式不一致，停止后续提交")
}
func (s *Service) pausePush(ctx context.Context, j *pushJob, state, stage, message string) error {
	// Resume always continues the original persisted stage and immutable target ID.
	if j.Task.Stage == "connecting" || j.Task.Stage == "preparing" || j.Task.Stage == "dependencies" || j.Task.Stage == "executing" || j.Task.Stage == "observing" {
		j.Payload.ResumeStage = j.Task.Stage
	}
	j.Task.State, j.Task.Stage, j.Task.Error = state, stage, message
	j.NextAttempt = 0
	return s.savePush(ctx, j)
}
func (s *Service) pushPeerFailure(ctx context.Context, j *pushJob, err error) error {
	var peer *pushPeerError
	if !errors.As(err, &peer) {
		return err
	}
	if peer.Identity {
		if !j.RemoteStarted {
			j.Task.State, j.Task.Stage, j.Task.Error = "failed", "identity_mismatch", "目标身份、TLS 或迁移协议无法确认，未提交配置"
			return s.savePush(ctx, j)
		}
		return s.pausePush(ctx, j, "recovery_required", "identity_mismatch", "目标身份或响应无法确认，保留原计划并停止提交")
	}
	if peer.Status == http.StatusUnauthorized || peer.Status == http.StatusForbidden {
		return s.pausePush(ctx, j, "recovery_required", "target_permissions", "目标 Key 已失效或权限不足，请重新授权后核对原任务")
	}
	if peer.Plan != nil {
		if err = s.acceptPushPlan(j, *peer.Plan); err != nil {
			return s.pausePush(ctx, j, "recovery_required", "identity_mismatch", "目标预检结果不匹配，停止提交")
		}
		return s.pausePush(ctx, j, "waiting_confirmation", "preflight_blocked", "目标预检尚未通过，请处理逐项结果后继续")
	}
	if peer.Status >= 400 && peer.Status < 500 && peer.Status != http.StatusTooManyRequests && peer.Code != "MAINTENANCE_ACTIVE" {
		return s.pausePush(ctx, j, "waiting_confirmation", "target_blocked", "目标拒绝当前步骤，请核对权限、基础版本、依赖和并发任务后继续")
	}
	delay := int64(2) << min(j.Attempts, 5)
	delay = min(delay, 60)
	if peer.Code == "MAINTENANCE_ACTIVE" {
		delay = max(delay, 30)
	}
	delay = max(delay, peer.Wait)
	j.NextAttempt = time.Now().Unix() + delay
	j.Task.Error = "目标暂不可达或正在维护，等待核对原任务"
	return s.savePush(ctx, j)
}
