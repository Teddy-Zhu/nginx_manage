package migration

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func (s *Service) pushDependencies(call, ctx context.Context, j *pushJob) error {
	if !j.Task.TargetBound || j.Payload.Input.Dependencies == nil {
		return s.pausePush(ctx, j, "recovery_required", "invalid_binding", "依赖准备授权或目标绑定缺失，停止提交")
	}
	var plan Plan
	err := pushRPC(call, j.Payload.Input.Remote, j.Task.TargetNode, http.MethodGet, "/migrations/"+j.Task.ID, "", nil, &plan)
	if err != nil {
		var peer *pushPeerError
		if errors.As(err, &peer) && peer.Status == http.StatusNotFound {
			return s.pausePush(ctx, j, "recovery_required", "target_missing", "已确认的目标计划缺失，停止重新创建")
		}
		return s.pushPeerFailure(ctx, j, err)
	}
	if err = s.acceptPushPlan(j, plan); err != nil {
		return s.pushPeerFailure(ctx, j, &pushPeerError{Identity: true})
	}
	if plan.State != "planned" {
		return s.pausePush(ctx, j, "recovery_required", "target_changed", "依赖准备期间目标迁移状态已变化，请核对原计划")
	}
	if plan.Dependencies == nil {
		err = pushRPC(call, j.Payload.Input.Remote, j.Task.TargetNode, http.MethodPost, "/migrations/"+j.Task.ID+"/dependencies", "migration-deps:"+j.Task.ID, *j.Payload.Input.Dependencies, &plan)
		if err != nil {
			return s.pushPeerFailure(ctx, j, err)
		}
		if err = s.acceptPushPlan(j, plan); err != nil {
			return s.pushPeerFailure(ctx, j, &pushPeerError{Identity: true})
		}
	}
	d := j.Task.Plan.Dependencies
	if d == nil {
		return s.pushPeerFailure(ctx, j, &pushPeerError{Identity: true})
	}
	switch d.State {
	case "queued", "running":
		j.NextAttempt = time.Now().Unix() + 15
		return s.savePush(ctx, j)
	case "succeeded":
		if d.Stage != "prepared" && d.Stage != "not_required" {
			return s.pushPeerFailure(ctx, j, &pushPeerError{Identity: true})
		}
		j.Task.Stage, j.Payload.ResumeStage = "executing", "executing"
		return s.savePush(ctx, j)
	case "recovery_required":
		return s.pausePush(ctx, j, "recovery_required", "dependency_recovery", "目标依赖准备结果待恢复，请核对原组件任务")
	case "failed", "cancelled":
		j.Task.State, j.Task.Stage, j.Task.Error = "failed", "dependencies_failed", "目标依赖准备未完成，停止配置应用；请核对逐项结果并重新预检"
		return s.savePush(ctx, j)
	default:
		return s.pushPeerFailure(ctx, j, &pushPeerError{Identity: true})
	}
}
