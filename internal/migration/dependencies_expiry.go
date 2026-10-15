package migration

import (
	"context"
	"errors"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

// Expiry stops creation, while accepted child operations keep their own root
// deadlines. Only observations of the original child can settle this parent.
func (s *Service) expireDependencies(ctx context.Context, id, owner string, d *DependencyStatus, install bool) error {
	childID := d.PrepareTaskID
	if childID == "" {
		childID = d.CheckTaskID
	}
	if childID == "" {
		return s.saveDependency(ctx, id, d, "failed", "grant_expired", "依赖准备授权已过期，未创建组件任务")
	}
	if s.Components == nil {
		return s.saveDependency(ctx, id, d, "recovery_required", "grant_expired", "准备授权已过期，原组件任务结果待核对")
	}
	task, err := s.Components.Get(ctx, auth.Principal{ID: owner, Scopes: []string{"components.manage"}}, childID)
	if err != nil {
		var f *fault.Error
		if !errors.As(err, &f) || f.Status != 404 {
			return err
		}
		return s.saveDependency(ctx, id, d, "recovery_required", "grant_expired", "准备授权已过期，原组件任务记录缺失，停止新提交")
	}
	if !install && task.State == "succeeded" && d.PrepareTaskID != "" && task.Result != nil && task.Result.Stage == "prepared" {
		return s.saveDependency(ctx, id, d, "succeeded", "prepared", "")
	}
	if task.State == "succeeded" || task.State == "failed" || task.State == "cancelled" || task.State == "rolled_back" {
		return s.saveDependency(ctx, id, d, "failed", "grant_expired", "依赖准备授权已过期；原组件任务已核对，未继续提交迁移")
	}
	return s.saveDependency(ctx, id, d, "recovery_required", "grant_expired", "准备授权已过期，仅查询原组件任务；未将其视为已停止")
}
