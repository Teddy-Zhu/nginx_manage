package migration

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
)

func (s *Service) linkDependencyInstallation(ctx context.Context, tx *sql.Tx, id, column, childID string, version int64) error {
	// column is selected by the two internal callers, never from request data.
	result, err := tx.ExecContext(ctx, `UPDATE migration_dependencies SET `+column+`=? WHERE plan_id=? AND deadline>?
 AND (`+column+`='' OR `+column+`=?) AND settlement_state=''
 AND EXISTS(SELECT 1 FROM migration_plans WHERE id=plan_id AND state='planned')
 AND EXISTS(SELECT 1 FROM tasks WHERE id=migration_dependencies.task_id AND state IN ('queued','running','recovery_required'))
 AND (SELECT version FROM config_head WHERE id=1)=?`, childID, id, time.Now().Unix(), childID, version)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fault.Conflict("迁移安装授权、目标版本或子任务关联已变化")
	}
	return nil
}

func (s *Service) startDependencyMaintenance(ctx context.Context, id, owner string, d *DependencyStatus, version int64) error {
	if s.Maintenance == nil || s.Installations == nil {
		return s.saveDependency(ctx, id, d, "failed", "installation_unavailable", "首次安装协调服务未配置")
	}
	p := auth.Principal{ID: owner, Scopes: []string{"system.write"}}
	child, err := s.Maintenance.StartLinked(ctx, p, d.TaskID, "migration-deps:"+id+":maintenance", maintenance.StartInput{DrainSeconds: 120}, d.TaskID, func(tx *sql.Tx, child maintenance.Session) error {
		if child.OwnerTaskID != d.TaskID {
			return fault.Conflict("维护父任务不匹配")
		}
		return s.linkDependencyInstallation(ctx, tx, id, "maintenance_task_id", child.TaskID, version)
	})
	if err != nil {
		var f *fault.Error
		if errors.As(err, &f) && f.Status >= 400 && f.Status < 500 {
			return s.saveDependency(ctx, id, d, "failed", "maintenance_blocked", "自动维护未获准，未提交首次安装")
		}
		return err
	}
	d.MaintenanceTaskID = child.TaskID
	return s.saveDependency(ctx, id, d, "running", "maintenance", "")
}

func (s *Service) beginDependencySettlement(ctx context.Context, id string, d *DependencyStatus, state, stage, message string) error {
	d.SettlementState, d.SettlementStage, d.SettlementError = state, stage, message
	return s.saveDependency(ctx, id, d, "running", "releasing", message)
}

func (s *Service) coordinateDependencyInstallation(ctx context.Context, id, owner, planOwner string, d *DependencyStatus, in DependencyInput, plan Plan, version int64) error {
	finish := func(state, stage, message string) error { return s.saveDependency(ctx, id, d, state, stage, message) }
	if in.Install == nil || s.Maintenance == nil || s.Installations == nil || s.Components == nil {
		return finish("recovery_required", "input_invalid", "首次安装授权或协调服务无法确认，保留原维护记录")
	}
	var phase, parent, principal string
	err := s.DB.QueryRowContext(ctx, "SELECT phase,COALESCE(owner_task_id,''),principal FROM maintenance_sessions WHERE task_id=?", d.MaintenanceTaskID).Scan(&phase, &parent, &principal)
	if errors.Is(err, sql.ErrNoRows) {
		return finish("recovery_required", "maintenance_missing", "原维护记录缺失，停止重新创建")
	}
	if err != nil {
		return err
	}
	if parent != d.TaskID || principal != owner {
		return finish("recovery_required", "maintenance_mismatch", "维护归属无法确认，停止提交")
	}
	if d.SettlementState != "" {
		return s.settleDependencyInstallation(ctx, id, owner, planOwner, d, phase, plan, version)
	}
	if d.InstallTaskID != "" {
		child, err := s.Installations.Get(ctx, auth.Principal{ID: owner, Scopes: []string{"components.manage"}}, d.InstallTaskID)
		if err != nil {
			var f *fault.Error
			if errors.As(err, &f) && f.Status == 404 {
				return finish("recovery_required", "install_missing", "原安装任务缺失，保留维护状态并停止重新创建")
			}
			return err
		}
		if child.Input.MaintenanceID != d.MaintenanceTaskID || child.PrepareTaskID != d.PrepareTaskID {
			return finish("recovery_required", "install_mismatch", "安装任务与迁移授权不匹配，保留维护状态")
		}
		switch child.State {
		case "succeeded":
			if child.Result == nil || child.Result.State != "succeeded" {
				return finish("recovery_required", "install_mismatch", "安装完成记录缺少独立执行结果，保留维护状态")
			}
			return s.beginDependencySettlement(ctx, id, d, "succeeded", "installed", "")
		case "failed", "cancelled":
			return s.beginDependencySettlement(ctx, id, d, "failed", "installation_failed", "首次安装未完成，未继续写入迁移配置；请核对原安装任务")
		case "recovery_required":
			return finish("recovery_required", "installation_recovery", "原安装结果待恢复，维护保持关闭；请在组件安装中恢复或取消原任务")
		case "queued", "running":
			return finish("running", "installing", "")
		default:
			return finish("recovery_required", "install_mismatch", "原安装任务状态无法确认，保留维护状态")
		}
	}
	if d.Deadline <= time.Now().Unix() || plan.ExpiresAt <= time.Now().Unix() {
		return s.beginDependencySettlement(ctx, id, d, "failed", "grant_expired", "迁移安装授权已过期，未提交首次安装")
	}
	if plan.State != "planned" || version != plan.BaseVersion {
		return s.beginDependencySettlement(ctx, id, d, "failed", "target_changed", "目标配置或迁移状态已变化，未提交首次安装")
	}
	if phase == "released" || phase == "failed" || phase == "releasing" {
		return s.beginDependencySettlement(ctx, id, d, "failed", "maintenance_lost", "维护未完成或已被释放，未提交首次安装")
	}
	if phase == "recovery_required" {
		return finish("recovery_required", "maintenance_recovery", "原维护结果待恢复，未提交首次安装")
	}
	if phase != "held" || s.Maintenance.View().Phase != "held" {
		return finish("running", "maintenance", "")
	}
	prepared, err := s.Components.Get(ctx, auth.Principal{ID: owner, Scopes: []string{"components.manage"}}, d.PrepareTaskID)
	if err != nil {
		var f *fault.Error
		if errors.As(err, &f) && f.Status == 404 {
			return s.beginDependencySettlement(ctx, id, d, "failed", "prepare_unconfirmed", "原准备任务缺失，未提交首次安装")
		}
		return err
	}
	assetID := ""
	if prepared.State == "succeeded" && prepared.Result != nil && prepared.Result.Release != nil {
		for _, asset := range prepared.Result.Release.Assets {
			if asset.Component != "nginx" {
				continue
			}
			for _, selected := range prepared.Result.Release.Selected {
				if selected == asset.ID {
					if assetID != "" {
						return s.beginDependencySettlement(ctx, id, d, "failed", "install_mismatch", "准备结果包含多个 Nginx 资产，未提交首次安装")
					}
					assetID = asset.ID
				}
			}
		}
	}
	if assetID == "" {
		return s.beginDependencySettlement(ctx, id, d, "failed", "prepare_unconfirmed", "原准备任务没有可安装的 Nginx 资产")
	}
	p := auth.Principal{ID: owner, Scopes: []string{"components.manage", "system.write"}}
	child, err := s.Installations.CreateLinked(ctx, p, d.TaskID, "migration-deps:"+id+":install", nginxinstall.CreateInput{MaintenanceID: d.MaintenanceTaskID, PrepareTaskID: d.PrepareTaskID, AssetID: assetID, Start: *in.Install.Start, Enable: *in.Install.Enable}, d.Deadline, func(tx *sql.Tx, child nginxinstall.Task) error {
		return s.linkDependencyInstallation(ctx, tx, id, "install_task_id", child.ID, plan.BaseVersion)
	})
	if err != nil {
		var f *fault.Error
		if errors.As(err, &f) && f.Status >= 400 && f.Status < 500 {
			return s.beginDependencySettlement(ctx, id, d, "failed", "installation_blocked", "首次安装未获准，未继续迁移；请核对安装条件")
		}
		if errors.As(err, &f) && f.Status >= 500 {
			return finish("running", "installation_wait", "安装服务暂不可用，等待核对原授权")
		}
		return err
	}
	d.InstallTaskID = child.ID
	return finish("running", "installing", "")
}

func (s *Service) settleDependencyInstallation(ctx context.Context, id, owner, planOwner string, d *DependencyStatus, phase string, plan Plan, version int64) error {
	finish := func(state, stage, message string) error { return s.saveDependency(ctx, id, d, state, stage, message) }
	if phase != "released" && phase != "failed" {
		if phase != "releasing" {
			_, err := s.Maintenance.Release(ctx, auth.Principal{ID: owner, Scopes: []string{"system.write"}}, d.TaskID, d.MaintenanceTaskID)
			if err != nil {
				var f *fault.Error
				if errors.As(err, &f) && f.Status >= 400 && f.Status < 500 {
					return finish("recovery_required", "release_blocked", "维护释放尚未获准，保留原记录等待核对")
				}
				return err
			}
		}
		return finish("running", "releasing", d.SettlementError)
	}
	if d.SettlementState != "succeeded" {
		return finish(d.SettlementState, d.SettlementStage, d.SettlementError)
	}
	if d.Deadline <= time.Now().Unix() || plan.ExpiresAt <= time.Now().Unix() {
		return finish("failed", "grant_expired", "首次安装已完成，但迁移授权已过期；未继续写入配置")
	}
	if plan.State != "planned" || version != plan.BaseVersion {
		return finish("failed", "target_changed", "首次安装已完成，但目标配置或迁移状态已变化；未继续写入配置")
	}
	done, ok := s.Maintenance.Progress()
	if !ok {
		return finish("running", "releasing", "等待写入恢复后重新预检")
	}
	defer done()
	if _, err := s.preflight(ctx, auth.Principal{ID: planOwner, Scopes: []string{"backup.restore", "backup.secrets"}}, d.TaskID, id); err != nil {
		if errors.Is(err, nginxconfig.ErrConflict) {
			return finish("failed", "target_changed", "首次安装已完成，但目标版本在重新预检期间变化；未继续写入配置")
		}
		var f *fault.Error
		if errors.As(err, &f) && f.Status >= 400 && f.Status < 500 {
			return finish("failed", "preflight_blocked", "首次安装已完成，但重新预检未获准；请核对目标计划，未继续写入配置")
		}
		return err
	}
	return finish("succeeded", "installed", "")
}
