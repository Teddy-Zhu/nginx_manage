package migration

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

// A continuation has no separate running task: its dependency coordinator owns
// maintenance draining and its eventual Nginx task owns runtime reconciliation.
func (s *Service) nextPull(ctx context.Context) error {
	if !s.mu.TryLock() {
		return nil
	}
	defer s.mu.Unlock()
	var id, owner, key string
	var raw []byte
	var status PullStatus
	err := s.DB.QueryRowContext(ctx, `SELECT plan_id,principal,key,continuation,state,stage,mode,last_error,deadline FROM migration_pulls
 WHERE continuation IS NOT NULL AND (state IN ('queued','running') OR (state='recovery_required' AND stage IN ('dependencies','observing')))
 ORDER BY created_at,plan_id LIMIT 1`).Scan(&id, &owner, &key, &raw, &status.State, &status.Stage, &status.Mode, &status.Error, &status.Deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	finish := func(state, stage, message string) error {
		return s.savePullStatus(ctx, id, &status, state, stage, message)
	}
	grant, err := s.openPullGrant(id, status.Mode, raw)
	if err != nil {
		return finish("failed", "grant_invalid", "原迁入授权无法确认，停止后续提交")
	}
	p := auth.Principal{ID: owner, Scopes: grant.Scopes}
	if p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "components.manage") != nil || (grant.Execute.EnableNginx || grant.Dependencies.Install != nil) && !p.Has("system.write") {
		return finish("failed", "grant_invalid", "原迁入权限不完整，停止后续提交")
	}
	plan, err := s.Get(ctx, p, id)
	if err != nil {
		return err
	}
	// A committed execution is observed even after the admission grant expires.
	// Expiration never means that a submitted root operation was cancelled.
	if plan.State != "planned" {
		switch plan.State {
		case "draft", "saved":
			if status.Mode == "draft" && plan.State == "draft" || status.Mode == "save" && plan.State == "saved" {
				return finish("succeeded", plan.State, "")
			}
		case "applying", "succeeded", "rolled_back", "recovery_required":
			if status.Mode == "apply" && validTransferID(plan.RevisionID) && validTransferID(plan.TaskID) {
				switch plan.State {
				case "applying":
					return finish("running", "observing", "")
				case "succeeded":
					return finish("succeeded", "succeeded", "")
				case "rolled_back":
					return finish("rolled_back", "rolled_back", "目标应用失败，原运行与期望配置已确认恢复")
				default:
					return finish("recovery_required", "observing", "原 Nginx 应用结果待恢复，未重复提交")
				}
			}
		case "failed":
			return finish("failed", "plan_failed", "原迁移计划已结束，未继续提交")
		}
		return finish("failed", "target_changed", "原迁入计划状态与授权不符，停止后续提交")
	}
	if status.Stage == "observing" {
		return finish("failed", "target_changed", "原计划已退回执行前状态，停止重复应用")
	}
	if status.Deadline <= time.Now().Unix() || plan.ExpiresAt <= time.Now().Unix() {
		return finish("failed", "grant_expired", "迁入授权已过期，停止新的配置提交；已接受的组件操作仍按原记录核对")
	}
	d := plan.Dependencies
	if d == nil && status.Stage != "preparing_dependencies" {
		return finish("failed", "dependency_missing", "原依赖任务缺失，停止重新创建")
	}
	if d != nil {
		var dependencyOwner, digest string
		if err := s.DB.QueryRowContext(ctx, "SELECT principal,request_hash FROM migration_dependencies WHERE plan_id=?", id).Scan(&dependencyOwner, &digest); err != nil {
			return err
		}
		expected, err := dependencyDigest(id, grant.Dependencies)
		if err != nil {
			return err
		}
		if dependencyOwner != owner || digest != expected {
			return finish("failed", "dependency_invalid", "原依赖任务与本次迁入授权不符，未继续配置迁入")
		}
		switch d.State {
		case "queued", "running":
			return finish("running", "dependencies", "")
		case "recovery_required":
			return finish("recovery_required", "dependencies", "原依赖操作待恢复，未继续配置迁入")
		case "failed", "cancelled":
			return finish("failed", "dependencies_failed", "依赖准备未完成，未继续配置迁入；请核对原组件任务")
		case "succeeded":
			if d.Stage != "prepared" && d.Stage != "not_required" && d.Stage != "installed" {
				return finish("failed", "dependency_invalid", "原依赖结果无法确认，未继续配置迁入")
			}
		default:
			return finish("failed", "dependency_invalid", "原依赖状态无法确认，未继续配置迁入")
		}
	}
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var version int64
	if err := s.DB.QueryRowContext(ctx, "SELECT version FROM config_head WHERE id=1").Scan(&version); err != nil {
		return err
	}
	if version != plan.BaseVersion {
		return finish("failed", "target_changed", "目标基础版本已变化，未继续配置迁入")
	}
	if d == nil {
		if s.Components == nil || grant.Dependencies.Install != nil && (s.Installations == nil || s.Maintenance == nil) {
			return finish("failed", "unavailable", "依赖协调服务不可用，未继续配置迁入")
		}
		_, err = s.prepareDependencies(ctx, p, id, "migration-pull-deps:"+id, id, grant.Dependencies)
		if err != nil {
			var f *fault.Error
			if errors.As(err, &f) && f.Status == 409 {
				return finish("running", "preparing_dependencies", "等待现有依赖准备任务结束")
			}
			return s.pullFailure(ctx, id, &status, "dependencies_blocked", err)
		}
		return finish("running", "dependencies", "")
	}
	if status.Stage != "executing" {
		return finish("running", "executing", "")
	}
	_, err = s.execute(ctx, p, id, pullExecuteKey(owner, key), id, grant.Execute)
	if err != nil {
		return s.pullFailure(ctx, id, &status, "execution_blocked", err)
	}
	// Execute commits the immutable revision, task and idempotency response in
	// one transaction. The next pass observes that original result after restart.
	return finish("running", "observing", "")
}

func (s *Service) pullFailure(ctx context.Context, id string, status *PullStatus, stage string, err error) error {
	var f *fault.Error
	if errors.As(err, &f) && f.Status >= 400 {
		return s.savePullStatus(ctx, id, status, "failed", stage, "目标条件未满足，已停止自动迁入；请核对原计划及逐项预检结果")
	}
	return err
}

func (s *Service) savePullStatus(ctx context.Context, id string, prior *PullStatus, state, stage, message string) error {
	if prior.State == state && prior.Stage == stage && prior.Error == message {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	terminal := state == "succeeded" || state == "failed" || state == "rolled_back"
	result, err := tx.ExecContext(ctx, "UPDATE migration_pulls SET state=?,stage=?,last_error=?,continuation=CASE WHEN ? THEN NULL ELSE continuation END WHERE plan_id=? AND state=? AND stage=?", state, stage, message, terminal, id, prior.State, prior.Stage)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fault.Conflict("迁入进度已变化，停止覆盖原记录")
	}
	if err := pushAudit(ctx, tx, "system:migration", id, id, "migration.pull."+stage, state); err != nil {
		return err
	}
	return tx.Commit()
}
