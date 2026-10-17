package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) dependencyStatus(ctx context.Context, id string) (*DependencyStatus, error) {
	var d DependencyStatus
	err := s.DB.QueryRowContext(ctx, `SELECT t.id,t.state,t.stage,d.check_task_id,d.prepare_task_id,t.last_error,d.deadline,
 d.maintenance_task_id,d.install_task_id,d.settlement_state,d.settlement_stage,d.settlement_error
 FROM migration_dependencies d JOIN tasks t ON t.id=d.task_id WHERE d.plan_id=?`, id).Scan(&d.TaskID, &d.State, &d.Stage, &d.CheckTaskID, &d.PrepareTaskID, &d.Error, &d.Deadline, &d.MaintenanceTaskID, &d.InstallTaskID, &d.SettlementState, &d.SettlementStage, &d.SettlementError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}
func (s *Service) migrationBlocked(ctx context.Context, message string, plan Plan) error {
	d, err := s.dependencyStatus(ctx, plan.ID)
	if err != nil {
		return err
	}
	plan.Dependencies = d
	return blockedPlan(message, plan)
}

func (s *Service) PrepareDependencies(ctx context.Context, p auth.Principal, requestID, key, id string, in DependencyInput) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write", "components.manage"); err != nil {
		return Plan{}, err
	}
	if !validTransferID(id) || !validPushKey(key) {
		return Plan{}, fault.Invalid("迁移标识或幂等键无效")
	}
	if err := in.validate(); err != nil {
		return Plan{}, err
	}
	if in.Install != nil {
		if err := p.Require("system.write"); err != nil {
			return Plan{}, err
		}
		if s.Installations == nil || s.Maintenance == nil {
			return Plan{}, fault.Unavailable("首次安装协调服务未配置")
		}
	}
	if s.Components == nil {
		return Plan{}, fault.Unavailable("组件服务未配置")
	}
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移正在处理")
	}
	defer s.mu.Unlock()
	return s.prepareDependencies(ctx, p, requestID, key, id, in)
}

// The caller holds the migration coordinator lock and has checked the grant.
func (s *Service) prepareDependencies(ctx context.Context, p auth.Principal, requestID, key, id string, in DependencyInput) (Plan, error) {
	if err := s.admitPullDependencies(ctx, p, id, in); err != nil {
		return Plan{}, err
	}
	plan, err := s.Get(ctx, p, id)
	if err != nil {
		return Plan{}, err
	}
	hash, err := dependencyDigest(id, in)
	if err != nil {
		return Plan{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, err
	}
	defer tx.Rollback()
	var prior string
	err = tx.QueryRowContext(ctx, "SELECT request_hash FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior)
	if err == nil {
		if prior != hash {
			return Plan{}, fault.Conflict("同一幂等键不能用于不同请求")
		}
		return plan, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Plan{}, err
	}
	if plan.PrunedAt > 0 {
		return Plan{}, fault.New(410, "HISTORY_PRUNED", "迁移计划载荷已清理，不能创建新的依赖准备授权")
	}
	var owner string
	err = tx.QueryRowContext(ctx, "SELECT principal,request_hash FROM migration_dependencies WHERE plan_id=?", id).Scan(&owner, &prior)
	if err == nil {
		if owner != p.ID && !p.Has("auth.manage") {
			return Plan{}, auth.ErrForbidden
		}
		if prior != hash {
			return Plan{}, fault.Conflict("原迁移已固定依赖准备选项，请核对原任务")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if plan.State != "planned" || plan.ExpiresAt <= time.Now().Unix() {
			return Plan{}, fault.Conflict("仅有效的待执行迁移可以准备依赖")
		}
		var active int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind='migration.dependencies' AND state IN ('queued','running','recovery_required')").Scan(&active); err != nil {
			return Plan{}, err
		}
		if active != 0 {
			return Plan{}, fault.Conflict("已有迁移依赖任务执行中或待恢复")
		}
		input, e := json.Marshal(in)
		if e != nil {
			return Plan{}, e
		}
		now := time.Now().Unix()
		taskID := secure.ID()
		if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'migration.dependencies',?,'queued','checking',?,?,?)", taskID, id, taskID, now, now); err != nil {
			return Plan{}, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO migration_dependencies(plan_id,task_id,principal,request_hash,payload,deadline) VALUES(?,?,?,?,?,?)", id, taskID, p.ID, hash, s.Vault.Seal(input, "migration-dependencies:"+id), min(plan.ExpiresAt, now+1800)); err != nil {
			return Plan{}, err
		}
		if err = pushAudit(ctx, tx, p.ID, requestID, id, "migration.dependencies", "queued"); err != nil {
			return Plan{}, err
		}
	} else {
		return Plan{}, err
	}
	ref, err := json.Marshal(struct {
		PlanID string `json:"plan_id"`
	}{id})
	if err != nil {
		return Plan{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, hash, s.Vault.Seal(ref, "idempotency:"+p.ID+":"+key), time.Now().Unix()); err != nil {
		return Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		return Plan{}, err
	}
	return s.Get(ctx, p, id)
}

func dependencyDigest(id string, in DependencyInput) (string, error) {
	raw, err := json.Marshal(struct {
		Action, ID string
		Input      DependencyInput
	}{"migration.dependencies", id, in})
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}
