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
	err := s.DB.QueryRowContext(ctx, `SELECT t.id,t.state,t.stage,d.check_task_id,d.prepare_task_id,t.last_error,d.deadline
 FROM migration_dependencies d JOIN tasks t ON t.id=d.task_id WHERE d.plan_id=?`, id).Scan(&d.TaskID, &d.State, &d.Stage, &d.CheckTaskID, &d.PrepareTaskID, &d.Error, &d.Deadline)
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
	if s.Components == nil {
		return Plan{}, fault.Unavailable("组件服务未配置")
	}
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移正在处理")
	}
	defer s.mu.Unlock()
	plan, err := s.Get(ctx, p, id)
	if err != nil {
		return Plan{}, err
	}
	raw, err := json.Marshal(struct {
		Action, ID string
		Input      DependencyInput
	}{"migration.dependencies", id, in})
	if err != nil {
		return Plan{}, err
	}
	hash := secure.Hash(raw)
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
