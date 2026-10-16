package migration

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/secure"
)

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.reconcile(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		if err := s.nextDependencies(ctx); err != nil && ctx.Err() == nil {
			return err
		}
		if err := s.nextPush(ctx); err != nil && !errors.Is(err, errPushChanged) && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (s *Service) reconcile(ctx context.Context) error {
	done, ok := s.Maintenance.Progress()
	if !ok {
		return nil
	}
	defer done()
	var id, principal, basis, taskID, revision, basisApplied string
	err := s.DB.QueryRowContext(ctx, "SELECT id,principal,basis_revision,task_id,revision_id,basis_applied FROM migration_plans WHERE state IN ('applying','recovery_required') ORDER BY created_at LIMIT 1").Scan(&id, &principal, &basis, &taskID, &revision, &basisApplied)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var state string
	if err := s.DB.QueryRowContext(ctx, "SELECT state FROM tasks WHERE id=?", taskID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s.requireRecovery(ctx, id, "迁移应用任务记录缺失，停止重复提交并保留恢复材料")
		}
		return err
	}
	if state != "succeeded" && state != "failed" && state != "rolled_back" && state != "recovery_required" && state != "cancelled" {
		return nil
	}
	if state == "recovery_required" {
		return s.requireRecovery(ctx, id, "Nginx 执行结果需要恢复，迁移停止后续操作")
	}
	if state != "succeeded" {
		confirmed := false
		if s.Agent != nil {
			runtime, e := s.Agent.NginxState(ctx)
			confirmed = e == nil && runtime.Available && runtime.Running && runtime.Integrity && !runtime.ExternalChange && runtime.RevisionID == basisApplied
		}
		if !confirmed {
			return s.requireRecovery(ctx, id, "无法确认原运行配置已恢复，保留迁移记录等待恢复")
		}
	}
	st, err := s.load(ctx, auth.Principal{ID: principal}, id)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM migration_plans WHERE id=?", id).Scan(&current); err != nil {
		return err
	}
	if current != "applying" && current != "recovery_required" {
		return nil
	}
	message := ""
	outcome := "succeeded"
	if state != "succeeded" {
		if _, err := tx.ExecContext(ctx, "SAVEPOINT migration_compensation"); err != nil {
			return err
		}
		compensateErr := s.Config.CompensateImport(ctx, tx, revision, basis, principal, id)
		if compensateErr == nil {
			compensateErr = s.compensateFirewall(ctx, tx, &st, principal, id)
		}
		if compensateErr == nil && st.EnabledByMigration {
			var n int64
			result, e := tx.ExecContext(ctx, "UPDATE module_settings SET enabled=0,version=version+1 WHERE id='nginx-config' AND enabled=1 AND version=?", st.ModuleVersion+1)
			if e != nil {
				compensateErr = e
			} else {
				n, e = result.RowsAffected()
				if e != nil {
					compensateErr = e
				} else if n != 1 {
					compensateErr = errors.New("module changed")
				}
			}
		}
		if compensateErr != nil {
			if _, err := tx.ExecContext(ctx, "ROLLBACK TO migration_compensation"); err != nil {
				return err
			}
			outcome = "recovery_required"
			message = "运行恢复后无法恢复期望修订、防火墙期望策略或模块状态，保留迁移记录和依赖供本机恢复"
		} else {
			outcome = "rolled_back"
			message = "运行配置、期望配置及本次迁入的防火墙期望策略已恢复；导入的不可变修订、证书和凭据保留供审计与重试"
		}
	}
	if err := recordOutcome(ctx, tx, id, outcome, message); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) requireRecovery(ctx context.Context, id, message string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := recordOutcome(ctx, tx, id, "recovery_required", message); err != nil {
		return err
	}
	return tx.Commit()
}
func recordOutcome(ctx context.Context, tx *sql.Tx, id, state, message string) error {
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, "UPDATE migration_plans SET state=?,last_error=?,updated_at=? WHERE id=? AND (state!=? OR last_error!=?)", state, message, now, id, state, message)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,'system:migration','migration.complete',?,?,?)", secure.ID(), id, id, state, now)
	return err
}
