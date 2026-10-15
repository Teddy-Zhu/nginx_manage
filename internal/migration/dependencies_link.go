package migration

import (
	"context"
	"database/sql"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
)

func (s *Service) dependencyLink(ctx context.Context, id, stage string, version int64) func(*sql.Tx, components.Task) error {
	return func(tx *sql.Tx, t components.Task) error {
		query := `UPDATE migration_dependencies SET check_task_id=? WHERE plan_id=? AND deadline>?
 AND (check_task_id='' OR check_task_id=?) AND EXISTS(SELECT 1 FROM migration_plans WHERE id=plan_id AND state='planned')
 AND (SELECT version FROM config_head WHERE id=1)=?`
		if stage == "prepare" {
			query = `UPDATE migration_dependencies SET prepare_task_id=? WHERE plan_id=? AND deadline>?
 AND (prepare_task_id='' OR prepare_task_id=?) AND EXISTS(SELECT 1 FROM migration_plans WHERE id=plan_id AND state='planned')
 AND (SELECT version FROM config_head WHERE id=1)=?`
		}
		result, err := tx.ExecContext(ctx, query, t.ID, id, time.Now().Unix(), t.ID, version)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fault.Conflict("迁移准备授权、目标版本或子任务关联已变化")
		}
		return nil
	}
}
