package backup

import (
	"context"
	"database/sql"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
)

func (s *Service) archiveHistoryAtCapacity(ctx context.Context, tx *sql.Tx, actor, trace string) error {
	now := time.Now().Unix()
	rows, err := tx.QueryContext(ctx, history.BackupCandidatesSQL, now+1, "", true, "", true, 128, now)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, resource string
		var version, created, size int64
		if err = rows.Scan(&id, &resource, &version, &created, &size); err != nil {
			break
		}
		if len(ids) == 100 {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, id := range ids {
		result, err := tx.ExecContext(ctx, "UPDATE backup_records SET archived_at=? WHERE task_id=? AND archived_at=0 AND deleted_at IS NOT NULL AND delete_started=0", now, id)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return fault.Conflict("备份历史已变化，不能归档原记录")
		}
		if err = audit(ctx, tx, actor, trace, id, "backup.history.archive", "succeeded"); err != nil {
			return err
		}
	}
	return nil
}
