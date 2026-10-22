package maintenance

import (
	"context"
	"database/sql"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

const archiveTerminalTasks = "('succeeded','failed','rolled_back','cancelled')"

// Keep the session itself as a compact receipt: completed children and replayed
// requests continue to resolve the original UUID and final phase after archival.
const ArchiveCandidatesSQL = `SELECT s.task_id,'',0,s.created_at,0
 FROM maintenance_sessions s JOIN tasks t ON t.id=s.task_id
 WHERE s.archived_at=0 AND s.updated_at<? AND s.phase IN('released','failed')
 AND t.state IN ` + archiveTerminalTasks + `
 AND s.task_id NOT IN(SELECT task_id FROM maintenance_sessions WHERE archived_at=0 ORDER BY updated_at DESC,task_id DESC LIMIT ?)
 AND (s.owner_task_id IS NULL OR EXISTS(SELECT 1 FROM tasks p WHERE p.id=s.owner_task_id AND p.state IN ` + archiveTerminalTasks + `))
 AND NOT EXISTS(SELECT 1 FROM backup_records b JOIN tasks t ON t.id=b.task_id WHERE b.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM nginx_installations i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM nginx_switches i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM panel_updates i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM agent_upgrades i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM panel_image_upgrades i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM migration_dependencies d JOIN tasks t ON t.id=d.task_id WHERE d.maintenance_task_id=s.task_id AND t.state NOT IN ` + archiveTerminalTasks + `)
 ORDER BY s.updated_at,s.task_id LIMIT 101`

// At capacity, archive settled receipts before accepting another maintenance.
// Rows, task references and idempotency responses stay in the same database;
// archival never substitutes for finishing a child or reconciling root state.
func archiveAtCapacity(ctx context.Context, tx *sql.Tx, p auth.Principal, requestID string) error {
	rows, err := tx.QueryContext(ctx, ArchiveCandidatesSQL, time.Now().Unix()+1, 32)
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
		result, updateErr := tx.ExecContext(ctx, "UPDATE maintenance_sessions SET archived_at=? WHERE task_id=? AND archived_at=0 AND phase IN('released','failed')", time.Now().Unix(), id)
		if updateErr != nil {
			return updateErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil {
			return countErr
		}
		if count != 1 {
			return fault.Conflict("维护会话已变化，不能归档原记录")
		}
		if err = audit(ctx, tx, p, requestID, id, "maintenance.archive", "succeeded"); err != nil {
			return err
		}
	}
	return nil
}
