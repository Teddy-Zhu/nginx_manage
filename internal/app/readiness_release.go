package app

import (
	"context"
	"database/sql"
	"os"

	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
)

func readinessReleaseStatus(ctx context.Context, o Options, release panelruntime.Release, db *sql.DB, restoreID, maintenanceID string) (out panelready.ReleaseStatus, err error) {
	out = panelready.ReleaseStatus{Protocol: panelready.Protocol, PID: os.Getpid(), Version: o.Version, Mode: o.PanelRuntime, ReleaseID: release.ID, RestoreID: restoreID, MaintenanceID: maintenanceID}
	// One read transaction proves the same live database has both completed
	// restoration and its original maintenance/task release durably committed.
	err = db.QueryRowContext(ctx, `SELECT s.value,m.updated_at FROM settings s JOIN restore_barriers b ON b.target_node_id=s.value JOIN maintenance_sessions m ON m.task_id=? JOIN tasks t ON t.id=m.task_id
 WHERE s.key='node_id' AND b.id=? AND b.state='completed' AND m.phase='released' AND m.root_requested=1 AND t.kind='maintenance.enter' AND t.state='succeeded' AND t.stage='released'`, maintenanceID, restoreID).Scan(&out.NodeID, &out.ReleasedAt)
	if err != nil {
		return out, err
	}
	return out, out.Validate()
}
