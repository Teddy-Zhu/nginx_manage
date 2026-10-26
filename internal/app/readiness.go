package app

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
)

func readinessStatus(ctx context.Context, o Options, release panelruntime.Release, db *sql.DB, m *maintenance.Service, a *agent.Client) (panelready.Status, error) {
	out := panelready.Status{Protocol: panelready.Protocol, PID: os.Getpid(), Version: o.Version, Mode: o.PanelRuntime, ReleaseID: release.ID}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT MAX(version_id) FROM goose_db_version").Scan(&out.DatabaseSchema); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='node_id'").Scan(&out.NodeID); err != nil {
		return out, err
	}
	c := &out.Configuration
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(desired_revision,''),COALESCE(applied_revision,''),version FROM config_head WHERE id=1").Scan(&c.DesiredRevision, &c.AppliedRevision, &c.HeadVersion); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	view := m.View()
	root, err := a.MaintenanceStatus(ctx)
	if err != nil {
		return out, err
	}
	if view.Session == nil || !root.Available || root.Epoch != view.Session.RootEpoch || out.DatabaseSchema != release.DatabaseSchema {
		return out, errors.New("数据库或独立维护身份尚未就绪")
	}
	out.Maintenance = panelready.Maintenance{ID: view.Session.TaskID, Phase: view.Phase, RootID: root.ID, RootPhase: root.Phase, Epoch: root.Epoch, Busy: root.Busy, Active: view.Active}
	if err = out.Validate(); err != nil {
		return out, err
	}
	runtime, err := a.NginxState(ctx)
	if err != nil {
		return out, err
	}
	c.Available, c.RevisionID, c.DeploymentID, c.Integrity, c.Running, c.ExternalChange = runtime.Available, runtime.RevisionID, runtime.DeploymentID, runtime.Integrity, runtime.Running, runtime.ExternalChange
	if c.AppliedRevision != "" && (!c.Available || !c.Integrity || !c.Running || c.ExternalChange || c.RevisionID != c.AppliedRevision) {
		return out, errors.New("原应用配置运行状态尚未确认")
	}
	return out, out.Validate()
}

func healthyStatus(ctx context.Context, o Options, release panelruntime.Release, db *sql.DB) (panelready.Status, error) {
	out := panelready.Status{Protocol: panelready.Protocol, PID: os.Getpid(), Version: o.Version, Mode: o.PanelRuntime, ReleaseID: release.ID}
	err := db.QueryRowContext(ctx, "SELECT (SELECT MAX(version_id) FROM goose_db_version),(SELECT value FROM settings WHERE key='node_id')").Scan(&out.DatabaseSchema, &out.NodeID)
	if err == nil && out.DatabaseSchema != release.DatabaseSchema {
		err = errors.New("数据库迁移尚未完成")
	}
	return out, err
}
