package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/secure"
)

const terminalTasks = "('succeeded','failed','rolled_back','cancelled')"

// Completed task and deployment metadata remain useful after their material is
// retired. Live tasks, renewal state, migration compensation and challenge
// cleanup still need the original bytes and therefore pin their references.
const revisionCandidates = `SELECT r.id,'',r.version,r.created_at,
 COALESCE((SELECT SUM(length(content)) FROM nginx_config_files WHERE revision_id=r.id),0)+
 COALESCE((SELECT SUM(length(projection)) FROM nginx_resource_bindings WHERE revision_id=r.id),0)
 FROM config_revisions r CROSS JOIN config_head h
 WHERE h.id=1 AND r.pruned_at=0 AND r.created_at<?
 AND r.id NOT IN (SELECT id FROM config_revisions WHERE pruned_at=0 ORDER BY version DESC LIMIT ?)
 AND r.id<>COALESCE(h.desired_revision,'') AND r.id<>COALESCE(h.applied_revision,'')
 AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.state NOT IN ` + terminalTasks + ` AND (t.revision_id=r.id OR t.expected_revision=r.id OR t.observed_revision=r.id))
 AND NOT EXISTS(SELECT 1 FROM certificate_deployments d JOIN tasks t ON t.id=d.task_id WHERE t.state NOT IN ` + terminalTasks + ` AND (d.basis_revision=r.id OR d.revision_id=r.id))
 AND NOT EXISTS(SELECT 1 FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.http01_revision=r.id AND (o.http01_state NOT IN('none','cleaned') OR t.state NOT IN ` + terminalTasks + `))
 AND NOT EXISTS(SELECT 1 FROM migration_plans m WHERE m.state IN('planned','applying','recovery_required') AND (m.basis_revision=r.id OR m.basis_applied=r.id OR m.revision_id=r.id))
 ORDER BY r.created_at,r.version LIMIT 101`

const certificateCandidates = `SELECT v.id,v.certificate_id,v.ordinal,v.created_at,length(v.fullchain)+length(v.private_key)
 FROM certificate_versions v JOIN certificates c ON c.id=v.certificate_id
 WHERE v.pruned_at=0 AND v.created_at<? AND v.id<>c.latest_version_id
 AND v.id NOT IN(SELECT id FROM certificate_versions WHERE certificate_id=v.certificate_id AND pruned_at=0 ORDER BY ordinal DESC LIMIT ?)
 AND NOT EXISTS(SELECT 1 FROM nginx_certificate_references r WHERE r.version_id=v.id AND r.revision_id NOT IN(SELECT value FROM json_each(?)))
 AND NOT EXISTS(SELECT 1 FROM acme_renewals n WHERE n.version_id=v.id)
 AND NOT EXISTS(SELECT 1 FROM acme_orders o JOIN tasks t ON t.id=o.task_id WHERE o.certificate_version_id=v.id AND (t.state NOT IN ` + terminalTasks + ` OR (o.terminal=0 AND o.submit_started=1) OR o.http01_state NOT IN('none','cleaned') OR EXISTS(SELECT 1 FROM acme_dns_locks l WHERE l.order_id=o.id) OR EXISTS(SELECT 1 FROM acme_dns_records d WHERE d.order_id=o.id AND d.state<>'cleaned')))
 AND NOT EXISTS(SELECT 1 FROM certificate_deployments d JOIN tasks t ON t.id=d.task_id WHERE d.version_id=v.id AND t.state NOT IN ` + terminalTasks + `)
 ORDER BY v.created_at,v.certificate_id,v.ordinal LIMIT 101`

const orderCandidates = `SELECT o.id,o.profile_id,0,o.created_at,length(o.credentials)+length(o.private_key)+length(o.csr)+
 COALESCE((SELECT SUM(length(payload)) FROM acme_dns_records WHERE order_id=o.id),0)
 FROM acme_orders o JOIN tasks t ON t.id=o.task_id
 WHERE o.pruned_at=0 AND o.created_at<? AND t.state IN ` + terminalTasks + `
 AND (o.terminal=1 OR (o.submit_started=0 AND o.order_url=''))
 AND o.http01_state IN('none','cleaned')
 AND NOT EXISTS(SELECT 1 FROM acme_profiles p WHERE p.current_order_id=o.id)
 AND o.id NOT IN(SELECT id FROM acme_orders WHERE profile_id=o.profile_id AND pruned_at=0 ORDER BY created_at DESC,id DESC LIMIT ?)
 AND NOT EXISTS(SELECT 1 FROM acme_dns_locks l WHERE l.order_id=o.id)
 AND NOT EXISTS(SELECT 1 FROM acme_dns_records d WHERE d.order_id=o.id AND d.state<>'cleaned')
 ORDER BY o.created_at,o.id LIMIT 101`

// A retired plan remains a receipt for remote senders. Its payload may go only
// after every local coordinator, child operation and maintenance has settled.
const migrationCandidates = `SELECT m.id,'',0,m.created_at,length(m.payload)+
 COALESCE((SELECT SUM(length(payload)) FROM migration_dependencies WHERE plan_id=m.id),0)
 FROM migration_plans m
 WHERE m.pruned_at=0 AND m.updated_at<?
 AND (m.state IN('draft','saved','succeeded','failed','rolled_back') OR (m.state='planned' AND m.expires_at<?))
 AND m.id NOT IN(SELECT id FROM migration_plans WHERE principal=m.principal AND pruned_at=0 ORDER BY created_at DESC,id DESC LIMIT ?)
 AND (m.principal=? OR ?)
 AND (m.task_id='' OR EXISTS(SELECT 1 FROM tasks t WHERE t.id=m.task_id AND t.state IN ` + terminalTasks + `))
 AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=m.id AND t.state NOT IN ` + terminalTasks + `)
 AND NOT EXISTS(SELECT 1 FROM migration_pulls p WHERE p.plan_id=m.id AND (p.continuation IS NOT NULL OR p.state NOT IN('','succeeded','failed','rolled_back','cancelled')))
 AND NOT EXISTS(SELECT 1 FROM migration_dependencies d WHERE d.plan_id=m.id AND (
 NOT EXISTS(SELECT 1 FROM tasks t WHERE t.id=d.task_id AND t.state IN ` + terminalTasks + `)
 OR (d.check_task_id<>'' AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.id=d.check_task_id AND t.state IN ` + terminalTasks + `))
 OR (d.prepare_task_id<>'' AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.id=d.prepare_task_id AND t.state IN ` + terminalTasks + `))
 OR (d.install_task_id<>'' AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.id=d.install_task_id AND t.state IN ` + terminalTasks + `))
 OR (d.maintenance_task_id<>'' AND NOT EXISTS(SELECT 1 FROM maintenance_sessions s JOIN tasks t ON t.id=s.task_id WHERE s.task_id=d.maintenance_task_id AND s.phase IN('released','failed') AND t.state IN ` + terminalTasks + `))))
 ORDER BY m.updated_at,m.id LIMIT 101`

// BackupCandidatesSQL is shared by manual and capacity-triggered archival.
// Files must already be deleted, with no unsettled task/lease or live ticket.
// The receipt itself remains intact, including its original authorization.
const BackupCandidatesSQL = `SELECT b.task_id,'',0,t.created_at,0
 FROM backup_records b JOIN tasks t ON t.id=b.task_id
 WHERE b.archived_at=0 AND b.deleted_at IS NOT NULL AND b.deleted_at<? AND b.delete_started=0
 AND t.state IN('succeeded','failed','rolled_back','cancelled')
 AND (b.principal=? OR ?)
 AND b.task_id NOT IN(SELECT b2.task_id FROM backup_records b2 JOIN tasks t2 ON t2.id=b2.task_id WHERE b2.archived_at=0 AND (b2.principal=? OR ?) ORDER BY t2.created_at DESC,t2.id DESC LIMIT ?)
 AND (b.maintenance_id IS NULL OR EXISTS(SELECT 1 FROM maintenance_sessions s JOIN tasks m ON m.id=s.task_id WHERE s.task_id=b.maintenance_id AND s.phase IN('released','failed') AND m.state IN('succeeded','failed','rolled_back','cancelled')))
 AND NOT EXISTS(SELECT 1 FROM backup_downloads d WHERE d.task_id=b.task_id AND d.used_at IS NULL AND d.expires_at>?)
 ORDER BY b.deleted_at,b.task_id LIMIT 101`

func collect(ctx context.Context, tx *sql.Tx, node string, f Filter, owner auth.Principal) (Preview, error) {
	p := Preview{NodeID: node, Filter: f, Items: []Item{}, Scopes: []Scope{}}
	if err := tx.QueryRowContext(ctx, "SELECT version FROM config_head WHERE id=1").Scan(&p.BaseVersion); err != nil {
		return p, err
	}
	revisions := []string{}
	for _, q := range []struct {
		kind, sql, count string
		args, countArgs  []any
	}{
		{"revision", revisionCandidates, "SELECT COUNT(*) FROM config_revisions WHERE pruned_at=0", []any{f.Before, f.RevisionKeep}, nil},
		{"certificate", certificateCandidates, "SELECT COUNT(*) FROM certificate_versions WHERE pruned_at=0", nil, nil},
		{"order", orderCandidates, "SELECT COUNT(*) FROM acme_orders WHERE pruned_at=0", []any{f.Before, f.OrderKeep}, nil},
		{"migration", migrationCandidates, "SELECT COUNT(*) FROM migration_plans WHERE pruned_at=0 AND (principal=? OR ?)", []any{f.Before, f.Before, f.MigrationKeep, owner.ID, owner.Has("auth.manage")}, []any{owner.ID, owner.Has("auth.manage")}},
		{"maintenance", maintenance.ArchiveCandidatesSQL, "SELECT COUNT(*) FROM maintenance_sessions WHERE archived_at=0", []any{f.Before, f.MaintenanceKeep}, nil},
		{"backup", BackupCandidatesSQL, "SELECT COUNT(*) FROM backup_records WHERE archived_at=0 AND (principal=? OR ?)", []any{f.Before, owner.ID, owner.Has("auth.manage"), owner.ID, owner.Has("auth.manage"), f.BackupKeep, time.Now().Unix()}, []any{owner.ID, owner.Has("auth.manage")}},
	} {
		if q.kind == "migration" && f.MigrationKeep == 0 {
			continue
		}
		if q.kind == "maintenance" && f.MaintenanceKeep == 0 {
			continue
		}
		if q.kind == "backup" && f.BackupKeep == 0 {
			continue
		}
		args := q.args
		if q.kind == "certificate" {
			raw, _ := json.Marshal(revisions)
			args = []any{f.Before, f.CertificateKeep, string(raw)}
		}
		scope := Scope{Kind: q.kind}
		if err := tx.QueryRowContext(ctx, q.count, q.countArgs...).Scan(&scope.Retained); err != nil {
			return p, err
		}
		rows, err := tx.QueryContext(ctx, q.sql, args...)
		if err != nil {
			return p, err
		}
		for rows.Next() {
			item := Item{Kind: q.kind}
			if err = rows.Scan(&item.ID, &item.ResourceID, &item.Version, &item.CreatedAt, &item.Bytes); err != nil {
				break
			}
			if scope.Selected == 100 {
				scope.More = true
				break
			}
			p.Items = append(p.Items, item)
			scope.Selected++
			scope.Bytes += item.Bytes
			if q.kind == "revision" {
				revisions = append(revisions, item.ID)
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return p, err
		}
		scope.Retained -= int64(scope.Selected)
		p.Scopes = append(p.Scopes, scope)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	p.SHA256 = secure.Hash(raw)
	return p, nil
}
