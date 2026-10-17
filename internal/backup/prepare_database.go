package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type restoreAdmin struct {
	Username     string
	PasswordHash string
	Epoch        int64
	CreatedAt    int64
}

func readRestoreAdmin(ctx context.Context, db *sql.DB) (restoreAdmin, error) {
	var a restoreAdmin
	err := db.QueryRowContext(ctx, "SELECT username,password_hash,session_epoch,created_at FROM users WHERE id=1 AND typeof(username)='text' AND length(CAST(username AS BLOB))<=64 AND typeof(password_hash)='text' AND length(CAST(password_hash AS BLOB))<=512 AND typeof(session_epoch)='integer' AND typeof(created_at)='integer'").Scan(&a.Username, &a.PasswordHash, &a.Epoch, &a.CreatedAt)
	if err != nil {
		return a, err
	}
	if a.Username == "" || !utf8.ValidString(a.Username) || strings.ContainsAny(a.Username, "\x00\r\n") || a.PasswordHash == "" || a.Epoch < 1 || a.Epoch > 1<<62 || a.CreatedAt <= 0 {
		return a, errors.New("目标管理员身份无效，不能准备恢复材料")
	}
	return a, nil
}
func sanitizeRestore(ctx context.Context, path string, target *sql.DB, admin restoreAdmin, p *Preparation) (retErr error) {
	db, err := writableRestoreDatabase(ctx, path)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, db.Close()) }()
	if err = storage.VerifyCurrentSchema(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	counts := []struct {
		query string
		value *int64
	}{
		{"SELECT COUNT(*) FROM tasks WHERE state NOT IN('succeeded','failed','rolled_back','cancelled')", &p.Isolation.Tasks},
		{"SELECT COUNT(*) FROM sessions", &p.Isolation.Sessions},
		{"SELECT COUNT(*) FROM api_credentials WHERE revoked_at IS NULL", &p.Isolation.Credentials},
		{"SELECT COUNT(*) FROM nodes WHERE removed_at IS NULL", &p.Isolation.Connections},
		{"SELECT COUNT(*) FROM notification_deliveries WHERE state IN('pending','sending')", &p.Isolation.Deliveries},
		{"SELECT COUNT(*) FROM acme_dns_records WHERE state<>'cleaned'", &p.Isolation.DNSRecords},
		{"SELECT COUNT(*) FROM audit_logs", &p.Isolation.ImportedAudits},
	}
	for _, count := range counts {
		if err = tx.QueryRowContext(ctx, count.query).Scan(count.value); err != nil {
			return err
		}
	}
	var sourceEpoch int64
	if err = tx.QueryRowContext(ctx, "SELECT session_epoch FROM users WHERE id=1 AND typeof(session_epoch)='integer'").Scan(&sourceEpoch); err != nil {
		return err
	}
	if sourceEpoch < 1 || sourceEpoch >= 1<<62 || admin.Epoch >= 1<<62 {
		return errors.New("源或目标账户安全代次无效")
	}
	p.SessionEpoch = max(admin.Epoch, sourceEpoch) + 1
	modules, err := tx.QueryContext(ctx, "SELECT substr(id,1,129) FROM module_settings WHERE id<>'nginx-config' AND enabled=1 ORDER BY id LIMIT 65")
	if err != nil {
		return err
	}
	for modules.Next() {
		var id string
		if err = modules.Scan(&id); err != nil {
			break
		}
		if len(id) > 128 {
			err = errors.New("恢复模块标识超过限制")
			break
		}
		p.DisabledModules = append(p.DisabledModules, id)
	}
	err = errors.Join(err, modules.Err())
	modules.Close()
	if err != nil {
		return err
	}
	if len(p.DisabledModules) > 64 {
		return errors.New("恢复模块数量超过上限")
	}
	now := p.PreparedAt
	namespace := "restore:" + p.OperationID + ":"
	policy, err := json.Marshal(struct{ Mode, SourceNodeID, TargetNodeID, RestoredNodeID, ArchiveSHA256 string }{p.Mode, p.Source.Database.NodeID, p.Target.Database.NodeID, p.Database.NodeID, p.ArchiveSHA256})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO restore_barriers(id,mode,source_node_id,target_node_id,archive_sha256,prepared_at,state,report) VALUES(?,?,?,?,?,?,'prepared',?)", p.OperationID, p.Mode, p.Source.Database.NodeID, p.Database.NodeID, p.ArchiveSHA256, now, string(policy)); err != nil {
		return err
	}
	steps := []struct {
		sql  string
		args []any
	}{
		{"UPDATE event_log_status SET paused=1 WHERE id=1", nil},
		{"DELETE FROM sessions", nil},
		{"DELETE FROM settings WHERE key='bootstrap_hash'", nil},
		{"UPDATE users SET username=?,password_hash=?,session_epoch=?,created_at=? WHERE id=1", []any{admin.Username, admin.PasswordHash, p.SessionEpoch, admin.CreatedAt}},
		{"UPDATE settings SET value=? WHERE key='node_id'", []any{p.Database.NodeID}},
		{"UPDATE config_head SET applied_revision=NULL WHERE id=1", nil},
		{"UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?)", []any{now}},
		{"UPDATE module_settings SET enabled=CASE WHEN id='nginx-config' THEN 1 ELSE 0 END,version=version+1", nil},
		{"UPDATE backup_policy SET version=version+1,key_saved_at=0,principal='',issuer_machine=0,issuer_epoch=0,authorization_until=0,next_run_at=0,last_error='完整恢复后须重新确认离线公钥及备份授权',updated_at=? WHERE id=1", []any{now}},
		{"DELETE FROM backup_downloads", nil},
		{"UPDATE backup_records SET deleted_at=COALESCE(deleted_at,?),delete_started=0", []any{now}},
		{"UPDATE nodes SET token=NULL,capabilities=NULL,state='removed',removed_at=COALESCE(removed_at,?),revocation=CASE WHEN revocation='revoked' THEN revocation ELSE 'pending' END,last_error='源连接不继承；远端凭据须在原目标核对撤销',version=version+1,updated_at=?", []any{now, now}},
		{"UPDATE node_pairings SET state='revoked',token=NULL,revoked_at=COALESCE(revoked_at,?)", []any{now}},
		{"UPDATE node_pairing_jobs SET state='abandoned',stage='finished',material=NULL,revocation=CASE WHEN revocation='revoked' THEN revocation ELSE 'pending' END,last_error='源配对已隔离，远端领取结果须另行核对',updated_at=?", []any{now}},
		{"UPDATE notification_channels SET enabled=0,version=version+1,updated_at=?", []any{now}},
		{"UPDATE acme_profiles SET auto_renew=0,auto_deploy=0,deploy_after=0,deployment_observed_version='',version=version+1,updated_at=?", []any{now}},
		{"UPDATE acme_renewals SET paused=1,next_check_at=0,last_error='恢复后须核对 CA 订单与 DNS 所有权并重新授权自动化'", nil},
		{"UPDATE acme_dns_records SET state='blocked',last_error='源 DNS 挑战值需核对所有权与远端状态，禁止自动清理或重放' WHERE state<>'cleaned'", nil},
		{"DELETE FROM host_dns_plans", nil},
		{"DELETE FROM host_dns_desired", nil},
		{"UPDATE migration_plans SET expires_at=0,execution_principal='',execution_key='',execution_hash=''", nil},
		{"UPDATE migration_pushes SET expires_at=0,next_attempt_at=0", nil},
		{"UPDATE panel_updates SET cleanup_pending=0", nil},
		{"INSERT INTO restore_quarantined_tasks(task_id,restore_id,original_state,original_stage,original_error,isolated_at) SELECT id,?,state,stage,last_error,? FROM tasks WHERE state NOT IN('succeeded','failed','rolled_back','cancelled') ON CONFLICT(task_id) DO NOTHING", []any{p.OperationID, now}},
		{"UPDATE tasks SET state='recovery_required',stage='restore_isolated',last_error='来自完整备份的旧任务已隔离，须核对独立执行记录，禁止重放',lease_until=NULL,updated_at=? WHERE state NOT IN('succeeded','failed','rolled_back','cancelled')", []any{now}},
		{"UPDATE maintenance_sessions SET phase='failed',last_error='源维护会话不继承到恢复目标，执行结果保留待核对',updated_at=? WHERE phase NOT IN('released','failed')", []any{now}},
		{"UPDATE notification_deliveries SET state='cancelled',lease_until=0,completed_at=?,last_error='源通知投递已隔离，不在恢复目标重放' WHERE state IN('pending','sending')", []any{now}},
		{"UPDATE notification_events SET fanout_at=CASE WHEN fanout_at=0 THEN ? ELSE fanout_at END,expires_at=MIN(expires_at,?)", []any{now, now}},
		{"UPDATE notification_signals SET active=0", nil},
	}
	for _, step := range steps {
		if _, err = tx.ExecContext(ctx, step.sql, step.args...); err != nil {
			return err
		}
	}
	// Inactive request receipts remain available for audit, but cannot satisfy a
	// new administrator request that happens to reuse an old idempotency key.
	for _, table := range []string{"idempotency_keys", "backup_requests", "migration_pulls", "node_requests", "node_pairings", "node_pairing_jobs"} {
		if _, err = tx.ExecContext(ctx, "UPDATE "+table+" SET principal=?||principal", namespace); err != nil {
			return err
		}
	}
	if err = mergeTargetAudits(ctx, target, tx, &p.Isolation); err != nil {
		return err
	}
	if err = audit(ctx, tx, "restore-preparation", p.OperationID, p.OperationID, "backup.restore.prepare", "isolated"); err != nil {
		return err
	}
	// Old event deliveries belong to the source writer, never the restore target.
	if _, err = tx.ExecContext(ctx, "DELETE FROM event_log_queue"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE event_log_status SET dropped=0,paused=0 WHERE id=1"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE settings SET value=lower(hex(randomblob(16))) WHERE key='event_log_epoch'"); err != nil {
		return err
	}
	summary, err := json.Marshal(struct {
		Isolation RestoreIsolation `json:"isolation"`
		Disabled  []string         `json:"disabled_modules"`
		Pending   []string         `json:"pending_checks"`
	}{p.Isolation, p.DisabledModules, p.PendingChecks})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE restore_barriers SET report=? WHERE id=?", string(summary), p.OperationID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	meta, err := databaseMetadata(ctx, db)
	if err != nil {
		return err
	}
	if meta != p.Database {
		return errors.New("隔离后的恢复数据库与批准身份不一致")
	}
	return nil
}

type restoreAudit struct {
	ID, RequestID, Principal, Action, ResourceID, Outcome string
	CreatedAt                                             int64
}

func mergeTargetAudits(ctx context.Context, target *sql.DB, tx *sql.Tx, out *RestoreIsolation) error {
	for _, db := range []auditQueryer{target, tx} {
		if err := validateRestoreAudits(ctx, db); err != nil {
			return err
		}
	}
	rows, err := target.QueryContext(ctx, "SELECT id,request_id,principal,action,resource_id,outcome,created_at FROM audit_logs ORDER BY created_at,id")
	if err != nil {
		return err
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var a restoreAudit
		if err = rows.Scan(&a.ID, &a.RequestID, &a.Principal, &a.Action, &a.ResourceID, &a.Outcome, &a.CreatedAt); err != nil {
			return err
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		total += int64(len(raw))
		if len(raw) > 64<<10 || total > AuditMergeMax {
			return errors.New("目标审计超过恢复合并容量，须先进行受控归档；未删除任何审计")
		}
		out.TargetAudits++
		var prior restoreAudit
		err = tx.QueryRowContext(ctx, "SELECT id,request_id,principal,action,resource_id,outcome,created_at FROM audit_logs WHERE id=?", a.ID).Scan(&prior.ID, &prior.RequestID, &prior.Principal, &prior.Action, &prior.ResourceID, &prior.Outcome, &prior.CreatedAt)
		if err == nil {
			if prior != a {
				return errors.New("源与目标审计存在同标识不同内容，拒绝覆盖")
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", a.ID, a.RequestID, a.Principal, a.Action, a.ResourceID, a.Outcome, a.CreatedAt); err != nil {
			return err
		}
		out.AddedTargetAudits++
	}
	return rows.Err()
}

type auditQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateRestoreAudits(ctx context.Context, db auditQueryer) error {
	var invalid bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE
 typeof(id)<>'text' OR length(CAST(id AS BLOB))>65536 OR
 typeof(request_id)<>'text' OR length(CAST(request_id AS BLOB))>65536 OR
 typeof(principal)<>'text' OR length(CAST(principal AS BLOB))>65536 OR
 typeof(action)<>'text' OR length(CAST(action AS BLOB))>65536 OR
 typeof(resource_id)<>'text' OR length(CAST(resource_id AS BLOB))>65536 OR
 typeof(outcome)<>'text' OR length(CAST(outcome AS BLOB))>65536 OR
 typeof(created_at)<>'integer')`).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return errors.New("恢复审计字段类型或容量无效，拒绝合并")
	}
	return nil
}
