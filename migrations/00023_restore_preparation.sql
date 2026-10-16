-- +goose Up
CREATE TABLE restore_barriers (
 id TEXT PRIMARY KEY,
 mode TEXT NOT NULL CHECK(mode IN('clone','disaster')),
 source_node_id TEXT NOT NULL, target_node_id TEXT NOT NULL,
 archive_sha256 TEXT NOT NULL, prepared_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('prepared','reconciling','completed')),
 report TEXT NOT NULL CHECK(json_valid(report) AND length(report)<=131072)
);
CREATE UNIQUE INDEX restore_barrier_active ON restore_barriers((1)) WHERE state<>'completed';
CREATE TABLE restore_quarantined_tasks (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 restore_id TEXT NOT NULL REFERENCES restore_barriers(id),
 original_state TEXT NOT NULL, original_stage TEXT NOT NULL,
 original_error TEXT NOT NULL, isolated_at INTEGER NOT NULL
);

-- +goose StatementBegin
DROP TRIGGER notification_task_failure;
CREATE TRIGGER notification_task_failure AFTER UPDATE OF state ON tasks
WHEN NEW.state IN ('failed','rolled_back','recovery_required') AND OLD.state!=NEW.state
 AND NOT EXISTS(SELECT 1 FROM restore_barriers WHERE state<>'completed')
BEGIN
 INSERT INTO notification_events(id,dedup_key,kind,resource_kind,resource_id,severity,state,summary,created_at,last_seen_at,expires_at)
 SELECT 'task.'||NEW.id||'.'||NEW.state||'.'||(CAST(strftime('%s','now') AS INTEGER)/3600),
 'task:'||category||':'||substr(NEW.resource_id,1,128)||':'||(CAST(strftime('%s','now') AS INTEGER)/3600),
 category,substr(NEW.kind,1,48),substr(NEW.resource_id,1,128),CASE WHEN NEW.state='recovery_required' THEN 'critical' ELSE 'error' END,'firing',
 CASE category WHEN 'recovery.required' THEN '任务需要人工恢复' WHEN 'certificate.failure' THEN '证书申请或续期失败' WHEN 'configuration.failure' THEN '配置校验、应用或恢复失败' WHEN 'backup.failure' THEN '备份或迁移任务失败' WHEN 'update.failure' THEN '更新任务失败' ELSE '任务执行失败' END,
 CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER)+86400
 FROM (SELECT CASE WHEN NEW.state='recovery_required' THEN 'recovery.required' WHEN NEW.kind LIKE 'nginx.%' THEN 'configuration.failure' WHEN NEW.kind LIKE 'acme.%' THEN 'certificate.failure' WHEN NEW.kind LIKE 'backup.%' OR NEW.kind LIKE 'migration.%' THEN 'backup.failure' WHEN NEW.kind LIKE 'update.%' THEN 'update.failure' ELSE 'task.failure' END AS category)
 WHERE true
 ON CONFLICT(dedup_key) DO UPDATE SET occurrences=occurrences+1,last_seen_at=excluded.last_seen_at;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER notification_task_failure;
CREATE TRIGGER notification_task_failure AFTER UPDATE OF state ON tasks
WHEN NEW.state IN ('failed','rolled_back','recovery_required') AND OLD.state!=NEW.state
BEGIN
 INSERT INTO notification_events(id,dedup_key,kind,resource_kind,resource_id,severity,state,summary,created_at,last_seen_at,expires_at)
 SELECT 'task.'||NEW.id||'.'||NEW.state||'.'||(CAST(strftime('%s','now') AS INTEGER)/3600),
 'task:'||category||':'||substr(NEW.resource_id,1,128)||':'||(CAST(strftime('%s','now') AS INTEGER)/3600),
 category,substr(NEW.kind,1,48),substr(NEW.resource_id,1,128),CASE WHEN NEW.state='recovery_required' THEN 'critical' ELSE 'error' END,'firing',
 CASE category WHEN 'recovery.required' THEN '任务需要人工恢复' WHEN 'certificate.failure' THEN '证书申请或续期失败' WHEN 'configuration.failure' THEN '配置校验、应用或恢复失败' WHEN 'backup.failure' THEN '备份或迁移任务失败' WHEN 'update.failure' THEN '更新任务失败' ELSE '任务执行失败' END,
 CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER)+86400
 FROM (SELECT CASE WHEN NEW.state='recovery_required' THEN 'recovery.required' WHEN NEW.kind LIKE 'nginx.%' THEN 'configuration.failure' WHEN NEW.kind LIKE 'acme.%' THEN 'certificate.failure' WHEN NEW.kind LIKE 'backup.%' OR NEW.kind LIKE 'migration.%' THEN 'backup.failure' WHEN NEW.kind LIKE 'update.%' THEN 'update.failure' ELSE 'task.failure' END AS category)
 WHERE true
 ON CONFLICT(dedup_key) DO UPDATE SET occurrences=occurrences+1,last_seen_at=excluded.last_seen_at;
END;
-- +goose StatementEnd

DROP TABLE restore_quarantined_tasks;
DROP INDEX restore_barrier_active;
DROP TABLE restore_barriers;
