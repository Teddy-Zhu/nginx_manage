-- +goose Up
CREATE TABLE notification_settings (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL DEFAULT 1, settings TEXT NOT NULL CHECK(length(settings)<=2048));
CREATE TABLE notification_health (id INTEGER PRIMARY KEY CHECK(id=1), evicted_events INTEGER NOT NULL DEFAULT 0, dropped_deliveries INTEGER NOT NULL DEFAULT 0);
INSERT INTO notification_health(id) VALUES(1);
CREATE TABLE notification_channels (
 id TEXT PRIMARY KEY, version INTEGER NOT NULL, name TEXT NOT NULL CHECK(length(name)<=128),
 kind TEXT NOT NULL CHECK(kind IN ('telegram','webhook')), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 subscriptions TEXT NOT NULL CHECK(length(subscriptions)<=2048), config BLOB NOT NULL CHECK(length(config)<=8192),
 next_send_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE notification_events (
 id TEXT PRIMARY KEY CHECK(length(id)<=128), dedup_key TEXT NOT NULL UNIQUE CHECK(length(dedup_key)<=512),
 kind TEXT NOT NULL CHECK(length(kind)<=48), resource_kind TEXT NOT NULL CHECK(length(resource_kind)<=48), resource_id TEXT NOT NULL CHECK(length(resource_id)<=128),
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','error','critical')), state TEXT NOT NULL CHECK(state IN ('notice','firing','resolved')),
 summary TEXT NOT NULL CHECK(length(summary)<=1024), occurrences INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, fanout_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX notification_events_fanout ON notification_events(fanout_at,created_at);
CREATE TABLE notification_deliveries (
 id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
 channel_id TEXT REFERENCES notification_channels(id) ON DELETE SET NULL, channel_name TEXT NOT NULL, channel_version INTEGER NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=8192),
 state TEXT NOT NULL CHECK(state IN ('pending','sending','sent','failed','expired','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 8),
 next_attempt_at INTEGER NOT NULL, retry_not_before INTEGER NOT NULL DEFAULT 0, lease_until INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
 http_status INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_attempt_at INTEGER NOT NULL DEFAULT 0, completed_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL,
 UNIQUE(event_id,channel_id)
);
CREATE INDEX notification_deliveries_due ON notification_deliveries(state,next_attempt_at);
CREATE TABLE notification_signals (id TEXT PRIMARY KEY, active INTEGER NOT NULL CHECK(active IN (0,1)), episode INTEGER NOT NULL, version_id TEXT REFERENCES certificate_versions(id) ON DELETE CASCADE);

-- +goose StatementBegin
CREATE TRIGGER notification_events_capacity BEFORE INSERT ON notification_events
WHEN NOT EXISTS(SELECT 1 FROM notification_events WHERE dedup_key=NEW.dedup_key) AND (SELECT COUNT(*) FROM notification_events)>=2048
BEGIN
 UPDATE notification_health SET evicted_events=evicted_events+1 WHERE id=1;
 DELETE FROM notification_events WHERE id=(SELECT id FROM notification_events ORDER BY created_at,id LIMIT 1);
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER notification_events_remove BEFORE DELETE ON notification_events
BEGIN
 UPDATE notification_health SET dropped_deliveries=dropped_deliveries+(SELECT COUNT(*) FROM notification_deliveries WHERE event_id=OLD.id AND state IN ('pending','sending')) WHERE id=1;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER notification_deliveries_capacity BEFORE INSERT ON notification_deliveries
WHEN NOT EXISTS(SELECT 1 FROM notification_deliveries WHERE event_id=NEW.event_id AND channel_id=NEW.channel_id) AND (SELECT COUNT(*) FROM notification_deliveries)>=8192
BEGIN
 UPDATE notification_health SET dropped_deliveries=dropped_deliveries+COALESCE((SELECT state IN ('pending','sending') FROM notification_deliveries ORDER BY state IN ('pending','sending'),created_at,id LIMIT 1),0) WHERE id=1;
 DELETE FROM notification_deliveries WHERE id=(SELECT id FROM notification_deliveries ORDER BY state IN ('pending','sending'),created_at,id LIMIT 1);
END;
-- +goose StatementEnd
-- +goose StatementBegin
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
-- +goose StatementBegin
CREATE TRIGGER notification_monitoring AFTER INSERT ON monitoring_events
BEGIN
 INSERT INTO notification_events(id,dedup_key,kind,resource_kind,resource_id,severity,state,summary,created_at,last_seen_at,expires_at)
 VALUES('metric.'||NEW.id,'metric:'||NEW.id,CASE WHEN NEW.active=1 THEN 'resource.alert' ELSE 'resource.recovered' END,substr(NEW.kind,1,48),substr(NEW.resource_id,1,128),CASE WHEN NEW.active=1 THEN 'warning' ELSE 'info' END,CASE WHEN NEW.active=1 THEN 'firing' ELSE 'resolved' END,NEW.summary,NEW.created_at,NEW.created_at,NEW.expires_at)
 ON CONFLICT(dedup_key) DO NOTHING;
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER notification_monitoring;
DROP TRIGGER notification_task_failure;
DROP TRIGGER notification_deliveries_capacity;
DROP TRIGGER notification_events_remove;
DROP TRIGGER notification_events_capacity;
DROP TABLE notification_signals;
DROP TABLE notification_deliveries;
DROP TABLE notification_events;
DROP TABLE notification_channels;
DROP TABLE notification_health;
DROP TABLE notification_settings;
