-- +goose Up
CREATE TABLE backup_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL DEFAULT 1,
 recipient TEXT NOT NULL DEFAULT '', key_saved_at INTEGER NOT NULL DEFAULT 0,
 interval_hours INTEGER NOT NULL DEFAULT 24 CHECK(interval_hours BETWEEN 1 AND 168),
 keep_count INTEGER NOT NULL DEFAULT 7 CHECK(keep_count BETWEEN 1 AND 15),
 retention_days INTEGER NOT NULL DEFAULT 30 CHECK(retention_days BETWEEN 1 AND 90),
 principal TEXT NOT NULL DEFAULT '', issuer_machine INTEGER NOT NULL DEFAULT 0 CHECK(issuer_machine IN(0,1)),
 issuer_epoch INTEGER NOT NULL DEFAULT 0, authorization_until INTEGER NOT NULL DEFAULT 0,
 next_run_at INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT INTO backup_policy(id) VALUES(1);
CREATE TABLE backup_records (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), principal TEXT NOT NULL,
 issuer_machine INTEGER NOT NULL CHECK(issuer_machine IN(0,1)), issuer_epoch INTEGER NOT NULL,
 name TEXT NOT NULL, encryption TEXT NOT NULL CHECK(encryption IN('recipient','passphrase')),
 recipient TEXT NOT NULL, authorization_until INTEGER NOT NULL, policy_version INTEGER NOT NULL DEFAULT 0,
 maintenance_id TEXT REFERENCES maintenance_sessions(task_id), request_id TEXT NOT NULL,
 manifest BLOB CHECK(manifest IS NULL OR length(manifest)<=131072),
 archive_size INTEGER NOT NULL DEFAULT 0, archive_sha256 TEXT NOT NULL DEFAULT '',
 captured_at INTEGER NOT NULL DEFAULT 0, finished_at INTEGER NOT NULL DEFAULT 0,
 expires_at INTEGER NOT NULL, delete_started INTEGER NOT NULL DEFAULT 0 CHECK(delete_started IN(0,1)), deleted_at INTEGER
);
CREATE TABLE backup_requests (
 principal TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
 task_id TEXT NOT NULL UNIQUE REFERENCES backup_records(task_id),
 PRIMARY KEY(principal,key)
);
CREATE UNIQUE INDEX backup_active ON tasks((1)) WHERE kind='backup.create' AND state NOT IN('succeeded','failed','rolled_back','cancelled');
CREATE INDEX backup_maintenance ON backup_records(maintenance_id);
CREATE TABLE backup_downloads (
 token_hash TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES backup_records(task_id),
 principal TEXT NOT NULL, session_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
);
INSERT INTO module_settings(id,enabled) VALUES('automatic-backups',0);

-- +goose Down
DELETE FROM module_settings WHERE id='automatic-backups';
DROP TABLE backup_downloads;
DROP INDEX backup_active;
DROP TABLE backup_requests;
DROP TABLE backup_records;
DROP TABLE backup_policy;
