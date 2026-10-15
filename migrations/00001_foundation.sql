-- +goose Up
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE users (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    session_epoch INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE TABLE sessions (token TEXT PRIMARY KEY, data BLOB NOT NULL, expiry INTEGER NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expiry);
CREATE TABLE api_credentials (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL CHECK(json_valid(scopes)),
    allowed_sources TEXT NOT NULL CHECK(json_valid(allowed_sources)),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    last_used_at INTEGER, revoked_at INTEGER
);
CREATE TABLE module_settings (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE config_revisions (
    id TEXT PRIMARY KEY, parent_id TEXT REFERENCES config_revisions(id),
    version INTEGER NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN ('draft','desired')),
    parser_version TEXT NOT NULL, policy_version TEXT NOT NULL,
    diagnostics TEXT NOT NULL CHECK(json_valid(diagnostics)),
    created_at INTEGER NOT NULL, created_by TEXT NOT NULL
);
CREATE TABLE nginx_config_files (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    id TEXT NOT NULL, path TEXT NOT NULL, content BLOB NOT NULL, sha256 TEXT NOT NULL,
    PRIMARY KEY(revision_id,id), UNIQUE(revision_id,path)
);
CREATE TABLE nginx_resource_bindings (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    resource_id TEXT NOT NULL, file_id TEXT NOT NULL, block_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('http','stream')),
    projection BLOB NOT NULL,
    PRIMARY KEY(revision_id,resource_id), UNIQUE(revision_id,file_id,block_key),
    FOREIGN KEY(revision_id,file_id) REFERENCES nginx_config_files(revision_id,id)
);
CREATE TABLE config_head (
    id INTEGER PRIMARY KEY CHECK(id=1), desired_revision TEXT REFERENCES config_revisions(id),
    applied_revision TEXT REFERENCES config_revisions(id), version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO config_head (id,version) VALUES (1,0);
CREATE TABLE tasks (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, resource_id TEXT NOT NULL,
    revision_id TEXT REFERENCES config_revisions(id),
    state TEXT NOT NULL CHECK(state IN ('queued','running','waiting_confirmation','compensating','succeeded','failed','rolled_back','recovery_required','cancelled')),
    stage TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
    attempts INTEGER NOT NULL DEFAULT 0, lease_until INTEGER,
    last_error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX tasks_queue ON tasks(state,created_at);
CREATE TABLE idempotency_keys (
    principal TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
    response BLOB NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY(principal,key)
);
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL, principal TEXT NOT NULL,
    action TEXT NOT NULL, resource_id TEXT NOT NULL, outcome TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX audit_created ON audit_logs(created_at);

-- +goose Down
DROP TABLE audit_logs;
DROP TABLE idempotency_keys;
DROP TABLE tasks;
DROP TABLE config_head;
DROP TABLE nginx_resource_bindings;
DROP TABLE nginx_config_files;
DROP TABLE config_revisions;
DROP TABLE module_settings;
DROP TABLE api_credentials;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE settings;
