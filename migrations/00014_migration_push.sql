-- +goose Up
CREATE TABLE migration_receives (
 plan_id TEXT PRIMARY KEY REFERENCES migration_plans(id), request_hash TEXT NOT NULL
);
CREATE TABLE migration_pushes (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), principal TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=12582912), summary BLOB NOT NULL CHECK(length(summary)<=270336),
 remote_started INTEGER NOT NULL DEFAULT 0 CHECK(remote_started IN(0,1)),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version>0), expires_at INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX migration_push_due ON migration_pushes(next_attempt_at);
-- +goose Down
DROP TABLE migration_pushes;
DROP TABLE migration_receives;
