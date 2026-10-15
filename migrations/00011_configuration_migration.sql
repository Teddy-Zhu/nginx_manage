-- +goose Up
CREATE TABLE migration_plans (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=12582912),
 summary BLOB NOT NULL CHECK(length(summary)<=262144),
 state TEXT NOT NULL CHECK(state IN ('planned','draft','saved','applying','succeeded','failed','rolled_back','recovery_required')),
 revision_id TEXT NOT NULL DEFAULT '', task_id TEXT NOT NULL DEFAULT '',
 basis_revision TEXT NOT NULL DEFAULT '', basis_version INTEGER NOT NULL, basis_applied TEXT NOT NULL DEFAULT '',
 expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 last_error TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX migration_active ON migration_plans((1)) WHERE state IN ('applying','recovery_required');
CREATE TABLE migration_pulls (
 principal TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
 plan_id TEXT NOT NULL REFERENCES migration_plans(id), created_at INTEGER NOT NULL,
 PRIMARY KEY(principal,key)
);

-- +goose Down
DROP TABLE migration_pulls;
DROP TABLE migration_plans;
