-- +goose Up
CREATE TABLE migration_dependencies (
 plan_id TEXT PRIMARY KEY REFERENCES migration_plans(id),
 task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
 principal TEXT NOT NULL, request_hash TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=16384),
 check_task_id TEXT NOT NULL DEFAULT '', prepare_task_id TEXT NOT NULL DEFAULT '',
 deadline INTEGER NOT NULL
);

-- +goose Down
DROP TABLE migration_dependencies;
