-- +goose Up
ALTER TABLE migration_pulls ADD COLUMN continuation BLOB CHECK(continuation IS NULL OR length(continuation)<=16384);
ALTER TABLE migration_pulls ADD COLUMN state TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_pulls ADD COLUMN stage TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_pulls ADD COLUMN mode TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_pulls ADD COLUMN deadline INTEGER NOT NULL DEFAULT 0;
ALTER TABLE migration_pulls ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX migration_pull_plan ON migration_pulls(plan_id);

-- +goose Down
DROP INDEX migration_pull_plan;
ALTER TABLE migration_pulls DROP COLUMN last_error;
ALTER TABLE migration_pulls DROP COLUMN deadline;
ALTER TABLE migration_pulls DROP COLUMN mode;
ALTER TABLE migration_pulls DROP COLUMN stage;
ALTER TABLE migration_pulls DROP COLUMN state;
ALTER TABLE migration_pulls DROP COLUMN continuation;
