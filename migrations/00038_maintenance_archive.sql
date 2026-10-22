-- +goose Up
ALTER TABLE maintenance_sessions ADD COLUMN archived_at INTEGER NOT NULL DEFAULT 0 CHECK(archived_at>=0 AND (archived_at=0 OR phase IN('released','failed')));
CREATE INDEX maintenance_history_archive ON maintenance_sessions(updated_at,task_id) WHERE archived_at=0;

-- +goose Down
DROP INDEX maintenance_history_archive;
ALTER TABLE maintenance_sessions DROP COLUMN archived_at;
