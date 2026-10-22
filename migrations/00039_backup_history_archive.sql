-- +goose Up
ALTER TABLE backup_records ADD COLUMN archived_at INTEGER NOT NULL DEFAULT 0 CHECK(archived_at>=0 AND (archived_at=0 OR (deleted_at IS NOT NULL AND delete_started=0)));
CREATE INDEX backup_history_archive ON backup_records(archived_at,deleted_at,task_id);

-- +goose Down
DROP INDEX backup_history_archive;
ALTER TABLE backup_records DROP COLUMN archived_at;
