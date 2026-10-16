-- +goose Up
ALTER TABLE panel_updates ADD COLUMN cleanup_pending INTEGER NOT NULL DEFAULT 1 CHECK(cleanup_pending IN (0,1));
ALTER TABLE panel_updates ADD COLUMN cleanup_checked_at INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_checked_at>=0);
CREATE INDEX panel_update_cleanup ON panel_updates(cleanup_pending,cleanup_checked_at,task_id);

-- +goose Down
DROP INDEX panel_update_cleanup;
ALTER TABLE panel_updates DROP COLUMN cleanup_checked_at;
ALTER TABLE panel_updates DROP COLUMN cleanup_pending;
