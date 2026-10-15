-- +goose Up
ALTER TABLE tasks ADD COLUMN restore_snapshot TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE tasks DROP COLUMN restore_snapshot;
