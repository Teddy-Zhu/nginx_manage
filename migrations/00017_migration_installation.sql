-- +goose Up
ALTER TABLE maintenance_sessions ADD COLUMN owner_task_id TEXT REFERENCES tasks(id);
CREATE UNIQUE INDEX maintenance_owner_task ON maintenance_sessions(owner_task_id) WHERE owner_task_id IS NOT NULL;
ALTER TABLE migration_dependencies ADD COLUMN maintenance_task_id TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_dependencies ADD COLUMN install_task_id TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_dependencies ADD COLUMN settlement_state TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_dependencies ADD COLUMN settlement_stage TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_dependencies ADD COLUMN settlement_error TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE migration_dependencies DROP COLUMN settlement_error;
ALTER TABLE migration_dependencies DROP COLUMN settlement_stage;
ALTER TABLE migration_dependencies DROP COLUMN settlement_state;
ALTER TABLE migration_dependencies DROP COLUMN install_task_id;
ALTER TABLE migration_dependencies DROP COLUMN maintenance_task_id;
DROP INDEX maintenance_owner_task;
ALTER TABLE maintenance_sessions DROP COLUMN owner_task_id;
