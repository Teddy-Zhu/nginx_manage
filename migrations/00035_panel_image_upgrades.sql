-- +goose Up
CREATE TABLE panel_image_upgrades (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 principal TEXT NOT NULL,
 maintenance_id TEXT NOT NULL REFERENCES maintenance_sessions(task_id),
 prepare_task_id TEXT NOT NULL REFERENCES component_operations(task_id),
 input BLOB NOT NULL CHECK(length(input)<=8192),
 request_id TEXT NOT NULL UNIQUE,
 result BLOB CHECK(result IS NULL OR length(result)<=16384)
);
CREATE TABLE panel_image_upgrade_requests (
 id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL REFERENCES panel_image_upgrades(task_id),
 principal TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=8192),
 dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN (0,1)),
 created_at INTEGER NOT NULL
);
CREATE INDEX panel_image_upgrade_request_task ON panel_image_upgrade_requests(task_id);
DROP INDEX independent_program_active;
CREATE UNIQUE INDEX independent_program_active ON tasks((1)) WHERE kind IN ('panel.update','agent.upgrade','panel.image') AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND stage<>'restore_isolated';
CREATE INDEX panel_image_upgrade_maintenance ON panel_image_upgrades(maintenance_id);

-- +goose Down
DROP INDEX independent_program_active;
CREATE UNIQUE INDEX independent_program_active ON tasks((1)) WHERE kind IN ('panel.update','agent.upgrade') AND state NOT IN ('succeeded','failed','rolled_back','cancelled');
DROP TABLE panel_image_upgrade_requests;
DROP TABLE panel_image_upgrades;
