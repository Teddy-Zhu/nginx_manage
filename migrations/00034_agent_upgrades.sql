-- +goose Up
CREATE TABLE agent_upgrades (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 principal TEXT NOT NULL,
 maintenance_id TEXT NOT NULL REFERENCES maintenance_sessions(task_id),
 prepare_task_id TEXT NOT NULL REFERENCES component_operations(task_id),
 input BLOB NOT NULL CHECK(length(input)<=8192),
 request_id TEXT NOT NULL UNIQUE,
 result BLOB CHECK(result IS NULL OR length(result)<=16384)
);
CREATE TABLE agent_upgrade_requests (
 id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL REFERENCES agent_upgrades(task_id),
 principal TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=8192),
 dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN (0,1)),
 created_at INTEGER NOT NULL
);
CREATE INDEX agent_upgrade_request_task ON agent_upgrade_requests(task_id);
DROP INDEX panel_update_active;
CREATE UNIQUE INDEX independent_program_active ON tasks((1)) WHERE kind IN ('panel.update','agent.upgrade') AND state NOT IN ('succeeded','failed','rolled_back','cancelled');
CREATE INDEX agent_upgrade_maintenance ON agent_upgrades(maintenance_id);

-- +goose Down
DROP INDEX independent_program_active;
CREATE UNIQUE INDEX panel_update_active ON tasks((1)) WHERE kind='panel.update' AND state NOT IN ('succeeded','failed','rolled_back','cancelled');
DROP TABLE agent_upgrade_requests;
DROP TABLE agent_upgrades;
