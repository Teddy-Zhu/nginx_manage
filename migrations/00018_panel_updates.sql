-- +goose Up
CREATE TABLE panel_updates (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 principal TEXT NOT NULL,
 maintenance_id TEXT NOT NULL REFERENCES maintenance_sessions(task_id),
 prepare_task_id TEXT NOT NULL REFERENCES component_operations(task_id),
 input BLOB NOT NULL CHECK(length(input)<=8192),
 request_id TEXT NOT NULL UNIQUE,
 result BLOB CHECK(result IS NULL OR length(result)<=16384)
);
CREATE TABLE panel_update_requests (
 id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL REFERENCES panel_updates(task_id),
 principal TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=8192),
 dispatched INTEGER NOT NULL DEFAULT 0 CHECK(dispatched IN (0,1)),
 created_at INTEGER NOT NULL
);
CREATE INDEX panel_update_request_task ON panel_update_requests(task_id);
CREATE UNIQUE INDEX panel_update_active ON tasks((1)) WHERE kind='panel.update' AND state NOT IN ('succeeded','failed','rolled_back','cancelled');
CREATE INDEX panel_update_maintenance ON panel_updates(maintenance_id);

-- +goose Down
DROP INDEX panel_update_active;
DROP TABLE panel_update_requests;
DROP TABLE panel_updates;
