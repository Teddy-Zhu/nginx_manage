-- +goose Up
CREATE TABLE nginx_installations (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 principal TEXT NOT NULL,
 maintenance_id TEXT NOT NULL REFERENCES maintenance_sessions(task_id),
 prepare_task_id TEXT NOT NULL REFERENCES component_operations(task_id),
 sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 32),
 command TEXT NOT NULL CHECK(command IN ('install','resume','cancel')),
 authorization_until INTEGER NOT NULL CHECK(authorization_until>0),
 payload BLOB NOT NULL CHECK(length(payload)<=8192),
 result BLOB CHECK(result IS NULL OR length(result)<=32768)
);
CREATE UNIQUE INDEX nginx_installation_active ON tasks((1)) WHERE kind='component.install' AND state NOT IN ('succeeded','failed','cancelled');
CREATE INDEX nginx_installation_maintenance ON nginx_installations(maintenance_id);

-- +goose Down
DROP INDEX nginx_installation_active;
DROP TABLE nginx_installations;
