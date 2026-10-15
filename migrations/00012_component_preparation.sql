-- +goose Up
CREATE TABLE component_operations (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 principal TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=65536),
 result BLOB CHECK(result IS NULL OR length(result)<=65536)
);
CREATE INDEX component_principal ON component_operations(principal,task_id);
CREATE UNIQUE INDEX component_active ON tasks((1)) WHERE kind IN ('component.check','component.prepare') AND state IN ('queued','running','recovery_required');

-- +goose Down
DROP INDEX component_active;
DROP TABLE component_operations;
