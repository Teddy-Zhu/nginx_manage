-- +goose Up
CREATE TABLE host_dns_plans(id TEXT NOT NULL, principal TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=32768), expires_at INTEGER NOT NULL, PRIMARY KEY(principal,id));
CREATE TABLE host_dns_operations(task_id TEXT PRIMARY KEY REFERENCES tasks(id), payload BLOB NOT NULL CHECK(length(payload)<=32768), decision TEXT NOT NULL DEFAULT '' CHECK(decision IN ('','confirm','rollback')));
CREATE TABLE host_dns_desired(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=32768), source_hash TEXT NOT NULL, updated_at INTEGER NOT NULL);

-- +goose Down
DROP TABLE host_dns_desired;
DROP TABLE host_dns_operations;
DROP TABLE host_dns_plans;
