-- +goose Up
CREATE TABLE fail2ban_operations (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    payload BLOB NOT NULL CHECK(length(payload)<=73728)
);

-- +goose Down
DROP TABLE fail2ban_operations;
