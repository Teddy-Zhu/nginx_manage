-- +goose Up
CREATE TABLE fail2ban_policy (
    id INTEGER PRIMARY KEY CHECK(id=1),
    version INTEGER NOT NULL CHECK(version>=1),
    payload BLOB NOT NULL CHECK(length(payload)<=65792),
    updated_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE fail2ban_policy;
