-- +goose Up
-- Match the 16 MiB policy limit, including the authenticated encryption envelope.
CREATE TABLE firewall_policy_expanded (
    id INTEGER PRIMARY KEY CHECK(id=1),
    version INTEGER NOT NULL CHECK(version>=1),
    payload BLOB NOT NULL CHECK(length(payload)<=16777472),
    updated_at INTEGER NOT NULL
);
INSERT INTO firewall_policy_expanded SELECT * FROM firewall_policy;
DROP TABLE firewall_policy;
ALTER TABLE firewall_policy_expanded RENAME TO firewall_policy;

-- +goose Down
CREATE TABLE firewall_policy_reduced (
    id INTEGER PRIMARY KEY CHECK(id=1),
    version INTEGER NOT NULL CHECK(version>=1),
    payload BLOB NOT NULL CHECK(length(payload)<=262400),
    updated_at INTEGER NOT NULL
);
INSERT INTO firewall_policy_reduced SELECT * FROM firewall_policy;
DROP TABLE firewall_policy;
ALTER TABLE firewall_policy_reduced RENAME TO firewall_policy;
