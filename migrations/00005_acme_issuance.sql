-- +goose Up
ALTER TABLE certificate_versions ADD COLUMN environment TEXT NOT NULL DEFAULT 'manual' CHECK(environment IN ('manual','production','staging'));
CREATE TABLE acme_profiles (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT NOT NULL, version INTEGER NOT NULL,
 account_id TEXT REFERENCES acme_accounts(id), credential_id TEXT REFERENCES dns_credentials(id),
 environment TEXT NOT NULL CHECK(environment IN ('production','staging')),
 domains TEXT NOT NULL CHECK(json_valid(domains)),
 certificate_id TEXT UNIQUE REFERENCES certificates(id) ON DELETE SET NULL,
 state TEXT NOT NULL CHECK(state IN ('idle','issuing','issued','failed','recovery_required','archived')),
 current_order_id TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '', retry_after INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE acme_orders (
 id TEXT PRIMARY KEY, profile_id TEXT NOT NULL REFERENCES acme_profiles(id), task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
 account_id TEXT REFERENCES acme_accounts(id) ON DELETE SET NULL,
 provider TEXT NOT NULL, credentials BLOB NOT NULL, private_key BLOB NOT NULL, csr BLOB NOT NULL,
 submit_started INTEGER NOT NULL DEFAULT 0 CHECK(submit_started IN (0,1)),
 order_url TEXT NOT NULL DEFAULT '', certificate_url TEXT NOT NULL DEFAULT '',
 next_poll_at INTEGER NOT NULL DEFAULT 0,
 certificate_version_id TEXT REFERENCES certificate_versions(id) ON DELETE SET NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE acme_dns_locks (fqdn TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES acme_orders(id));
CREATE TABLE acme_dns_records (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES acme_orders(id), fqdn TEXT NOT NULL,
 value_hash TEXT NOT NULL, payload BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('preparing','present','cleaned','blocked')),
 last_error TEXT NOT NULL DEFAULT '', UNIQUE(order_id,fqdn,value_hash)
);
CREATE UNIQUE INDEX acme_issuance_lock ON tasks(resource_id)
 WHERE kind='acme.issue' AND state IN ('queued','running','recovery_required');

-- +goose Down
DROP INDEX acme_issuance_lock;
DROP TABLE acme_dns_records;
DROP TABLE acme_dns_locks;
DROP TABLE acme_orders;
DROP TABLE acme_profiles;
ALTER TABLE certificate_versions DROP COLUMN environment;
