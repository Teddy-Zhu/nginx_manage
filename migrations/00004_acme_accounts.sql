-- +goose Up
CREATE TABLE acme_accounts (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('production','staging')),
    version INTEGER NOT NULL CHECK(version > 0),
    private_key BLOB NOT NULL, key_fingerprint TEXT NOT NULL,
    registration BLOB, account_url TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK(state IN ('pending','registering','ready','failed')),
    task_id TEXT NOT NULL REFERENCES tasks(id),
    last_error TEXT NOT NULL DEFAULT '', retry_after INTEGER NOT NULL DEFAULT 0,
    terms_agreed_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    UNIQUE(environment,key_fingerprint)
);
CREATE TABLE dns_credentials (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    provider TEXT NOT NULL CHECK(provider IN ('cloudflare','alidns','tencentcloud')),
    version INTEGER NOT NULL CHECK(version > 0),
    secrets BLOB NOT NULL, field_names TEXT NOT NULL CHECK(json_valid(field_names)),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX acme_account_task_lock ON tasks(resource_id)
    WHERE kind='acme.account.register' AND state IN ('queued','running','recovery_required');

-- +goose Down
DROP INDEX acme_account_task_lock;
DROP TABLE dns_credentials;
DROP TABLE acme_accounts;
