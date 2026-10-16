-- +goose Up
CREATE TABLE node_pairings (
 id TEXT PRIMARY KEY,
 principal TEXT NOT NULL,
 issuer_machine INTEGER NOT NULL CHECK(issuer_machine IN (0,1)),
 issuer_epoch INTEGER NOT NULL,
 create_key TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 name TEXT NOT NULL,
 controller_node_id TEXT NOT NULL,
 scopes TEXT NOT NULL CHECK(json_valid(scopes) AND length(scopes)<=4096),
 allowed_sources TEXT NOT NULL CHECK(json_valid(allowed_sources) AND length(allowed_sources)<=4096),
 credential_expires_at INTEGER NOT NULL,
 secret_hash TEXT NOT NULL,
 claim_hash TEXT,
 credential_id TEXT REFERENCES api_credentials(id),
 token BLOB CHECK(token IS NULL OR length(token)<=2048),
 state TEXT NOT NULL CHECK(state IN ('offered','claimed','confirmed','revoked')),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 claimed_at INTEGER,
 confirmed_at INTEGER,
 revoked_at INTEGER,
 UNIQUE(principal,create_key)
);
CREATE UNIQUE INDEX node_pairings_credential ON node_pairings(credential_id) WHERE credential_id IS NOT NULL;

CREATE TABLE node_pairing_jobs (
 id TEXT PRIMARY KEY,
 principal TEXT NOT NULL,
 request_key TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 name TEXT NOT NULL,
 endpoint TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 controller_node_id TEXT NOT NULL,
 target_node_id TEXT NOT NULL,
 pairing_id TEXT NOT NULL,
 material BLOB CHECK(material IS NULL OR length(material)<=8192),
 credential_id TEXT NOT NULL DEFAULT '',
 connection_id TEXT REFERENCES nodes(id),
 state TEXT NOT NULL CHECK(state IN ('pending','recovery_required','abandoning','succeeded','abandoned')),
 stage TEXT NOT NULL CHECK(stage IN ('exchange','confirm','register','finished')),
 last_error TEXT NOT NULL DEFAULT '',
 revocation TEXT NOT NULL DEFAULT '' CHECK(revocation IN ('','pending','revoked')),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 UNIQUE(principal,request_key)
);
CREATE UNIQUE INDEX node_pairing_jobs_offer ON node_pairing_jobs(target_node_id,pairing_id);

-- +goose Down
DROP TABLE node_pairing_jobs;
DROP TABLE node_pairings;
