-- +goose Up
CREATE TABLE nodes (
 id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 name TEXT NOT NULL,
 endpoint TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 credential_id TEXT NOT NULL,
 token BLOB CHECK(token IS NULL OR length(token)<=2048),
 scopes TEXT NOT NULL CHECK(json_valid(scopes) AND length(scopes)<=4096),
 expires_at INTEGER NOT NULL,
 api_version INTEGER NOT NULL,
 capabilities BLOB CHECK(capabilities IS NULL OR length(capabilities)<=262144),
 state TEXT NOT NULL CHECK(state IN ('connected','unreachable','identity_changed','authorization_failed','incompatible','removing','removed')),
 last_error TEXT NOT NULL DEFAULT '',
 checked_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 removed_at INTEGER,
 revocation TEXT NOT NULL DEFAULT '' CHECK(revocation IN ('','pending','revoked')),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE UNIQUE INDEX nodes_active_identity ON nodes(node_id) WHERE removed_at IS NULL;
CREATE TABLE node_requests (
 principal TEXT NOT NULL,
 key TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('create','delete')),
 request_hash TEXT NOT NULL,
 connection_id TEXT NOT NULL REFERENCES nodes(id),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(principal,key)
);

-- +goose Down
DROP TABLE node_requests;
DROP TABLE nodes;
