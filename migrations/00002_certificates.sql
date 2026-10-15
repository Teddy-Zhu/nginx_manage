-- +goose Up
CREATE TABLE certificates (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT NOT NULL,
    version INTEGER NOT NULL, latest_version_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('manual','acme')),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE certificate_versions (
    id TEXT PRIMARY KEY, certificate_id TEXT NOT NULL REFERENCES certificates(id),
    ordinal INTEGER NOT NULL, fullchain BLOB NOT NULL, private_key BLOB NOT NULL,
    summary TEXT NOT NULL CHECK(json_valid(summary)), created_at INTEGER NOT NULL,
    UNIQUE(certificate_id,ordinal), UNIQUE(certificate_id,id)
);
CREATE TABLE nginx_certificate_references (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    file_id TEXT NOT NULL, position INTEGER NOT NULL, resource_id TEXT NOT NULL,
    certificate_id TEXT NOT NULL, version_id TEXT NOT NULL, purpose TEXT NOT NULL,
    PRIMARY KEY(revision_id,file_id,position),
    FOREIGN KEY(certificate_id,version_id) REFERENCES certificate_versions(certificate_id,id)
);
CREATE INDEX certificate_references ON nginx_certificate_references(certificate_id,version_id);

-- +goose Down
DROP TABLE nginx_certificate_references;
DROP TABLE certificate_versions;
DROP TABLE certificates;
