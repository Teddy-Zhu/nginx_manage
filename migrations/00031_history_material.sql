-- +goose Up
ALTER TABLE config_revisions ADD COLUMN pruned_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certificate_versions ADD COLUMN pruned_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE acme_orders ADD COLUMN pruned_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX config_history_material ON config_revisions(created_at,version) WHERE pruned_at=0;
CREATE INDEX certificate_history_material ON certificate_versions(certificate_id,ordinal) WHERE pruned_at=0;
CREATE INDEX acme_history_material ON acme_orders(profile_id,created_at,id) WHERE pruned_at=0;

-- +goose Down
DROP INDEX acme_history_material;
DROP INDEX certificate_history_material;
DROP INDEX config_history_material;
ALTER TABLE acme_orders DROP COLUMN pruned_at;
ALTER TABLE certificate_versions DROP COLUMN pruned_at;
ALTER TABLE config_revisions DROP COLUMN pruned_at;
