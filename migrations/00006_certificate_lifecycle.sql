-- +goose Up
ALTER TABLE acme_profiles ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0 CHECK(auto_renew IN (0,1));
ALTER TABLE acme_profiles ADD COLUMN auto_deploy INTEGER NOT NULL DEFAULT 0 CHECK(auto_deploy IN (0,1));
ALTER TABLE acme_profiles ADD COLUMN deploy_after INTEGER NOT NULL DEFAULT 0;
ALTER TABLE acme_profiles ADD COLUMN deployment_error TEXT NOT NULL DEFAULT '';
ALTER TABLE acme_profiles ADD COLUMN deployment_observed_version TEXT NOT NULL DEFAULT '';
ALTER TABLE acme_orders ADD COLUMN automatic INTEGER NOT NULL DEFAULT 0 CHECK(automatic IN (0,1));
ALTER TABLE acme_orders ADD COLUMN terminal INTEGER NOT NULL DEFAULT 0 CHECK(terminal IN (0,1));
ALTER TABLE acme_orders ADD COLUMN replaces_id TEXT NOT NULL DEFAULT '';
CREATE TABLE acme_renewals (
 profile_id TEXT PRIMARY KEY REFERENCES acme_profiles(id),
 version_id TEXT NOT NULL REFERENCES certificate_versions(id) ON DELETE CASCADE,
 renew_at INTEGER NOT NULL, source TEXT NOT NULL CHECK(source IN ('fallback','ari')),
 next_check_at INTEGER NOT NULL, last_check_at INTEGER NOT NULL DEFAULT 0,
 window_start INTEGER NOT NULL DEFAULT 0, window_end INTEGER NOT NULL DEFAULT 0,
 explanation_url TEXT NOT NULL DEFAULT '', check_failures INTEGER NOT NULL DEFAULT 0,
 failures INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0,1)),
 last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE certificate_deployments (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id),
 certificate_id TEXT NOT NULL REFERENCES certificates(id),
 version_id TEXT NOT NULL REFERENCES certificate_versions(id),
 basis_revision TEXT NOT NULL REFERENCES config_revisions(id),
 revision_id TEXT NOT NULL REFERENCES config_revisions(id),
 automatic INTEGER NOT NULL CHECK(automatic IN (0,1)), created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX certificate_auto_deploy ON certificate_deployments(version_id) WHERE automatic=1;

-- +goose Down
DROP INDEX certificate_auto_deploy;
DROP TABLE certificate_deployments;
DROP TABLE acme_renewals;
ALTER TABLE acme_orders DROP COLUMN replaces_id;
ALTER TABLE acme_orders DROP COLUMN terminal;
ALTER TABLE acme_orders DROP COLUMN automatic;
ALTER TABLE acme_profiles DROP COLUMN deployment_error;
ALTER TABLE acme_profiles DROP COLUMN deployment_observed_version;
ALTER TABLE acme_profiles DROP COLUMN deploy_after;
ALTER TABLE acme_profiles DROP COLUMN auto_deploy;
ALTER TABLE acme_profiles DROP COLUMN auto_renew;
