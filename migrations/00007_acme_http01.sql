-- +goose Up
ALTER TABLE acme_profiles ADD COLUMN challenge_type TEXT NOT NULL DEFAULT 'dns-01' CHECK(challenge_type IN ('dns-01','http-01'));
ALTER TABLE acme_profiles ADD COLUMN http01_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(http01_confirmed IN (0,1));
ALTER TABLE acme_orders ADD COLUMN challenge_type TEXT NOT NULL DEFAULT 'dns-01' CHECK(challenge_type IN ('dns-01','http-01'));
ALTER TABLE acme_orders ADD COLUMN http01_state TEXT NOT NULL DEFAULT 'none' CHECK(http01_state IN ('none','unknown','active','cleaned'));
ALTER TABLE acme_orders ADD COLUMN http01_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE acme_orders ADD COLUMN http01_expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE acme_orders ADD COLUMN http01_epoch INTEGER NOT NULL DEFAULT 0 CHECK(http01_epoch BETWEEN 0 AND 1000000000);

-- +goose Down
ALTER TABLE acme_orders DROP COLUMN http01_epoch;
ALTER TABLE acme_orders DROP COLUMN http01_expires_at;
ALTER TABLE acme_orders DROP COLUMN http01_revision;
ALTER TABLE acme_orders DROP COLUMN http01_state;
ALTER TABLE acme_orders DROP COLUMN challenge_type;
ALTER TABLE acme_profiles DROP COLUMN http01_confirmed;
ALTER TABLE acme_profiles DROP COLUMN challenge_type;
