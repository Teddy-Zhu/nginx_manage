-- +goose Up
ALTER TABLE migration_plans ADD COLUMN pruned_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE migration_plans ADD COLUMN execution_principal TEXT NOT NULL DEFAULT '';
ALTER TABLE migration_plans ADD COLUMN execution_key TEXT NOT NULL DEFAULT '' CHECK(length(execution_key)<=128);
ALTER TABLE migration_plans ADD COLUMN execution_hash TEXT NOT NULL DEFAULT '' CHECK(length(execution_hash) IN(0,64));
CREATE INDEX migration_history_material ON migration_plans(principal,created_at,id) WHERE pruned_at=0;
CREATE INDEX migration_plans_history ON migration_plans(created_at DESC,id);
CREATE INDEX migration_plans_owner_history ON migration_plans(principal,created_at DESC,id);

-- +goose Down
DROP INDEX migration_plans_owner_history;
DROP INDEX migration_plans_history;
DROP INDEX migration_history_material;
ALTER TABLE migration_plans DROP COLUMN execution_hash;
ALTER TABLE migration_plans DROP COLUMN execution_key;
ALTER TABLE migration_plans DROP COLUMN execution_principal;
ALTER TABLE migration_plans DROP COLUMN pruned_at;
