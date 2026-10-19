-- +goose Up
DROP INDEX component_active;
CREATE UNIQUE INDEX component_active ON tasks((1)) WHERE kind IN ('component.check','component.prepare','component.activate','component.pull') AND state IN ('queued','running','recovery_required') AND stage<>'restore_isolated';

-- +goose Down
DROP INDEX component_active;
CREATE UNIQUE INDEX component_active ON tasks((1)) WHERE kind IN ('component.check','component.prepare','component.activate') AND state IN ('queued','running','recovery_required');
