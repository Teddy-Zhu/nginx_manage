-- +goose Up
DROP INDEX independent_program_active;
CREATE UNIQUE INDEX independent_program_active ON tasks((1)) WHERE kind IN ('panel.update','agent.upgrade','panel.image','nginx.image') AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND stage<>'restore_isolated';

-- +goose Down
DROP INDEX independent_program_active;
CREATE UNIQUE INDEX independent_program_active ON tasks((1)) WHERE kind IN ('panel.update','agent.upgrade','panel.image') AND state NOT IN ('succeeded','failed','rolled_back','cancelled') AND stage<>'restore_isolated';
