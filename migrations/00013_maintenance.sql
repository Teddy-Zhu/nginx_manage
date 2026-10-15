-- +goose Up
CREATE TABLE maintenance_sessions (
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), principal TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('draining','root_acquiring','held','releasing','released','failed','recovery_required')),
 deadline INTEGER NOT NULL, root_requested INTEGER NOT NULL DEFAULT 0 CHECK(root_requested IN(0,1)),
 root_epoch TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX maintenance_active ON maintenance_sessions((1)) WHERE phase NOT IN ('released','failed');

-- +goose Down
DROP TABLE maintenance_sessions;
