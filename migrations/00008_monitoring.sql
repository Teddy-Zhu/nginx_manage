-- +goose Up
CREATE TABLE monitoring_settings (
    id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL DEFAULT 1,
    settings TEXT NOT NULL CHECK(length(settings)<=4096)
);
CREATE TABLE metric_samples (
    minute INTEGER PRIMARY KEY, payload BLOB NOT NULL CHECK(length(payload)<=131072),
    bytes INTEGER NOT NULL CHECK(bytes>=0 AND bytes=length(payload))
);
CREATE TABLE monitoring_conditions (
    kind TEXT NOT NULL, resource_id TEXT NOT NULL, payload TEXT NOT NULL CHECK(length(payload)<=2048),
    PRIMARY KEY(kind,resource_id)
);
CREATE TABLE monitoring_events (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, resource_id TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)), summary TEXT NOT NULL CHECK(length(summary)<=1024),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX monitoring_events_time ON monitoring_events(created_at);

-- +goose Down
DROP TABLE monitoring_events;
DROP TABLE monitoring_conditions;
DROP TABLE metric_samples;
DROP TABLE monitoring_settings;
