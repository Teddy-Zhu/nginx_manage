-- +goose Up
CREATE TABLE firewall_geoip (
  id INTEGER PRIMARY KEY CHECK(id=1),
  version INTEGER NOT NULL CHECK(version>0),
  source BLOB NOT NULL,
  dataset BLOB NOT NULL,
  dataset_source TEXT NOT NULL,
  dataset_hash TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE firewall_geoip;
