package firewall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"nginxpanel/internal/fault"
)

type GeoIPConfig struct {
	Version int64       `json:"version"`
	Source  GeoIPSource `json:"source"`
}

func (s *Service) ReadGeoIPConfig(ctx context.Context, q PolicyReader) (GeoIPConfig, error) {
	out := GeoIPConfig{Source: DefaultGeoIPSource()}
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT version,source FROM firewall_geoip WHERE id=1").Scan(&out.Version, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	raw, err := s.Vault.Open(sealed, "firewall:geoip:source")
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out.Source); err != nil {
		return out, err
	}
	return out, out.Source.validate()
}

// Migration carries source settings and resolved rule snapshots, not downloaded databases.
func (s *Service) StoreGeoIPSource(ctx context.Context, tx *sql.Tx, base int64, source GeoIPSource) (GeoIPConfig, error) {
	var out GeoIPConfig
	if base < 0 || base == math.MaxInt64 {
		return out, fault.Invalid("GeoIP 配置版本无效")
	}
	if err := source.validate(); err != nil {
		return out, err
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return out, err
	}
	sealed := s.Vault.Seal(raw, "firewall:geoip:source")
	var result sql.Result
	if base == 0 {
		result, err = tx.ExecContext(ctx, "INSERT INTO firewall_geoip(id,version,source,dataset,dataset_source,dataset_hash,updated_at) VALUES(1,1,?,?, '', '',0) ON CONFLICT(id) DO NOTHING", sealed, []byte{})
	} else {
		result, err = tx.ExecContext(ctx, "UPDATE firewall_geoip SET version=?,source=? WHERE id=1 AND version=?", base+1, sealed, base)
	}
	if err != nil {
		return out, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return out, err
	}
	if n != 1 {
		return out, fault.Conflict("GeoIP 配置已变化，请重新准备迁移")
	}
	return GeoIPConfig{Version: base + 1, Source: source}, nil
}
