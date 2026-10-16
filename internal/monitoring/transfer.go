package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"nginxpanel/internal/fault"
)

type SettingsReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) ReadSettings(ctx context.Context, q SettingsReader) (SettingsView, error) {
	var out SettingsView
	var raw string
	if err := q.QueryRowContext(ctx, "SELECT version,settings FROM monitoring_settings WHERE id=1").Scan(&out.Version, &raw); err != nil {
		return out, err
	}
	if out.Version < 1 || len(raw) > 4096 {
		return out, fault.Unavailable("监控配置版本或内容无效")
	}
	if err := json.Unmarshal([]byte(raw), &out.Settings); err != nil {
		return out, err
	}
	return out, out.Settings.Validate()
}

// StoreSettings participates in the caller's import or compensation transaction.
// Runtime samples, alert state and module activation remain local to the node.
func (s *Service) StoreSettings(ctx context.Context, tx *sql.Tx, base int64, settings Settings) (SettingsView, error) {
	if base < 1 || base == math.MaxInt64 {
		return SettingsView{}, fault.Invalid("监控配置版本无效或达到上限")
	}
	if err := settings.Validate(); err != nil {
		return SettingsView{}, err
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return SettingsView{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE monitoring_settings SET settings=?,version=version+1 WHERE id=1 AND version=?", string(raw), base)
	if err != nil {
		return SettingsView{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return SettingsView{}, err
	}
	if n != 1 {
		return SettingsView{}, fault.Conflict("监控配置已更新，请刷新后重试")
	}
	return SettingsView{Version: base + 1, Settings: settings}, nil
}
