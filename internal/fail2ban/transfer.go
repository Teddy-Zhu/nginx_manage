package fail2ban

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"nginxpanel/internal/fault"
	"time"
)

type Transfer struct {
	Jails []DesiredJail `json:"jails"`
}

func ValidateTransfer(value *Transfer) error {
	if value == nil {
		return nil
	}
	_, err := (Policy{Jails: value.Jails}).Normalize()
	return err
}
func (s *PolicyService) Export(ctx context.Context, q PolicyReader) (*Transfer, error) {
	view, err := s.ReadPolicy(ctx, q)
	if err != nil {
		return nil, err
	}
	return &Transfer{Jails: view.Policy.Jails}, nil
}

// StorePolicy participates in the caller's configuration transaction. The new
// generation also invalidates stale clients when compensating to an old value.
// Callers own authorization, idempotency, migration admission and audit records.
func (s *PolicyService) StorePolicy(ctx context.Context, tx *sql.Tx, base int64, policy Policy) (PolicyView, error) {
	var out PolicyView
	if base < 0 || base == math.MaxInt64 {
		return out, fault.Invalid("Fail2ban jail 配置版本无效")
	}
	normalized, err := policy.Normalize()
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return out, err
	}
	out = PolicyView{Version: base + 1, Policy: normalized, UpdatedAt: time.Now().Unix()}
	sealed := s.Vault.Seal(raw, policyAAD(out.Version))
	var result sql.Result
	if base == 0 {
		result, err = tx.ExecContext(ctx, "INSERT INTO fail2ban_policy(id,version,payload,updated_at) VALUES(1,?,?,?) ON CONFLICT(id) DO NOTHING", out.Version, sealed, out.UpdatedAt)
	} else {
		result, err = tx.ExecContext(ctx, "UPDATE fail2ban_policy SET version=?,payload=?,updated_at=? WHERE id=1 AND version=?", out.Version, sealed, out.UpdatedAt, base)
	}
	if err != nil {
		return PolicyView{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return PolicyView{}, err
	}
	if n != 1 {
		return PolicyView{}, fault.Conflict("Fail2ban jail 配置已更新，请重新预检或读取")
	}
	return out, nil
}
func (s *PolicyService) migrationIdle(ctx context.Context, q PolicyReader) error {
	var pending int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required')").Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return fault.Conflict("配置迁移正在应用或等待恢复，暂不能修改 Fail2ban jail 配置")
	}
	return nil
}
