package migration

import (
	"context"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

func (s *Service) Preflight(ctx context.Context, p auth.Principal, requestID, id string) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"); err != nil {
		return Plan{}, err
	}
	if !validTransferID(id) {
		return Plan{}, fault.Invalid("迁移标识无效")
	}
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移正在处理")
	}
	defer s.mu.Unlock()
	st, err := s.load(ctx, p, id)
	if err != nil {
		return Plan{}, err
	}
	if st.Plan.State != "planned" || st.Plan.ExpiresAt <= time.Now().Unix() {
		return Plan{}, fault.Conflict("仅有效的待执行迁移可以重新预检")
	}
	if err = s.inspect(ctx, &st); err != nil {
		return Plan{}, err
	}
	summary, err := encodeSummary(st.Plan)
	if err != nil {
		return Plan{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE migration_plans SET summary=?,updated_at=? WHERE id=? AND state='planned'", s.Vault.Seal(summary, "migration-summary:"+id), time.Now().Unix(), id)
	if err != nil {
		return Plan{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Plan{}, err
	}
	if n != 1 {
		return Plan{}, fault.Conflict("迁移状态已变化")
	}
	if err = pushAudit(ctx, tx, p.ID, requestID, id, "migration.preflight", "planned"); err != nil {
		return Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		return Plan{}, err
	}
	return s.Get(ctx, p, id)
}
