package backup

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) policy(ctx context.Context) (Policy, error) {
	var p Policy
	err := s.DB.QueryRowContext(ctx, `SELECT p.version,m.enabled,p.recipient,p.key_saved_at,p.interval_hours,p.keep_count,p.retention_days,p.authorization_until,p.next_run_at,p.last_error,p.updated_at,p.principal,p.issuer_machine,p.issuer_epoch FROM backup_policy p JOIN module_settings m ON m.id='automatic-backups' WHERE p.id=1`).Scan(&p.Version, &p.Enabled, &p.Recipient, &p.KeySavedAt, &p.IntervalHours, &p.KeepCount, &p.RetentionDays, &p.AuthorizationUntil, &p.NextRunAt, &p.Error, &p.UpdatedAt, &p.principal, &p.machine, &p.epoch)
	return p, err
}
func (s *Service) Policy(ctx context.Context, p auth.Principal) (Policy, error) {
	if err := p.Require("backup.export"); err != nil {
		return Policy{}, err
	}
	return s.policy(ctx)
}
func (s *Service) SetPolicy(ctx context.Context, p auth.Principal, trace string, in PolicyInput) (Policy, error) {
	if err := p.Require("system.write", "backup.export", "backup.secrets"); err != nil {
		return Policy{}, err
	}
	if err := in.Validate(); err != nil {
		return Policy{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()
	until := in.AuthorizationUntil
	if !in.Enabled {
		until = 0
	}
	if _, err = checkIssuer(ctx, tx, p.ID, p.Machine, p.SessionEpoch, until); err != nil {
		return Policy{}, fault.Conflict("定期备份授权已失效或超过凭据有效期")
	}
	now := time.Now().Unix()
	saved := int64(0)
	if in.Recipient != "" && in.KeySaved {
		saved = now
	}
	result, err := tx.ExecContext(ctx, `UPDATE backup_policy SET version=version+1,recipient=?,key_saved_at=?,interval_hours=?,keep_count=?,retention_days=?,principal=?,issuer_machine=?,issuer_epoch=?,authorization_until=?,next_run_at=?,last_error='',updated_at=? WHERE id=1 AND version=?`, in.Recipient, saved, in.IntervalHours, in.KeepCount, in.RetentionDays, p.ID, p.Machine, p.SessionEpoch, until, now+in.IntervalHours*3600, now, in.BaseVersion)
	if err != nil {
		return Policy{}, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return Policy{}, fault.Conflict("备份设置版本已变化，请刷新")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE module_settings SET enabled=?,version=version+1 WHERE id='automatic-backups'", in.Enabled); err != nil {
		return Policy{}, err
	}
	if err = audit(ctx, tx, p.ID, trace, "policy", "backup.policy", "saved"); err != nil {
		return Policy{}, err
	}
	if err = tx.Commit(); err != nil {
		return Policy{}, err
	}
	return s.policy(ctx)
}
func (s *Service) scheduled(ctx context.Context) error {
	p, err := s.policy(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if !p.Enabled || p.NextRunAt > now {
		return nil
	}
	view := s.Maintenance.View()
	if view.Phase != "open" {
		return nil
	}
	var active bool
	if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM tasks WHERE kind='backup.create' AND state NOT IN('succeeded','failed','rolled_back','cancelled'))").Scan(&active); err != nil || active {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	reason := ""
	if p.KeySavedAt == 0 || recipientValid(p.Recipient) != nil {
		reason = "恢复接收方未完成确认"
	} else if p.AuthorizationUntil <= now {
		reason = "定期备份授权已到期，请重新确认"
	} else if _, err = checkIssuer(ctx, tx, p.principal, p.machine, p.epoch, p.AuthorizationUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, auth.ErrForbidden) {
			reason = "原定期备份授权已撤销或会话代次已变化，请重新授权"
		} else {
			return err
		}
	}
	if reason != "" {
		if _, err = tx.ExecContext(ctx, "UPDATE backup_policy SET last_error=?,next_run_at=?,updated_at=? WHERE id=1 AND version=?", reason, now+3600, now, p.Version); err != nil {
			return err
		}
		// A failed task feeds the existing bounded backup.failure notification
		// stream once per policy approval, rather than on every scheduler tick.
		id := ""
		if err = tx.QueryRowContext(ctx, "SELECT b.task_id FROM backup_records b JOIN tasks t ON t.id=b.task_id WHERE b.policy_version=? AND t.stage='authorization_expired' LIMIT 1", p.Version).Scan(&id); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			id = secure.ID()
			if err = s.insert(ctx, tx, id, p.principal, p.machine, p.epoch, secure.ID(), "定期备份授权检查", "recipient", p.Recipient, now, p.Version, p.RetentionDays); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state='failed',stage='authorization_expired',last_error=?,updated_at=? WHERE id=?", reason, now, id); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	id := secure.ID()
	until := min(p.AuthorizationUntil, now+600)
	if err = s.insert(ctx, tx, id, p.principal, p.machine, p.epoch, secure.ID(), "定期备份", "recipient", p.Recipient, until, p.Version, p.RetentionDays); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE backup_policy SET next_run_at=?,last_error='',updated_at=? WHERE id=1 AND version=?", now+p.IntervalHours*3600, now, p.Version); err != nil {
		return err
	}
	return tx.Commit()
}
