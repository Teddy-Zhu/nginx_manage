package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/maintenance"
)

func (s *Service) stage(ctx context.Context, r Record, state, stage, message string) error {
	_, err := s.DB.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,updated_at=? WHERE id=?", state, stage, message, time.Now().Unix(), r.ID)
	return err
}
func (s *Service) Run(ctx context.Context) error {
	if err := s.openStore(); err != nil {
		return err
	}
	// A captured manifest may be resumed, but an interrupted SQLite capture or
	// encryption has no completion receipt. Never adopt their partial outputs.
	if _, err := s.DB.ExecContext(ctx, "UPDATE tasks SET state='running',stage='release_failed',last_error='备份进程中断，未完成的快照或加密已停止',updated_at=? WHERE kind='backup.create' AND state NOT IN('succeeded','failed','rolled_back','cancelled') AND stage IN('capturing','encrypting')", time.Now().Unix()); err != nil {
		return err
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	reported := false
	nextPolicy := time.Time{}
	nextCleanup := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		s.mu.Lock()
		call, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := s.next(call)
		cancel()
		if err == nil && time.Now().After(nextCleanup) {
			call, cancel = context.WithTimeout(ctx, 30*time.Second)
			err = s.cleanup(call)
			cancel()
			nextCleanup = time.Now().Add(time.Minute)
		}
		if err == nil && time.Now().After(nextPolicy) {
			call, cancel = context.WithTimeout(ctx, 10*time.Second)
			err = s.scheduled(call)
			cancel()
			nextPolicy = time.Now().Add(30 * time.Second)
		}
		s.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			if !reported {
				slog.Warn("完整备份协调失败", "error", err)
			}
			reported = true
		} else if err == nil {
			reported = false
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func (s *Service) authorized(ctx context.Context, r Record) (auth.Principal, error) {
	if r.until <= time.Now().Unix() || r.CreatedAt+WorkspaceLifetime <= time.Now().Unix() {
		return auth.Principal{}, auth.ErrForbidden
	}
	p, err := checkIssuer(ctx, s.DB, r.principal, r.machine, r.epoch, r.until)
	if err != nil {
		return p, err
	}
	if r.Scheduled {
		policy, err := s.policy(ctx)
		if err != nil {
			return p, err
		}
		if !policy.Enabled || policy.Version != r.policyVersion || policy.AuthorizationUntil < r.until || policy.Recipient != r.Recipient {
			return p, auth.ErrForbidden
		}
	}
	return p, nil
}
func (s *Service) next(ctx context.Context) error {
	r, err := s.read(s.DB.QueryRowContext(ctx, "SELECT "+recordColumns+recordJoin+"WHERE t.state NOT IN('succeeded','failed','rolled_back','cancelled') ORDER BY t.created_at,t.id LIMIT 1"))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Stage == "cleanup_failed" {
		return nil
	}
	if r.Stage == "release_failed" {
		return s.abort(ctx, r)
	}
	if r.Stage == "capturing" || r.Stage == "encrypting" {
		if err = s.stage(ctx, r, "running", "release_failed", "备份完成回执缺失，未发布部分文件"); err != nil {
			return err
		}
		return s.abort(ctx, r)
	}
	p, err := s.authorized(ctx, r)
	if err != nil {
		if !errors.Is(err, auth.ErrForbidden) && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err = s.stage(ctx, r, "running", "release_failed", "原备份授权已失效或已过期"); err != nil {
			return err
		}
		return s.abort(ctx, r)
	}
	if r.Encryption == "passphrase" && r.Stage != "publishing" && s.passwords[r.ID] == "" {
		if err = s.stage(ctx, r, "running", "release_failed", "手动口令未保留，原备份已停止；请重新创建备份"); err != nil {
			return err
		}
		return s.abort(ctx, r)
	}
	if r.MaintenanceID == "" {
		_, err = s.Maintenance.StartLinked(ctx, p, r.requestID, "backup-maintenance:"+r.ID, maintenance.StartInput{DrainSeconds: 120}, r.ID, func(tx *sql.Tx, session maintenance.Session) error {
			_, err := tx.ExecContext(ctx, "UPDATE backup_records SET maintenance_id=? WHERE task_id=? AND maintenance_id IS NULL", session.TaskID, r.ID)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='draining',updated_at=? WHERE id=?", time.Now().Unix(), r.ID)
			return err
		})
		var known *fault.Error
		if errors.As(err, &known) && known.Status == 409 {
			if s.Maintenance.View().Phase != "open" {
				return nil
			}
			if err = s.stage(ctx, r, "running", "release_failed", known.Message); err != nil {
				return err
			}
			return s.abort(ctx, r)
		}
		return err
	}
	if r.Stage == "queued" || r.Stage == "draining" {
		var phase string
		if err = s.DB.QueryRowContext(ctx, "SELECT phase FROM maintenance_sessions WHERE task_id=?", r.MaintenanceID).Scan(&phase); err != nil {
			return err
		}
		if phase == "failed" || phase == "released" {
			if err = s.stage(ctx, r, "running", "release_failed", "原维护会话未获得一致性捕获边界"); err != nil {
				return err
			}
			return s.abort(ctx, r)
		}
		if phase != "held" {
			return nil
		}
		return s.captureHeld(ctx, r)
	}
	if r.Stage == "releasing" {
		ready, err := s.release(ctx, r)
		if err != nil || !ready {
			return err
		}
		if r.manifest == nil {
			return s.stage(ctx, r, "recovery_required", "cleanup_failed", "已捕获备份缺少原清单，须本机核对")
		}
		if err = s.stage(ctx, r, "running", "encrypting", ""); err != nil {
			return err
		}
		var recipient age.Recipient
		if r.Encryption == "recipient" {
			recipient, err = age.ParseX25519Recipient(r.Recipient)
		} else {
			recipient, err = age.NewScryptRecipient(s.passwords[r.ID])
		}
		if err != nil {
			return err
		}
		result, err := encodeArchive(ctx, s.workspace(r.ID), s.partialPath(r.ID), *r.manifest, recipient)
		delete(s.passwords, r.ID)
		if err != nil {
			slog.Warn("完整备份加密失败", "backup_id", r.ID, "error", err)
			if e := s.stage(ctx, r, "running", "release_failed", "备份加密未完成，未发布部分文件"); e != nil {
				return e
			}
			return s.abort(ctx, r)
		}
		// The expected artifact identity is durable before rename/publication.
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, "UPDATE backup_records SET archive_size=?,archive_sha256=? WHERE task_id=?", result.Size, result.SHA256, r.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE tasks SET stage='publishing',updated_at=? WHERE id=?", time.Now().Unix(), r.ID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if r.Stage == "publishing" {
		return s.publish(ctx, r)
	}
	return s.stage(ctx, r, "recovery_required", "cleanup_failed", "备份任务存在未知阶段，须本机核对")
}
func (s *Service) captureHeld(ctx context.Context, r Record) error {
	_, release, err := s.Maintenance.Held(r.MaintenanceID)
	if err != nil {
		return nil
	}
	defer release()
	if err = s.checkBudget(ctx); err != nil {
		slog.Warn("完整备份存储检查失败", "backup_id", r.ID, "error", err)
		return s.stage(ctx, r, "running", "release_failed", "备份容量不足或存储目录需要维护")
	}
	if err = s.stage(ctx, r, "running", "capturing", ""); err != nil {
		return err
	}
	m, err := s.capture(ctx, r.ID)
	if err != nil {
		slog.Warn("完整备份捕获失败", "backup_id", r.ID, "error", err)
		return s.stage(ctx, r, "running", "release_failed", "一致性快照未完成，请检查数据、密钥或存储状态")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE backup_records SET manifest=?,captured_at=? WHERE task_id=?", s.Vault.Seal(raw, "backup-manifest:"+r.ID), m.CreatedAt, r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET stage='releasing',updated_at=? WHERE id=?", time.Now().Unix(), r.ID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) release(ctx context.Context, r Record) (bool, error) {
	if r.MaintenanceID == "" {
		return true, nil
	}
	var phase string
	if err := s.DB.QueryRowContext(ctx, "SELECT phase FROM maintenance_sessions WHERE task_id=?", r.MaintenanceID).Scan(&phase); err != nil {
		return false, err
	}
	if phase == "released" || phase == "failed" {
		return true, nil
	}
	if phase == "releasing" {
		return false, nil
	}
	// Cleanup can only release the already linked session. Revoking the issuer
	// must stop new capture without preventing release of its existing lock.
	_, err := s.Maintenance.Release(ctx, auth.Principal{ID: r.principal, Scopes: []string{"system.write"}}, r.requestID, r.MaintenanceID)
	var known *fault.Error
	if errors.As(err, &known) && known.Status == 409 {
		return false, nil
	}
	return false, err
}
func (s *Service) abort(ctx context.Context, r Record) error {
	delete(s.passwords, r.ID)
	cleanupErr := removeWorkspace(s.workspace(r.ID))
	for _, path := range []string{s.partialPath(r.ID), s.archivePath(r.ID)} {
		cleanupErr = errors.Join(cleanupErr, s.removeArtifact(path))
	}
	released, err := s.release(ctx, r)
	if err != nil || !released {
		return err
	}
	if cleanupErr != nil {
		slog.Warn("完整备份暂存清理失败", "backup_id", r.ID, "error", cleanupErr)
		return s.stage(ctx, r, "recovery_required", "cleanup_failed", "未发布备份或暂存清理失败，须恢复存储后继续清理")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state='failed',stage='failed',updated_at=? WHERE id=?", now, r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE backup_records SET finished_at=?,archive_size=0,archive_sha256='' WHERE task_id=?", now, r.ID); err != nil {
		return err
	}
	if err = audit(ctx, tx, r.principal, r.requestID, r.ID, "backup.create", "failed"); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) partialPath(id string) string { return filepath.Join(s.root(), id+".partial") }
func (s *Service) publish(ctx context.Context, r Record) error {
	if r.ArchiveSize < 1 || r.ArchiveSize > ArchiveMax || !validHash.MatchString(r.ArchiveSHA256) {
		return s.stage(ctx, r, "recovery_required", "cleanup_failed", "备份发布缺少持久的文件身份")
	}
	path := s.archivePath(r.ID)
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		path = s.partialPath(r.ID)
	} else if err != nil {
		return err
	}
	file, err := digestFile(ctx, path, ArchiveMax)
	if err != nil {
		return err
	}
	if file.Size != r.ArchiveSize || file.SHA256 != r.ArchiveSHA256 {
		return s.stage(ctx, r, "recovery_required", "cleanup_failed", "待发布备份文件已偏离原身份")
	}
	if err = removeWorkspace(s.workspace(r.ID)); err != nil {
		return s.stage(ctx, r, "recovery_required", "cleanup_failed", "备份加密已完成，暂存清理失败，未发布")
	}
	if path == s.partialPath(r.ID) {
		if err = os.Rename(path, s.archivePath(r.ID)); err != nil {
			return err
		}
		if err = syncDir(s.root()); err != nil {
			return err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state='succeeded',stage='ready',last_error='',updated_at=? WHERE id=?", now, r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE backup_records SET finished_at=? WHERE task_id=?", now, r.ID); err != nil {
		return err
	}
	if err = audit(ctx, tx, r.principal, r.requestID, r.ID, "backup.create", "ready"); err != nil {
		return err
	}
	return tx.Commit()
}
