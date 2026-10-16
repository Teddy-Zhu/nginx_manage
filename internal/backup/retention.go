package backup

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func boundedEntries(path string, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	items, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(items) > limit {
		return nil, errors.New("备份存储条目超过上限")
	}
	return items, nil
}
func (s *Service) lock(id string) *sync.RWMutex {
	value, _ := s.fileLocks.LoadOrStore(id, &sync.RWMutex{})
	return value.(*sync.RWMutex)
}
func (s *Service) removeArtifact(path string) error {
	f, info, err := openPrivate(path, ArchiveMax)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) || !secure.RootFileUnchanged(f, info) {
		return errors.New("备份文件身份已变化，停止清理")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
func (s *Service) checkBudget(ctx context.Context) error {
	if err := s.openStore(); err != nil {
		return err
	}
	items, err := boundedEntries(s.root(), MaxArchives+3)
	if err != nil {
		return err
	}
	var used int64
	count := 0
	for _, item := range items {
		if item.Name() == ".work" && item.IsDir() {
			continue
		}
		id := strings.TrimSuffix(item.Name(), ".tar.age")
		if id == item.Name() {
			id = strings.TrimSuffix(item.Name(), ".partial")
		}
		if !validID.MatchString(id) || !item.Type().IsRegular() {
			return errors.New("备份目录存在未知资源")
		}
		var known bool
		if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM backup_records WHERE task_id=?)", id).Scan(&known); err != nil {
			return err
		}
		if !known {
			return errors.New("备份文件缺少持久记录")
		}
		f, info, err := openPrivate(filepath.Join(s.root(), item.Name()), ArchiveMax)
		if err != nil {
			return err
		}
		f.Close()
		used += info.Size()
		count++
	}
	work, err := boundedEntries(filepath.Join(s.root(), ".work"), MaxRecords)
	if err != nil {
		return err
	}
	for _, item := range work {
		if !validID.MatchString(item.Name()) || !item.IsDir() {
			return errors.New("备份暂存目录包含未知资源")
		}
		dir := s.workspace(item.Name())
		if err = privateDir(dir); err != nil {
			return err
		}
		files, err := boundedEntries(dir, len(resources)+1)
		if err != nil {
			return err
		}
		for _, file := range files {
			limit := int64(0)
			if file.Name() == "manifest.json" {
				limit = 128 << 10
			}
			for _, resource := range resources {
				if file.Name() == resource.local {
					limit = resource.limit
				}
			}
			if limit == 0 {
				return errors.New("备份暂存包含未知文件")
			}
			f, info, err := openPrivate(filepath.Join(dir, file.Name()), limit)
			if err != nil {
				return err
			}
			f.Close()
			used += info.Size()
		}
	}
	var pages, size int64
	if err = s.DB.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return err
	}
	if err = s.DB.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return err
	}
	if size < 512 || size > 65536 || pages < 1 || pages > DatabaseMax/size {
		return fault.Conflict("业务数据库超过备份容量")
	}
	reserve := 2*pages*size + (16 << 20)
	if count >= MaxArchives || used+reserve > StoreMax {
		return fault.Conflict("备份存储已满，请先清理旧备份")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(s.root(), &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((reserve+(64<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return fault.Conflict("备份可用磁盘空间不足")
	}
	return nil
}

// Deletion intent is durable before unlink, and records/audit are retained.
func (s *Service) erase(ctx context.Context, r Record, actor, trace string) error {
	lock := s.lock(r.ID)
	if !lock.TryLock() {
		return fault.Conflict("备份正在下载，请稍后清理")
	}
	defer lock.Unlock()
	if r.DeletedAt != 0 {
		return nil
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE backup_records SET delete_started=1 WHERE task_id=?", r.ID); err != nil {
		return err
	}
	cleanupErr := removeWorkspace(s.workspace(r.ID))
	for _, path := range []string{s.archivePath(r.ID), s.partialPath(r.ID)} {
		cleanupErr = errors.Join(cleanupErr, s.removeArtifact(path))
	}
	if r.State != "succeeded" && r.State != "failed" && r.State != "cancelled" && r.State != "rolled_back" {
		released, err := s.release(ctx, r)
		if err != nil {
			return err
		}
		if !released {
			return fault.Conflict("原维护会话仍在释放，请稍后继续清理")
		}
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "UPDATE backup_records SET deleted_at=?,delete_started=0 WHERE task_id=?", now, r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state=CASE WHEN state IN('succeeded','failed','cancelled','rolled_back') THEN state ELSE 'failed' END,stage='deleted',updated_at=? WHERE id=?", now, r.ID); err != nil {
		return err
	}
	if err = audit(ctx, tx, actor, trace, r.ID, "backup.delete", "deleted"); err != nil {
		return err
	}
	delete(s.passwords, r.ID)
	return tx.Commit()
}
func (s *Service) Delete(ctx context.Context, p auth.Principal, trace, id string) (Record, error) {
	if err := p.Require("backup.export", "system.write"); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.Get(ctx, p, id)
	if err != nil {
		return r, err
	}
	if r.State != "succeeded" && r.State != "failed" && r.State != "rolled_back" && r.State != "cancelled" && r.Stage != "cleanup_failed" {
		return r, fault.Conflict("备份仍在处理，不能删除")
	}
	if err = s.erase(ctx, r, p.ID, trace); err != nil {
		return r, err
	}
	return s.get(ctx, id)
}
func (s *Service) cleanup(ctx context.Context) error {
	policy, err := s.policy(ctx)
	if err != nil {
		return err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+recordColumns+recordJoin+"WHERE b.deleted_at IS NULL AND (t.state IN('succeeded','failed','rolled_back','cancelled') OR b.delete_started=1) ORDER BY t.created_at DESC,t.id DESC LIMIT ?", MaxRecords)
	if err != nil {
		return err
	}
	var records []Record
	for rows.Next() {
		r, e := s.read(rows)
		if e != nil {
			rows.Close()
			return e
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	kept := 0
	for _, r := range records {
		if r.State == "succeeded" && r.Stage == "ready" {
			kept++
		}
		if r.deleting || r.State == "succeeded" && (r.ExpiresAt <= now || r.CapturedAt+policy.RetentionDays*86400 <= now || kept > policy.KeepCount) {
			if err = s.erase(ctx, r, "backup-retention", secure.ID()); err != nil {
				var conflict *fault.Error
				if !errors.As(err, &conflict) || conflict.Status != 409 {
					return err
				}
			}
		}
	}
	items, err := boundedEntries(filepath.Join(s.root(), ".work"), MaxRecords)
	if err != nil {
		return err
	}
	for _, item := range items {
		if !validID.MatchString(item.Name()) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return errors.New("备份暂存存在未知目录")
		}
		r, err := s.get(ctx, item.Name())
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) || r.CreatedAt+WorkspaceLifetime <= now || r.State == "failed" || r.State == "succeeded" || r.DeletedAt != 0 {
			if err = removeWorkspace(s.workspace(item.Name())); err != nil {
				return err
			}
		}
	}
	_, err = s.DB.ExecContext(ctx, "DELETE FROM backup_downloads WHERE expires_at<=? OR used_at IS NOT NULL", now)
	return err
}
