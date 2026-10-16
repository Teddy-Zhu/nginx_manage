package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func restorePublicationRoot(data string) string {
	return filepath.Join(data, "agent", "disaster-configs")
}

func restorePublicationPath(data, id string) string {
	return filepath.Join(restorePublicationRoot(data), id, "panel.db")
}

func publicationEntries(dir string) ([]os.DirEntry, int64, error) {
	if err := privateAdoptionDirectory(dir, false); err != nil {
		return nil, 0, err
	}
	items, err := boundedEntries(dir, 4)
	if err != nil {
		return nil, 0, err
	}
	var size int64
	for _, item := range items {
		limit := DatabaseMax
		if item.Name() == "publication.json" || item.Name() == ".json-copy" {
			limit = adoptionRecordMax
		} else if item.Name() != "panel.db" && item.Name() != ".copy" {
			return nil, 0, errors.New("恢复发布存储包含未知文件")
		}
		f, stat, e := secure.OpenRootFile(filepath.Join(dir, item.Name()), limit)
		if e != nil {
			return nil, 0, e
		}
		f.Close()
		if stat.Mode().Perm() != 0400 && ((item.Name() != ".copy" && item.Name() != ".json-copy") || stat.Mode().Perm() != 0600) {
			return nil, 0, errors.New("恢复发布存储的文件权限无效")
		}
		size += stat.Size()
	}
	return items, size, nil
}

type restorationPublicationReceipt struct {
	OperationID       string             `json:"operation_id"`
	PreparationSHA256 string             `json:"preparation_sha256"`
	Publication       RestorePublication `json:"publication"`
}

func freezeRestorationPublication(ctx context.Context, data string, p RestorePublication, intent AdoptionIntent) error {
	if err := p.validate(intent.Preparation); err != nil {
		return err
	}
	root := restorePublicationRoot(data)
	if err := privateAdoptionDirectory(root, true); err != nil {
		return err
	}
	items, err := boundedEntries(root, AdoptionRecordMax)
	if err != nil {
		return err
	}
	found := false
	active := 0
	var used int64
	for _, item := range items {
		id := strings.TrimPrefix(strings.TrimPrefix(item.Name(), ".cleaning-"), ".cleaned-")
		if !validID.MatchString(id) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return errors.New("恢复发布存储存在未知资源")
		}
		_, size, e := publicationEntries(filepath.Join(root, item.Name()))
		if e != nil {
			return e
		}
		used += size
		found = found || item.Name() == p.RevisionID
		if !strings.HasPrefix(item.Name(), ".cleaned-") {
			active++
		}
		if id == p.RevisionID && item.Name() != id {
			return errors.New("原恢复计划副本已进入清理，须使用新计划标识")
		}
	}
	if !found && (active >= AdoptionMax || len(items) >= AdoptionRecordMax) || used+p.File.Size > StoreMax {
		return errors.New("恢复发布副本达到数量或容量上限，请先清理未被安装事务占用的副本")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(root, &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((p.File.Size+(32<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return errors.New("恢复发布固定副本的磁盘余量不足")
	}
	dir := filepath.Join(root, p.RevisionID)
	if err = privateAdoptionDirectory(dir, true); err != nil {
		return err
	}
	receipt := restorationPublicationReceipt{OperationID: intent.Preparation.OperationID, PreparationSHA256: intent.PreparationSHA256, Publication: p}
	var existing restorationPublicationReceipt
	receiptPath := filepath.Join(dir, "publication.json")
	if e := readAdoptionJSON(receiptPath, &existing); e == nil {
		if !sameAdoptionValue(existing, receipt) {
			return errors.New("原计划已有不同发布副本，须先清理并使用新计划标识")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else if err = writeAdoptionJSON(receiptPath, receipt); err != nil {
		return err
	}
	target := restorePublicationPath(data, p.RevisionID)
	if err = hashAdoptionFile(ctx, target, p.File); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, parent := range []string{filepath.Join(data, "staging"), filepath.Dir(restorePublicationWork(data, p.RevisionID)), restorePublicationWork(data, p.RevisionID)} {
		info, e := os.Lstat(parent)
		if e != nil {
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != intent.UID || int(st.Gid) != intent.GID || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return errors.New("恢复发布暂存目录归属无效")
		}
	}
	path := filepath.Join(restorePublicationWork(data, p.RevisionID), "panel.db")
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), path)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != intent.UID || int(st.Gid) != intent.GID || st.Nlink != 1 || info.Size() != p.File.Size {
		return errors.New("恢复发布暂存文件身份无效")
	}
	scratch := filepath.Join(dir, ".copy")
	if err = os.Remove(scratch); err != nil && !os.IsNotExist(err) {
		return err
	}
	dst, err := os.OpenFile(scratch, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer dst.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hash), contextReader{ctx, io.LimitReader(source, p.File.Size+1)})
	if err != nil {
		return err
	}
	if n != p.File.Size || hex.EncodeToString(hash.Sum(nil)) != p.File.SHA256 || !secure.RootFileUnchanged(source, info) {
		return errors.New("恢复发布副本与助手报告摘要不一致")
	}
	if err = dst.Chmod(0400); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return errors.Join(syncDir(dir), syncDir(root))
}

func restorationPlanStatus(data string, p RestorePlan) (out RestorePlanStatus, err error) {
	out = RestorePlanStatus{Plan: p, Expired: p.ExpiresAt <= time.Now().Unix()}
	if p.Preview.Publication == nil {
		return out, nil
	}
	f, info, err := secure.OpenRootFile(restorePublicationPath(data, p.ID), DatabaseMax)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	f.Close()
	if info.Mode().Perm() != 0400 || info.Size() != p.Preview.Publication.File.Size {
		return out, errors.New("恢复发布副本的权限或大小与原计划不一致")
	}
	out.PublicationAvailable = true
	return out, nil
}

// CleanupRestorePlan preserves both the approval and the publication receipt.
// An installed or orphaned intent must be compensated before its copy is removed.
func CleanupRestorePlan(ctx context.Context, data, id string) error {
	if !validID.MatchString(id) {
		return errors.New("恢复计划清理标识无效")
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return err
	}
	defer unlock()
	root := restorePublicationRoot(data)
	if err = privateAdoptionDirectory(root, true); err != nil {
		return err
	}
	dir := filepath.Join(root, id)
	cleaning, cleaned := filepath.Join(root, ".cleaning-"+id), filepath.Join(root, ".cleaned-"+id)
	phases := 0
	for _, path := range []string{dir, cleaning, cleaned} {
		if _, e := os.Lstat(path); e == nil {
			phases++
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	if phases > 1 {
		return errors.New("恢复发布副本存在冲突的清理阶段")
	}
	if _, e := os.Lstat(cleaned); e == nil {
		items, _, e := publicationEntries(cleaned)
		if e != nil {
			return e
		}
		if len(items) != 1 || items[0].Name() != "publication.json" {
			return errors.New("已清理恢复副本仍含额外材料")
		}
		return cleanupRestorationHelper(ctx, data, id)
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, e := os.Lstat(cleaning); e == nil {
		dir = cleaning
	} else if !os.IsNotExist(e) {
		return e
	}
	items, _, err := publicationEntries(dir)
	if os.IsNotExist(err) {
		return cleanupRestorationHelper(ctx, data, id)
	}
	if err != nil {
		return err
	}
	var receipt restorationPublicationReceipt
	err = readAdoptionJSON(filepath.Join(dir, "publication.json"), &receipt)
	onlyScratch := true
	for _, item := range items {
		if item.Name() != ".json-copy" {
			onlyScratch = false
		}
	}
	if os.IsNotExist(err) && onlyScratch {
		for _, item := range items {
			if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
				return err
			}
		}
		if err = os.Remove(dir); err != nil {
			return err
		}
		return errors.Join(syncDir(root), cleanupRestorationHelper(ctx, data, id))
	}
	if err != nil {
		return err
	}
	if !validID.MatchString(receipt.OperationID) || receipt.Publication.RevisionID != id || !validHash.MatchString(receipt.PreparationSHA256) {
		return errors.New("恢复发布清理缺少原接入身份")
	}
	if err = adoptionRestoreSettled(data, receipt.OperationID); err != nil {
		return err
	}
	if dir != cleaning {
		if err = unix.Renameat2(unix.AT_FDCWD, dir, unix.AT_FDCWD, cleaning, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = syncDir(root); err != nil {
			return err
		}
		dir = cleaning
	}
	for _, item := range items {
		if item.Name() == "publication.json" {
			continue
		}
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
	}
	if err = syncDir(dir); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, dir, unix.AT_FDCWD, cleaned, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return errors.Join(syncDir(root), cleanupRestorationHelper(ctx, data, id))
}

func cleanupRestorationHelper(ctx context.Context, data, id string) error {
	var result struct {
		OperationID string `json:"operation_id"`
		Cleaned     bool   `json:"cleaned"`
	}
	if err := runPreparationHelper(ctx, data, "backup-restore-plan-cleanup-data", id, nil, nil, &result); err != nil {
		return err
	}
	if result.OperationID != id || !result.Cleaned {
		return errors.New("恢复发布助手没有确认原计划暂存清理")
	}
	return nil
}
