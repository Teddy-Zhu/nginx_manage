package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func adoptionCheckDirectory(data, id string) (string, error) {
	if _, err := panelruntime.Root(data); err != nil {
		return "", err
	}
	if !validID.MatchString(id) {
		return "", errors.New("恢复核对目录标识无效")
	}
	return filepath.Join(data, "run", "disaster-check", id), nil
}

// SQLite resolves database paths before opening them. A fixed root-owned,
// group-readable projection gives the helper a stable immutable path without
// opening the private root receipt store to the panel account.
func prepareAdoptionCheck(ctx context.Context, data, id, source string, intent AdoptionIntent) error {
	if os.Geteuid() != 0 {
		return errors.New("恢复核对投影须由 root 准备")
	}
	dir, err := adoptionCheckDirectory(data, id)
	if err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	if err = secure.RootDirectory(parent, 0711); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0711 {
		return errors.New("恢复核对父目录权限无效")
	}
	if err = cleanupAdoptionCheck(data, id, intent.GID); err != nil {
		return err
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(parent, &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((intent.Preparation.Files[0].Size+(32<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return errors.New("恢复核对数据库投影的磁盘余量不足")
	}
	items, err := boundedEntries(parent, AdoptionMax)
	if err != nil {
		return err
	}
	for _, item := range items {
		if !validID.MatchString(item.Name()) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return errors.New("恢复核对目录存在未知资源")
		}
	}
	if len(items) >= AdoptionMax {
		return errors.New("恢复核对目录达到保留上限")
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err = os.Chown(dir, 0, intent.GID); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0710); err != nil {
		return err
	}
	if err = syncDir(parent); err != nil {
		return err
	}
	expected := intent.Preparation.Files[0]
	src, stat, err := secure.OpenRootFile(source, expected.Size)
	if err != nil {
		return err
	}
	defer src.Close()
	if stat.Mode().Perm() != 0400 || stat.Size() != expected.Size {
		return errors.New("恢复核对数据库来源尚未固定")
	}
	scratch := filepath.Join(dir, ".copy")
	dst, err := os.OpenFile(scratch, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer dst.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hash), contextReader{ctx, io.LimitReader(src, expected.Size+1)})
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 || !secure.RootFileUnchanged(src, stat) {
		return errors.New("恢复核对数据库来源与批准摘要不一致")
	}
	if err = dst.Chown(0, intent.GID); err != nil {
		return err
	}
	if err = dst.Chmod(0440); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, filepath.Join(dir, "panel.db"), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}

func openAdoptionCheck(data, id string, gid int, expected File) (*os.File, os.FileInfo, error) {
	dir, err := adoptionCheckDirectory(data, id)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || int(st.Gid) != gid || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0710 {
		return nil, nil, errors.New("恢复核对数据库目录不是固定 root 只读边界")
	}
	f, info, err := secure.OpenRootFile(filepath.Join(dir, "panel.db"), expected.Size)
	if err != nil {
		return nil, nil, err
	}
	st, ok = info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Gid) != gid || info.Mode().Perm() != 0440 || info.Size() != expected.Size {
		f.Close()
		return nil, nil, errors.New("恢复核对数据库投影身份无效")
	}
	return f, info, nil
}

func cleanupAdoptionCheck(data, id string, gid int) error {
	if os.Geteuid() != 0 {
		return errors.New("恢复核对投影清理需要 root")
	}
	dir, err := adoptionCheckDirectory(data, id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	// Creation may have stopped before chown/chmod. Both forms are root-only
	// writers; no panel-owned directory is accepted for recursive cleanup.
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 && (info.Mode().Perm() != 0710 || int(st.Gid) != gid) {
		return errors.New("恢复核对投影目录归属已变化")
	}
	items, err := boundedEntries(dir, 2)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Name() != "panel.db" && item.Name() != ".copy" {
			return errors.New("恢复核对投影含未知资源")
		}
		f, info, err := secure.OpenRootFile(filepath.Join(dir, item.Name()), DatabaseMax)
		if err != nil {
			return err
		}
		f.Close()
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0440 || info.Mode().Perm() == 0440 && int(st.Gid) != gid {
			return errors.New("恢复核对投影文件权限无效")
		}
	}
	for _, item := range items {
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}
