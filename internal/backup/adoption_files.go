package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func adoptionRoot(data string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("恢复接入存储仅供本机 root 使用")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return "", err
	}
	return filepath.Join(data, "agent", "disaster-recovery"), nil
}
func adoptionDirectory(data, id string, partial bool) (string, error) {
	if !validID.MatchString(id) {
		return "", errors.New("恢复接入操作标识无效")
	}
	root, err := adoptionRoot(data)
	if err != nil {
		return "", err
	}
	if partial {
		id = ".adopting-" + id
	}
	return filepath.Join(root, id), nil
}
func privateAdoptionDirectory(path string, create bool) error {
	if create {
		if err := secure.RootDirectory(path, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("恢复接入目录须为 root 专用的 0700 目录")
	}
	return nil
}
func lockAdoptionStore(data string, create bool) (func(), string, error) {
	root, err := adoptionRoot(data)
	if err != nil {
		return nil, "", err
	}
	if err = privateAdoptionDirectory(root, create); err != nil {
		return nil, "", err
	}
	name := filepath.Join(root, ".lock")
	if create {
		fd, err := unix.Open(name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err == nil {
			f := os.NewFile(uintptr(fd), name)
			err = errors.Join(f.Sync(), f.Close())
			if err == nil {
				err = syncDir(root)
			}
			if err != nil {
				return nil, "", err
			}
		} else if !errors.Is(err, unix.EEXIST) {
			return nil, "", err
		}
	}
	f, info, err := secure.OpenRootFile(name, 0)
	if err != nil {
		return nil, "", err
	}
	if info.Mode().Perm() != 0600 {
		f.Close()
		return nil, "", errors.New("恢复接入锁权限无效")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, "", errors.New("已有恢复接入或材料清理操作执行中")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, root, nil
}
func writeAdoptionJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if int64(len(raw)) > adoptionRecordMax {
		return errors.New("恢复接入记录超过容量限制")
	}
	scratch := filepath.Join(filepath.Dir(path), ".json-copy")
	if err = os.Remove(scratch); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(scratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
func readAdoptionJSON(path string, out any) error {
	f, info, err := secure.OpenRootFile(path, adoptionRecordMax)
	if err != nil {
		return err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 {
		return errors.New("恢复接入记录须为 root 只读")
	}
	raw, err := io.ReadAll(io.LimitReader(f, adoptionRecordMax+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) != info.Size() || !secure.RootFileUnchanged(f, info) || decodeStrict(raw, out) != nil {
		return errors.New("恢复接入记录不完整或读取期间变化")
	}
	expected, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, raw) {
		return errors.New("恢复接入记录不是原始规范记录")
	}
	return nil
}

func adoptionEntries(dir string) ([]os.DirEntry, int64, error) {
	if err := privateAdoptionDirectory(dir, false); err != nil {
		return nil, 0, err
	}
	items, err := boundedEntries(dir, 10)
	if err != nil {
		return nil, 0, err
	}
	var used int64
	for _, item := range items {
		limit := int64(0)
		mode := os.FileMode(0400)
		switch item.Name() {
		case "intent.json", "adoption.json":
			limit = adoptionRecordMax
		case "cleanup.json", "cleaned.json":
			limit = 2048
		case ".json-copy":
			limit = adoptionRecordMax
			mode = 0600
		case ".copy":
			limit = DatabaseMax
			mode = 0600
		}
		for _, r := range resources {
			if item.Name() == r.local {
				limit = r.limit
			}
		}
		if limit == 0 {
			return nil, 0, errors.New("恢复接入存在未知文件")
		}
		f, info, err := secure.OpenRootFile(filepath.Join(dir, item.Name()), limit)
		if err != nil {
			return nil, 0, err
		}
		f.Close()
		// A killed copy may have completed chmod before rename.
		if info.Mode().Perm() != mode && ((item.Name() != ".copy" && item.Name() != ".json-copy") || info.Mode().Perm() != 0400) {
			return nil, 0, errors.New("恢复接入文件权限无效")
		}
		used += info.Size()
	}
	return items, used, nil
}
func checkAdoptionWork(dir string) error {
	items, _, err := adoptionEntries(dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Name() == "cleanup.json" || item.Name() == "cleaned.json" {
			return errors.New("恢复接入意图目录混入清理记录")
		}
	}
	return nil
}

func adoptionBudget(root string) error {
	items, err := boundedEntries(root, AdoptionRecordMax+1)
	if err != nil {
		return err
	}
	var used int64
	count := 0
	total := 0
	for _, item := range items {
		if item.Name() == ".lock" {
			continue
		}
		id := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(item.Name(), ".adopting-"), ".cleaning-"), ".cleaned-")
		if !validID.MatchString(id) || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return errors.New("恢复接入存储存在未知资源")
		}
		_, size, err := adoptionEntries(filepath.Join(root, item.Name()))
		if err != nil {
			return err
		}
		used += size
		total++
		if !strings.HasPrefix(item.Name(), ".cleaned-") {
			count++
		}
	}
	if total >= AdoptionRecordMax {
		return errors.New("恢复接入历史达到 128 项上限，须先完成受控历史归档；未删除原回执")
	}
	if count >= AdoptionMax || used+2*DatabaseMax+(2<<20) > StoreMax {
		return errors.New("恢复接入达到数量或容量上限，不自动删除既有依据")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(root, &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((2*DatabaseMax+(128<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return errors.New("恢复接入可用磁盘空间不足")
	}
	return nil
}

func openAdoptionSource(data string, intent AdoptionIntent, index int) (*os.File, os.FileInfo, error) {
	p := intent.Preparation
	for _, dir := range []string{filepath.Join(data, "staging"), preparationRoot(data), preparationDir(data, p.OperationID)} {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != intent.UID || int(st.Gid) != intent.GID || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return nil, nil, errors.New("恢复准备源目录归属发生变化")
		}
	}
	path := filepath.Join(preparationDir(data, p.OperationID), resources[index].local)
	fd, err := secure.OpenReadNoSymlinks(unix.AT_FDCWD, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != intent.UID || int(st.Gid) != intent.GID || st.Nlink != 1 || info.Size() != p.Files[index].Size {
			err = errors.New("恢复准备源文件的身份或权限无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
func hashAdoptionFile(ctx context.Context, path string, expected File) error {
	f, info, err := secure.OpenRootFile(path, expected.Size)
	if err != nil {
		return err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 || info.Size() != expected.Size {
		return errors.New("恢复接入固定文件身份无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, expected.Size+1)})
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 || !secure.RootFileUnchanged(f, info) {
		return errors.New("恢复接入固定文件不完整或散列变化")
	}
	return nil
}
func copyAdoptionFile(ctx context.Context, data, dir string, intent AdoptionIntent, index int) error {
	expected := intent.Preparation.Files[index]
	target := filepath.Join(dir, resources[index].local)
	if err := hashAdoptionFile(ctx, target, expected); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if intent.Preparation.ExpiresAt <= time.Now().Unix() {
		return errors.New("恢复准备已到期，禁止从原暂存新增接入资源")
	}
	src, info, err := openAdoptionSource(data, intent, index)
	if err != nil {
		return err
	}
	defer src.Close()
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
	n, err := io.Copy(io.MultiWriter(dst, hash), contextReader{ctx, io.LimitReader(src, expected.Size+1)})
	if err != nil {
		return err
	}
	if n != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 || !secure.RootFileUnchanged(src, info) {
		return errors.New("恢复准备源内容与指定摘要不一致，拒绝接入")
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
	return syncDir(dir)
}
