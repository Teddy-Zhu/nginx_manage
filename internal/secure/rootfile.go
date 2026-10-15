package secure

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// OpenRootFile rejects writable ancestors, links and special files before the
// caller reads or executes an installation artifact.
func OpenRootFile(name string, limit int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || limit < 0 {
		return nil, nil, errors.New("可信文件路径或长度无效")
	}
	for dir := filepath.Dir(name); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, nil, errors.New("可信文件上层须由 root 持有且不可被其他账户写入")
		}
		if dir == "/" {
			break
		}
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > limit {
			err = errors.New("可信文件的归属、权限、链接或长度无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func RootFileUnchanged(f *os.File, before os.FileInfo) bool {
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return false
	}
	a, ok := before.Sys().(*syscall.Stat_t)
	b, yes := after.Sys().(*syscall.Stat_t)
	return ok && yes && a.Ctim == b.Ctim && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime() == after.ModTime()
}

func ReadRootFile(name string, limit int64) ([]byte, error) {
	f, info, err := OpenRootFile(name, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size() || int64(len(raw)) > limit || !RootFileUnchanged(f, info) {
		return nil, errors.New("可信文件在读取期间变化")
	}
	return raw, nil
}

func HashRootFile(name string, limit int64) (string, error) {
	f, info, err := OpenRootFile(name, limit)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if n != info.Size() || n > limit || !RootFileUnchanged(f, info) {
		return "", errors.New("可信文件在核对期间变化")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
