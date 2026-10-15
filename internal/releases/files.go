package releases

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func rootParents(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errors.New("可信路径须为规范绝对路径")
	}
	for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("可信目录及其上层须由 root 持有且不可被其他账户写入")
		}
		if parent == "/" {
			return nil
		}
	}
}
func openRoot(name string, max int64) (*os.File, os.FileInfo, error) {
	if err := rootParents(name); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > max {
			err = errors.New("可信文件的归属、权限、链接或长度无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
func unchanged(f *os.File, before os.FileInfo) bool {
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return false
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	return aok && bok && a.Ctim == b.Ctim && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}
func readRoot(name string, max int64) ([]byte, error) {
	f, before, err := openRoot(name, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != before.Size() || int64(len(raw)) > max || !unchanged(f, before) {
		return nil, errors.New("可信文件在读取期间变化")
	}
	return raw, nil
}
func fileHash(name string, size int64) (string, error) {
	f, before, err := openRoot(name, size)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return "", err
	}
	if n != size || !unchanged(f, before) {
		return "", errors.New("资产文件长度或身份发生变化")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func syncDir(name string) error {
	dir, err := os.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func safePath(name string) bool {
	if len(name) == 0 || len(name) > 256 || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || filepath.ToSlash(filepath.Clean(name)) != name || strings.Count(name, "/") > 15 {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	return strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+-") == ""
}
