package panelrecovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func root(data string) (string, error) {
	if _, err := panelruntime.Root(data); err != nil {
		return "", err
	}
	return filepath.Join(data, "agent", "panel-recovery"), nil
}

func workspace(data, id string) string {
	return filepath.Join(data, "run", "panel-recovery", id)
}

func privateDir(name string) error {
	if err := secure.RootDirectory(name, 0700); err != nil {
		return err
	}
	if err := checkPrivateDir(name); err != nil {
		return err
	}
	if err := syncDir(name); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}

func checkPrivateDir(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm() != 0700 {
		return errors.New("本机恢复目录须为 root 专用的 0700 目录")
	}
	return nil
}

func syncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func writeFile(name string, raw []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func key(store string, create bool) (*age.X25519Identity, error) {
	name := filepath.Join(store, "recovery.key")
	f, info, err := secure.OpenRootFile(name, 256)
	if errors.Is(err, os.ErrNotExist) && create {
		identity, e := age.GenerateX25519Identity()
		if e != nil {
			return nil, e
		}
		if e = writeFile(name, []byte(identity.String()+"\n"), 0600); e != nil {
			return nil, e
		}
		if e = syncDir(store); e != nil {
			return nil, e
		}
		return identity, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0600 {
		return nil, errors.New("本机恢复密钥权限无效")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return nil, err
	}
	if len(raw) > 256 || !secure.RootFileUnchanged(f, info) {
		return nil, errors.New("本机恢复密钥在读取时变化")
	}
	return age.ParseX25519Identity(strings.TrimSuffix(string(raw), "\n"))
}

// openOwned checks every parent and the open inode. Business files belong to
// the serve UID, so OpenRootFile would reject these valid snapshot resources.
func openOwned(name string, uid, gid int, limit int64) (*os.File, os.FileInfo, error) {
	return openBusinessFile(name, uid, gid, limit, false)
}

func openBusinessFile(name string, uid, gid int, limit int64, allowEmpty bool) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, nil, errors.New("快照资源路径无效")
	}
	for dir := filepath.Dir(name); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 && int(st.Uid) != uid || info.Mode().Perm()&0022 != 0 {
			return nil, nil, errors.New("快照资源上层目录归属或权限无效")
		}
		if dir == "/" {
			break
		}
	}
	// A serve-owned ancestor may be renamed after the metadata checks. Enforce
	// no symlinks for the whole lookup in the kernel, including intermediate dirs.
	fd, err := secure.OpenReadNoSymlinks(unix.AT_FDCWD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || int(st.Uid) != uid || int(st.Gid) != gid || st.Nlink != 1 || info.Size() < 0 || !allowEmpty && info.Size() == 0 || info.Size() > limit {
			err = errors.New("快照资源的归属、类型、权限或容量无效")
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func readReceipt(store, id string) (Receipt, error) {
	var r Receipt
	name := filepath.Join(store, id, "receipt.json")
	info, err := os.Lstat(name)
	if err != nil {
		return r, err
	}
	if info.Mode().Perm() != 0400 {
		return r, errors.New("本机快照批准记录须为 root 只读")
	}
	raw, err := secure.ReadRootFile(name, manifestMax+2048)
	if err != nil {
		return r, err
	}
	if err = decode(bytes.NewReader(raw), &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return r, errors.New("本机快照批准记录不是原始规范记录")
	}
	return r, nil
}
