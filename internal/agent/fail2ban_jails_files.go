package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

func writeFail2banJailImmutable(path string, raw []byte, limit int64) error {
	if len(raw) > int(limit) {
		return errors.New("受管 jail 文件超出限制")
	}
	current, err := listenerRead(path, limit)
	if err == nil {
		if !bytes.Equal(current, raw) {
			return ErrExternalChange
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err = existingRootDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + "." + secure.ID() + ".tmp"
	defer os.Remove(tmp)
	if err = durableFile(tmp, raw, 0600, 0); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func verifyFail2banJailConfig(r *fail2banManagedRecord, dir string, b *fail2banJailBundle) error {
	files, err := fail2banJailConfig(r, b)
	if err != nil {
		return err
	}
	for _, child := range []string{"", "jail.d", "filter.d", "action.d"} {
		path := filepath.Join(dir, child)
		if err = existingRootDirectory(path); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			return errors.New("受管 jail 目录权限不匹配")
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		expected := map[string]bool{}
		if child == "" {
			expected["jail.d"], expected["filter.d"], expected["action.d"] = true, true, true
		}
		for relative := range files {
			parent := filepath.Dir(relative)
			if parent == "." {
				parent = ""
			}
			if parent == child {
				expected[filepath.Base(relative)] = true
			}
		}
		if len(entries) != len(expected) {
			return errors.New("受管 jail 目录包含缺失或额外文件")
		}
		for _, entry := range entries {
			if !expected[entry.Name()] {
				return ErrExternalChange
			}
		}
	}
	for relative, content := range files {
		path := filepath.Join(dir, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != 0 || stat.Nlink != 1 {
			return ErrExternalChange
		}
		raw, err := nginxmodules.ReadTrusted(path, fail2banJailBundleLimit)
		if err != nil || string(raw) != content {
			return ErrExternalChange
		}
	}
	return nil
}

func prepareFail2banJailConfig(r *fail2banManagedRecord, b *fail2banJailBundle) error {
	return prepareFail2banJailConfigAt(r, b, r.jailCandidate(b.ID))
}

func prepareFail2banJailConfigAt(r *fail2banManagedRecord, b *fail2banJailBundle, dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return verifyFail2banJailConfig(r, dir, b)
	} else if !os.IsNotExist(err) {
		return err
	}
	base := filepath.Dir(dir)
	if err := secure.RootDirectory(base, 0700); err != nil {
		return err
	}
	// Build in a private temporary directory; a crash never publishes a partial tree.
	tmp, err := os.MkdirTemp(base, ".prepare-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, child := range []string{"jail.d", "filter.d", "action.d"} {
		if err = os.Mkdir(filepath.Join(tmp, child), 0700); err != nil {
			return err
		}
	}
	files, err := fail2banJailConfig(r, b)
	if err != nil {
		return err
	}
	for relative, content := range files {
		if strings.Count(relative, "/") > 1 {
			return errors.New("受管配置目录层级无效")
		}
		if err = durableFile(filepath.Join(tmp, relative), []byte(content), 0600, 0); err != nil {
			return err
		}
	}
	if err = syncTree(tmp); err != nil {
		return err
	}
	if err = verifyFail2banJailConfig(r, tmp, b); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(base)
}

func exchangeFail2banJailConfig(r *fail2banManagedRecord, id string, current, next *fail2banJailBundle) error {
	active, candidate := filepath.Join(r.work(), "config"), r.jailCandidate(id)
	if err := verifyFail2banJailConfig(r, active, current); err != nil {
		return err
	}
	if err := verifyFail2banJailConfig(r, candidate, next); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, active, unix.AT_FDCWD, candidate, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	return errors.Join(syncDir(r.work()), syncDir(filepath.Dir(candidate)))
}
