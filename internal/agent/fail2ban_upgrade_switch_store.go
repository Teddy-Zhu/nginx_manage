package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// Include abandoned temporary files and reserve intent/undo write headroom.
// Capacity pressure cannot remove original audit or recovery evidence.
func fail2banUpgradeSwitchQuota(store string, add bool) error {
	entries, err := os.ReadDir(store)
	if err != nil {
		return err
	}
	count := 0
	for _, e := range entries {
		if e.Name() != "current.json" {
			count++
		}
	}
	if add {
		count++
	}
	if count > 8 {
		return errors.New("升级切换目录已达 8 项上限，须本机维护")
	}
	budget := int64(112 << 20)
	if add {
		budget = 104 << 20
	}
	var total int64
	count = 0
	return filepath.WalkDir(store, func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == store {
			return nil
		}
		count++
		relative, err := filepath.Rel(store, path)
		if err != nil {
			return err
		}
		if count > 256 || strings.Count(relative, string(filepath.Separator)) > 1 {
			return errors.New("升级切换材料数量或层级超过限制")
		}
		if e.IsDir() {
			return fail2banStatePrivateDir(path, false)
		}
		f, info, err := secure.OpenRootFile(path, fail2banUpgradeSwitchLimit)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("升级切换材料须为 root 专用 0600 文件")
		}
		total += info.Size()
		if total > budget {
			return errors.New("升级切换材料无法在 128 MiB 预算内保留完整补偿依据")
		}
		return nil
	})
}

func reserveFail2banUpgradeSwitch(i fail2banUpgradeSwitch) (resultErr error) {
	store := fail2banUpgradeSwitches(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err := fail2banUpgradeSwitchQuota(store, true); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(store, ".switch-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	if err = writeFail2banUpgradeSwitchJSON(filepath.Join(tmp, "intent.json"), i); err != nil {
		return err
	}
	if err = syncDir(tmp); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, i.dir(), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(store)
}
