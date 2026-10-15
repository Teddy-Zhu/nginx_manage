package secure

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// RootDirectory checks every parent, so a non-root owner cannot rename an
// apparently private child directory or redirect a privileged journal write.
func RootDirectory(name string, mode os.FileMode) error {
	if !filepath.IsAbs(name) {
		return errors.New("trusted directory must be absolute")
	}
	current := "/"
	for _, part := range strings.Split(filepath.Clean(name), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, mode); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("trusted directory and all parents must be root-owned and not group/world writable")
		}
	}
	return nil
}
