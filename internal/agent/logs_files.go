package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

func (n *Nginx) prepareLogFiles(sources []logSource) error {
	parents := map[string]bool{}
	for _, kind := range []string{"nginx", "stream"} {
		base := filepath.Join(n.DataDir, "logs", kind)
		if err := secure.RootDirectory(base, 0755); err != nil {
			return err
		}
		if n.Container != nil {
			if err := os.Chmod(base, 0755); err != nil {
				return err
			}
		}
		dir, err := os.Open(base)
		if err != nil {
			return err
		}
		entries, err := dir.Readdirnames(limits.LogSources/3 + 1)
		dir.Close()
		if err != nil && err != io.EOF {
			return err
		}
		for _, name := range entries {
			parents[filepath.Join(base, name)] = true
		}
	}
	for _, source := range sources {
		parent := filepath.Dir(filepath.Join(n.DataDir, source.Path))
		if parent != filepath.Join(n.DataDir, "logs", "nginx-global") {
			parents[parent] = true
		}
	}
	if len(parents) > limits.LogSources/3 {
		return errors.New("retained managed log directory quota exceeded")
	}
	for _, source := range sources {
		name := filepath.Join(n.DataDir, source.Path)
		if err := secure.RootDirectory(filepath.Dir(name), 0755); err != nil {
			return err
		}
		if n.Container != nil {
			if err := os.Chmod(filepath.Dir(name), 0755); err != nil {
				return err
			}
		}
		fd, err := unix.Open(name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0640)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != 0 && stat.Uid != uint32(n.uid) || info.Mode().Perm()&0022 != 0 {
			file.Close()
			return errors.New("untrusted managed log file")
		}
		if err := file.Chmod(0640); err != nil {
			file.Close()
			return err
		}
		owner := -1
		if n.Container != nil {
			owner = n.uid
		}
		if err := file.Chown(owner, n.gid); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}
