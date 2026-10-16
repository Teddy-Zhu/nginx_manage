package panelruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// publicationLock serializes bootstrap and update staging in the same bounded
// immutable release store. Neither caller may change an existing release.
func publicationLock(root string) (func(), error) {
	if err := runtimeDir(root); err != nil {
		return nil, err
	}
	if err := runtimeDir(filepath.Join(root, "releases")); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(root, ".publish.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), ".publish.lock")
	checked, _, err := secure.OpenRootFile(filepath.Join(root, ".publish.lock"), 0)
	if err != nil {
		lock.Close()
		return nil, err
	}
	if err = checked.Close(); err != nil {
		lock.Close()
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("面板发布存储正在使用")
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); lock.Close() }, nil
}

// publishRelease requires publicationLock. A complete directory is renamed
// before its approval is recorded, so interruption leaves no approved half-copy.
func publishRelease(ctx context.Context, root, binary, web string, r Release) error {
	if err := r.validate(); err != nil {
		return err
	}
	var err error
	dir := filepath.Join(root, "releases", r.ID)
	if _, err = os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		retained, err := os.ReadDir(filepath.Join(root, "releases"))
		if err != nil {
			return err
		}
		if len(retained) >= 32 {
			return errors.New("面板发布目录达到保留上限，须本机维护")
		}
		tmp, err := os.MkdirTemp(filepath.Join(root, "releases"), ".bind-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if err = os.Chmod(tmp, 0755); err != nil {
			return err
		}
		if err = os.Mkdir(filepath.Join(tmp, "web"), 0755); err != nil {
			return err
		}
		if err = copyArtifact(binary, filepath.Join(tmp, "nginxpanel"), r.BinarySHA256, BinaryLimit, 0555); err != nil {
			return err
		}
		for name, f := range r.Web {
			if err = os.MkdirAll(filepath.Dir(filepath.Join(tmp, "web", name)), 0755); err != nil {
				return err
			}
			if err = copyArtifact(filepath.Join(web, name), filepath.Join(tmp, "web", name), f.SHA256, WebFileLimit, 0444); err != nil {
				return err
			}
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err = publishFile(filepath.Join(tmp, "release.json"), raw); err != nil {
			return err
		}
		if err = filepath.WalkDir(tmp, func(name string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if err = os.Chmod(name, 0755); err != nil {
					return err
				}
				return syncDir(name)
			}
			return nil
		}); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(dir)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err = readRelease(dir, r.ID); err != nil {
		return err
	}
	return nil
}
