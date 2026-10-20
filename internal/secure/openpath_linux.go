package secure

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenReadNoSymlinks opens a canonical path without following any links. Each
// directory is pinned before resolving its child, including for relative paths
// beneath dirfd. Using openat keeps RestrictSUIDSGID service isolation enabled.
// The caller retains ownership of dirfd and owns the returned descriptor.
func OpenReadNoSymlinks(dirfd int, name string, flags int) (int, error) {
	const allowed = unix.O_DIRECTORY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if name == "" || filepath.Clean(name) != name || flags & ^allowed != 0 {
		return -1, unix.EINVAL
	}
	if filepath.IsAbs(name) {
		if dirfd != unix.AT_FDCWD {
			return -1, unix.EINVAL
		}
		if name == "/" {
			return unix.Open(name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return -1, unix.EINVAL
		}
	}
	base, start := dirfd, "."
	if filepath.IsAbs(name) {
		base, start = unix.AT_FDCWD, "/"
	}
	fd, err := unix.Openat(base, start, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for i, part := range parts {
		childFlags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			childFlags = flags | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		child, err := unix.Openat(fd, part, childFlags, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = child
	}
	return fd, nil
}
