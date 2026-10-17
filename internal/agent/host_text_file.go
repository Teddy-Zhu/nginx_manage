package agent

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Preserve the captured owner, mode, ACL and security labels on a new inode.
// Callers retain their own closed source paths, rename intent and recovery.
func writeProtectedTextFile(f *os.File, desired dnsFile) error {
	var err error
	if _, err = f.Write(desired.Data); err != nil {
		return err
	}
	if err = f.Chown(int(desired.UID), int(desired.GID)); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(desired.Mode)); err != nil {
		return err
	}
	for name, value := range desired.Xattrs {
		if err = unix.Fsetxattr(int(f.Fd()), name, value, 0); err != nil {
			return err
		}
	}
	// Remove inherited attributes absent from the snapshot, preserving ACL and
	// SELinux labels exactly rather than inheriting the temporary file's labels.
	attrs := make([]byte, 8192)
	n, e := unix.Flistxattr(int(f.Fd()), attrs)
	if errors.Is(e, unix.ENOTSUP) {
		e = nil
		n = 0
	}
	if e != nil {
		return e
	}
	for _, name := range strings.Split(string(attrs[:n]), "\x00") {
		if name != "" {
			if _, ok := desired.Xattrs[name]; !ok {
				if err = unix.Fremovexattr(int(f.Fd()), name); err != nil {
					return err
				}
			}
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return nil
}
