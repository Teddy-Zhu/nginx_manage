package agent

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// Maintenance admission and release share this lock with the independent
// installation process. A root receipt is published before the lock is dropped.
func (j *Journal) maintenanceLock() (func(), error) { return j.rootLock(".maintenance-access.lock") }
func (j *Journal) rootLock(name string) (func(), error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("独立维护操作需要本机 root")
	}
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(j.Dir, name), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 {
			err = errors.New("独立维护锁不可信")
		}
	}
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
