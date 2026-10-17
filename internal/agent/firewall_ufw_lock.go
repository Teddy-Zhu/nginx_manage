package agent

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const ufwManagerLockPath = "/run/ufw.lock"

// UFW uses lockf (POSIX record locks), so flock would not exclude its CLI.
// An OFD lock conflicts with lockf and survives in the gated child until its
// last descriptor closes, even if the Agent exits during the restore.
func lockUFWManager() (*os.File, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("UFW 管理锁须由本机 root 持有")
	}
	if err := existingRootDirectory("/run"); err != nil {
		return nil, err
	}
	fd, err := unix.Open(ufwManagerLockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), ufwManagerLockPath)
	if err = verifyUFWManagerLock(f); err != nil {
		f.Close()
		return nil, err
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: unix.SEEK_SET}
	if err = unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lock); err != nil {
		f.Close()
		return nil, errors.New("UFW 官方管理锁正被占用或不支持，未提交规则")
	}
	if err = verifyUFWManagerLock(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func verifyUFWManagerLock(f *os.File) error {
	if f == nil {
		return errors.New("UFW 官方管理锁未持有")
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(ufwManagerLockPath)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != 0 || stat.Nlink != 1 || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return errors.New("UFW 官方管理锁的路径、归属或文件身份变化")
	}
	return nil
}
