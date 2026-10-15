package launcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func checkLayout(d panelruntime.Deployment) error {
	if os.Geteuid() != d.UID || os.Getegid() != d.GID {
		return errors.New("launcher 身份与宿主机登记不一致")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	hasIPC := d.IPCGID == d.GID
	for _, gid := range groups {
		if gid != d.GID && gid != d.IPCGID {
			return errors.New("launcher 不允许额外的宿主机组授权")
		}
		if gid == d.IPCGID {
			hasIPC = true
		}
	}
	if !hasIPC {
		return errors.New("launcher 缺少已登记的 Agent Socket 组")
	}
	for _, dir := range []string{"app", "bootstrap", "secrets", "staging", "run/launcher"} {
		info, err := os.Lstat(filepath.Join(d.DataDir, dir))
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(st.Uid) != d.UID || int(st.Gid) != d.GID {
			return errors.New("面板可写目录未按宿主机身份初始化")
		}
	}
	for dir := filepath.Join(d.DataDir, "run"); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("launcher Socket 上层须由宿主机 root 持有")
		}
		if dir == "/" {
			break
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	hash, err := secure.HashRootFile(exe, panelruntime.BinaryLimit)
	if err != nil {
		return err
	}
	if hash != d.LauncherSHA256 {
		return errors.New("launcher 镜像与宿主机批准的程序不匹配")
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && (fields[0] == "CapInh:" || fields[0] == "CapPrm:" || fields[0] == "CapEff:" || fields[0] == "CapBnd:" || fields[0] == "CapAmb:") {
			if strings.Trim(fields[1], "0") != "" {
				return errors.New("launcher 容器须删除全部 capabilities")
			}
			count++
		}
	}
	if count != 5 {
		return errors.New("无法确认 launcher capabilities")
	}
	return nil
}
func lock(data string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(filepath.Dir(Socket(data)), ".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "launcher.lock")
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() != 0 {
			err = errors.New("launcher 锁的归属或类型无效")
		}
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
