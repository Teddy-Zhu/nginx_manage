package nginxcontainer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// Launch is the image's fixed PID 1 entry point. The short bootstrap needs
// SETUID/SETGID/SETPCAP to discard root; the Nginx master and workers run under
// the dedicated host UID with only NET_BIND_SERVICE, including on host networks
// that retain the standard privileged-port threshold. No host sysctl is changed.
func Launch(data string) error {
	return launch(data, "")
}

// LaunchTest uses the same bounded identity transition for Docker exec and
// isolated candidate checks. Docker does not inherit PID 1's ambient capability
// when exec starts directly as the non-root Nginx user.
func LaunchTest(data, revision string) error {
	if err := checkRevision(revision); err != nil {
		return err
	}
	return launch(data, revision)
}

func testLaunchArgs(data, revision string) []string {
	return []string{Bootstrap, "nginx-container-test", "--data-dir", data, "--nginx-test-revision", revision}
}

func launch(data, revision string) error {
	if os.Geteuid() != 0 || revision == "" && os.Getpid() != 1 {
		return errors.New("Nginx 镜像启动器需要容器 root，正式实例必须为 PID 1")
	}
	b, err := Read(data)
	if err != nil {
		return err
	}
	for name, want := range map[string]string{Binary: b.BinarySHA256, Bootstrap: b.BootstrapSHA256} {
		hash, err := secure.HashRootFile(name, binaryLimit)
		if err != nil {
			return err
		}
		if hash != want {
			return errors.New("Nginx 镜像程序与宿主机登记不一致")
		}
	}
	// Capabilities, prctl state and credentials belong to the locked thread
	// that execs Nginx. Broadcast Set* calls need runtime signals that AppArmor
	// can deny between Docker exec threads with stacked labels. The other
	// runtime threads disappear on exec; failures return to the terminating CLI.
	runtime.LockOSThread()
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return err
	}
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return err
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || last < unix.CAP_NET_BIND_SERVICE || last > 63 {
		return errors.New("内核能力范围不受支持")
	}
	for cap := 0; cap <= last; cap++ {
		if cap != unix.CAP_NET_BIND_SERVICE {
			if err = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
				return err
			}
		}
	}
	if _, _, errno := syscall.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
		return errno
	}
	if _, _, errno := syscall.RawSyscall(unix.SYS_SETRESGID, uintptr(b.GID), uintptr(b.GID), uintptr(b.GID)); errno != 0 {
		return errno
	}
	if _, _, errno := syscall.RawSyscall(unix.SYS_SETRESUID, uintptr(b.UID), uintptr(b.UID), uintptr(b.UID)); errno != 0 {
		return errno
	}
	cap := uint32(1) << unix.CAP_NET_BIND_SERVICE
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	set := [2]unix.CapUserData{{Effective: cap, Permitted: cap, Inheritable: cap}, {}}
	if err = unix.Capset(&header, &set[0]); err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_BIND_SERVICE, 0, 0); err != nil {
		return err
	}
	if err = os.Chdir(data); err != nil {
		return err
	}
	args := []string{Binary, "-p", data + "/", "-c", filepath.Join(data, "nginx", "active", "nginx.conf"), "-e", "stderr", "-g", "daemon off;"}
	if revision != "" {
		args = append([]string{Binary}, testArguments(data, revision)...)
	}
	return syscall.Exec(Binary, args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"})
}
