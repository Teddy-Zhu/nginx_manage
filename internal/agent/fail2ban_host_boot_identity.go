package agent

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/secure"
)

// This identity restricts a local persistent grant; it is not a remote node
// credential. Root recovery material is never included in a migration.
func fail2banHostBootIdentity() (machine, boot string, err error) {
	if (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return "", "", errors.New("无法核对启动恢复的宿主机范围")
	}
	var self, hostNet unix.Stat_t
	if err = unix.Stat("/proc/self/ns/net", &self); err != nil {
		return
	}
	if err = unix.Stat("/proc/1/ns/net", &hostNet); err != nil {
		return
	}
	if self.Dev != hostNet.Dev || self.Ino != hostNet.Ino {
		return "", "", errors.New("启动恢复仅允许宿主机初始网络命名空间")
	}
	raw, err := secure.ReadRootFile("/etc/machine-id", 33)
	if err != nil {
		return "", "", err
	}
	id := strings.TrimSuffix(string(raw), "\n")
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || id == strings.Repeat("0", 32) {
		return "", "", errors.New("本机 machine-id 无效")
	}
	machine = secure.Hash([]byte("nginxpanel:fail2ban-host-machine:v1:" + id))
	raw, err = os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return
	}
	boot = strings.TrimSpace(string(raw))
	if len(raw) > 64 || !validID(boot) {
		return "", "", errors.New("本机启动身份无效")
	}
	return
}
