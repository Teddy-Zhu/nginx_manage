package fail2bancontainer

import (
	"context"
	"errors"
	"fmt"
	"nginxpanel/internal/secure"
	"os"
	"os/exec"
	"strings"
)

const kernelConfig = "/etc/modules-load.d/nginxpanel-fail2ban.conf"

// Load modules on the host, without granting the container CAP_SYS_MODULE or
// exposing the host module tree. systemd loads the same list before Docker on boot.
var kernelModules = []string{"ip_set", "ip_set_hash_ip", "ip_tables", "iptable_filter", "ip6_tables", "ip6table_filter", "xt_set", "xt_multiport", "ipt_REJECT", "ip6t_REJECT"}

func kernelContent() string {
	return "# NginxPanel login protection\n" + strings.Join(kernelModules, "\n") + "\n"
}

func checkKernelConfig() error {
	raw, err := secure.ReadRootFile(kernelConfig, 4096)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(raw) != kernelContent() {
		return errors.New("登录防护启动配置已被其他操作修改，请检查后重试")
	}
	return nil
}

func prepareKernel(ctx context.Context) error {
	if err := checkKernelConfig(); err != nil {
		return err
	}
	for _, name := range kernelModules {
		if _, err := os.Stat("/sys/module/" + name); err == nil {
			continue
		}
		out, err := exec.CommandContext(ctx, "modprobe", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("无法准备登录防护环境（%s）：%w；%s", name, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func persistKernel() error {
	if err := checkKernelConfig(); err != nil {
		return err
	}
	return atomicFile(kernelConfig, []byte(kernelContent()), 0644)
}

func removeKernelConfig() error {
	if err := checkKernelConfig(); err != nil {
		return err
	}
	err := os.Remove(kernelConfig)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
