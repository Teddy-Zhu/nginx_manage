package fail2bancontainer

import (
	"fmt"
	"nginxpanel/internal/fail2ban"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func render(data string, c fail2ban.ContainerConfig) error {
	if err := atomicFile(filepath.Join(directory(data), "data", "action.d", "nginxpanel-ipset.conf"), []byte(ipsetAction), 0644); err != nil {
		return err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "[DEFAULT]\nenabled = false\nusedns = no\nbackend = polling\nbanaction = nginxpanel-ipset\nchain = NGINXPANEL_F2B\nignoreip = 127.0.0.0/8 ::1 %s\n", strings.Join(c.Whitelist, " "))
	for _, rule := range c.Rules {
		ports := make([]string, len(rule.Ports))
		for i, p := range rule.Ports {
			ports[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&text, "\n[%s]\nenabled = %t\nport = %s\nmaxretry = %d\nfindtime = %d\nbantime = %d\n", jailName(rule.ID), rule.Enabled, strings.Join(ports, ","), rule.MaxRetry, rule.FindTime, rule.BanTime)
		switch rule.Kind {
		case "ssh":
			journal := false
			for _, dir := range []string{"/run/log/journal", "/var/log/journal"} {
				if info, err := os.Stat(dir); err == nil && info.IsDir() {
					journal = true
				}
			}
			if journal {
				text.WriteString("filter = sshd\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service\n")
			} else {
				path := ""
				for _, candidate := range []string{"auth.log", "secure"} {
					if info, err := os.Stat(filepath.Join("/var/log", candidate)); err == nil && info.Mode().IsRegular() {
						path = "/host-logs/" + candidate
						break
					}
				}
				if path == "" && rule.Enabled {
					return fmt.Errorf("当前无法读取 SSH 登录日志，请检查系统日志服务")
				}
				fmt.Fprintf(&text, "filter = sshd\nlogpath = %s\n", path)
			}
		case "panel":
			text.WriteString("filter = nginxpanel-panel\nlogpath = /panel-security/login.jsonl\n")
		case "nginx":
			files, err := filepath.Glob(filepath.Join(data, "logs", "nginx", "*", "access.log"))
			if err != nil {
				return err
			}
			if rule.Enabled && len(files) == 0 {
				return fmt.Errorf("%s 尚无可用网站日志，请先保存并应用网站配置", rule.Name)
			}
			text.WriteString("filter = nginxpanel-nginx\nlogpath = /panel-logs/nginx/*/access.log\n")
		}
	}
	for template, name := range map[string]string{fail2ban.PanelLoginTemplate: "nginxpanel-panel", fail2ban.HTTP401Template: "nginxpanel-nginx"} {
		raw, err := fail2ban.FilterConfig(template)
		if err != nil {
			return err
		}
		if err = atomicFile(filepath.Join(directory(data), "data", "filter.d", name+".conf"), []byte(raw), 0644); err != nil {
			return err
		}
	}
	return atomicFile(filepath.Join(directory(data), "data", "jail.d", "nginxpanel.local"), []byte(text.String()), 0644)
}
