package agent

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"nginxpanel/internal/panelruntime"
)

func nativeAgentArguments(actual, data string, uid int) ([]string, error) {
	base := []string{"/opt/nginxpanel/current/nginxpanel", "agent", "--data-dir", data, "--allowed-uid", strconv.Itoa(uid), "--nginx-binding", "--nginx-user", "nginxpanel-nginx", "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--metrics-scope", "host", "--component-scope", "host", "--maintenance-scope", "host"}
	args := strings.Split(actual, " ")
	if len(args) > 6 && args[6] == "--nginx-container" {
		base[6] = "--nginx-container"
	}
	return nativeFixedArguments(args, base, "Agent")
}

func nativeFixedArguments(args, base []string, service string) ([]string, error) {
	invalid := errors.New(service + " 服务参数不是已登记的固定入口")
	if len(args) < len(base) || len(args) > len(base)+14 || (len(args)-len(base))%2 != 0 {
		return nil, invalid
	}
	for index, expected := range base {
		if args[index] != expected {
			return nil, invalid
		}
	}
	// Only the fixed socket context and local owner selections may extend it.
	seen := make(map[string]bool)
	for index := len(base); index < len(args); index += 2 {
		key, value := args[index], args[index+1]
		if seen[key] {
			return nil, invalid
		}
		seen[key] = true
		switch key {
		case "--nginx-log-owner":
			if value != "unconfirmed" && value != "agent" && value != "external" {
				return nil, invalid
			}
		case "--socket-selinux-context":
			if value != agentSocketSELinuxContext {
				return nil, invalid
			}
		case "--dns-scope", "--firewall-scope":
			if value != "host" && value != "unconfirmed" {
				return nil, invalid
			}
		case "--dns-owner":
			switch value {
			case "unconfirmed", "regular-file", "networkmanager", "networkd", "netplan":
			default:
				return nil, invalid
			}
		case "--firewall-owner":
			switch value {
			case "unconfirmed", "direct-nftables", "firewalld", "ufw", "iptables-nft", "iptables-legacy":
			default:
				return nil, invalid
			}
		case "--firewall-ssh":
			if value != "unconfirmed" && value != "openssh" && value != "none" {
				return nil, invalid
			}
		default:
			return nil, invalid
		}
	}
	return args, nil
}

func nativeCoreArguments(actual, data string, uid int, executable string) ([]string, error) {
	invalid := errors.New("核心服务参数不是已登记的固定入口")
	if uid != 0 || data == "" || executable == "" {
		return nil, invalid
	}
	if executable != "/opt/nginxpanel/current/nginxpanel" {
		snapshot, err := panelruntime.Read(data)
		if err != nil || snapshot.Deployment.Mode != "native" || filepath.Clean(executable) != filepath.Join(snapshot.Directory, "nginxpanel") {
			return nil, invalid
		}
	}
	base := []string{executable, "core", "--data-dir", data, "--allowed-uid", "0", "--nginx-container", "--nginx-user", "nginxpanel-nginx", "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--metrics-scope", "host", "--component-scope", "host", "--maintenance-scope", "host"}
	return nativeFixedArguments(strings.Split(actual, " "), base, "核心")
}
