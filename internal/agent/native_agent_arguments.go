package agent

import (
	"errors"
	"strconv"
	"strings"
)

func nativeAgentArguments(actual, data string, uid int) ([]string, error) {
	base := []string{"/opt/nginxpanel/current/nginxpanel", "agent", "--data-dir", data, "--allowed-uid", strconv.Itoa(uid), "--nginx-binding", "--nginx-user", "nginxpanel-nginx", "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--metrics-scope", "host", "--component-scope", "host", "--maintenance-scope", "host"}
	args := strings.Split(actual, " ")
	invalid := errors.New("Agent 服务参数不是已登记的固定入口")
	if len(args) < len(base) || len(args) > len(base)+14 || (len(args)-len(base))%2 != 0 {
		return nil, invalid
	}
	if args[6] == "--nginx-container" {
		base[6] = "--nginx-container"
	}
	for i, expected := range base {
		if args[i] != expected {
			return nil, invalid
		}
	}
	// Only the fixed socket context and local owner selections may extend it.
	// Keep their exact order for /proc verification during Agent upgrades.
	seen := make(map[string]bool)
	for i := len(base); i < len(args); i += 2 {
		key, value := args[i], args[i+1]
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
