package agent

import (
	"context"
	"errors"
	"os"
	"time"
)

// InstallationDefaults inspects the deployment host without changing network
// configuration. Registration separately verifies ownership before granting
// management access to the selected supported manager.
type InstallationDefaults struct {
	DNSOwner      string
	FirewallOwner string
	FirewallSSH   string
	Warnings      []string
}

func DetectInstallationDefaults(ctx context.Context, dataDir string) (InstallationDefaults, error) {
	out := InstallationDefaults{DNSOwner: "unconfirmed", FirewallOwner: "unconfirmed", FirewallSSH: "unconfirmed"}
	if os.Geteuid() != 0 {
		return out, errors.New("安装环境检测需要本机 root")
	}
	if reason := (&HostDNS{Scope: "host"}).hostScopeReason(); reason != "" {
		return out, errors.New(reason)
	}
	view := (&HostDNS{Scope: "host"}).Read()
	candidates := []string{}
	switch view.Owner {
	case "regular-file", "netplan", "networkd":
		candidates = append(candidates, view.Owner)
	case "NetworkManager":
		candidates = append(candidates, "networkmanager")
	case "resolved":
		candidates = append(candidates, "networkmanager", "networkd")
	}
	for _, owner := range candidates {
		candidate := (&HostDNS{Scope: "host", Owner: owner}).Read()
		if candidate.Writable {
			out.DNSOwner = owner
			break
		}
		view = candidate
	}
	if out.DNSOwner == "unconfirmed" {
		out.Warnings = append(out.Warnings, "DNS 设置暂时仅支持查看："+view.Reason)
	}
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	fw := (&firewallObserver{scope: "host", dataDir: dataDir, skipIPTablesRegistration: true}).collect(call)
	if fw.Available && fw.Backend != "mixed" {
		switch fw.Manager {
		case "firewalld", "ufw":
			out.FirewallOwner = fw.Manager
		case "direct-candidate":
			if fw.Kernel.Available && len(fw.Rulesets) > 0 && fw.Rulesets[0].Available && fw.Backend != "legacy" {
				out.FirewallOwner = "direct-nftables"
			} else if len(fw.Iptables) == 2 && fw.Iptables[0].Backend == fw.Iptables[1].Backend {
				switch fw.Iptables[0].Backend {
				case "nftables":
					out.FirewallOwner = "iptables-nft"
				case "legacy":
					out.FirewallOwner = "iptables-legacy"
				}
			}
		}
	}
	if out.FirewallOwner != "unconfirmed" {
		// Keep SSH discovery mandatory. An absent or unreadable daemon must
		// never be interpreted as proof that SSH protection can be omitted.
		out.FirewallSSH = "openssh"
	} else {
		out.Warnings = append(out.Warnings, "无法确定可管理的系统防火墙，保留现有规则并仅支持查看。")
	}
	return out, nil
}
