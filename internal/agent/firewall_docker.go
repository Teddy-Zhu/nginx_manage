package agent

import (
	"encoding/json"
	"net/netip"
	"slices"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/firewall"
)

type dockerFirewallHook struct {
	Observed bool
	Reason   string
}

// A chain name or any conditional reference is insufficient. This observation
// requires the complete native export's first FORWARD rule to be the sole,
// unconditional jump. It claims no ownership of Docker or third-party rules.
func observeDockerFirewallHook(image iptablesImage) dockerFirewallHook {
	user, forward := image.chain("filter", "DOCKER-USER"), image.chain("filter", "FORWARD")
	if user == nil || user.Policy != "-" || forward == nil || forward.Policy != "ACCEPT" && forward.Policy != "DROP" {
		return dockerFirewallHook{Reason: "filter/DOCKER-USER 及 FORWARD 未完整观察到"}
	}
	if len(forward.Rules) == 0 || !slices.Equal(forward.Rules[0], []string{"-j", "DOCKER-USER"}) && !slices.Equal(forward.Rules[0], []string{"--jump", "DOCKER-USER"}) {
		return dockerFirewallHook{Reason: "FORWARD 首条规则不是明确的无条件 DOCKER-USER 跳转"}
	}
	for _, table := range image.Tables {
		if table.Name != "filter" {
			continue
		}
		for _, chain := range table.Chains {
			for ordinal, rule := range chain.Rules {
				if chain.Name == "FORWARD" && ordinal == 0 {
					continue
				}
				for index := 0; index < len(rule); index++ {
					if rule[index] == "--comment" {
						index++
						continue
					}
					if (rule[index] == "-j" || rule[index] == "--jump" || rule[index] == "-g" || rule[index] == "--goto") && index+1 < len(rule) && rule[index+1] == "DOCKER-USER" {
						return dockerFirewallHook{Reason: "filter 还有其他 DOCKER-USER 引用，不能确认单一挂接路径"}
					}
				}
			}
		}
	}
	return dockerFirewallHook{Observed: true}
}

func dockerFirewallCapabilities(out *firewall.Observation, hooks []dockerFirewallHook) {
	out.Docker.Capabilities = []firewall.DockerCapability{}
	complete := len(out.Rulesets) == 5
	for _, ruleset := range out.Rulesets {
		complete = complete && ruleset.Available
	}
	for _, backend := range []string{"direct-nftables", "iptables-nft", "iptables-legacy", "firewalld", "ufw"} {
		for familyIndex, family := range []string{"ipv4", "ipv6"} {
			capability := firewall.DockerCapability{Backend: backend, Family: family, Reason: "当前组合不支持 Docker 发布端口写入"}
			switch {
			case !out.Docker.Runtime.Available:
				capability.Reason = out.Docker.Runtime.Reason
			case out.Docker.Runtime.Rootless || out.Docker.Runtime.Swarm != "inactive":
				capability.Reason = "rootless 或 Swarm 不在本机 bridge 发布端口适配范围内"
			case out.Docker.BackendHint == "mixed":
				capability.Reason = "Docker 后端标记混合，不能确定单一转发路径"
			case out.Docker.BackendHint == "nftables":
				capability.Hook, capability.Reason = "forward", "Docker 原生 nftables 路径按实验适配保持只读"
			case !validIPTablesBackend(backend):
				capability.Reason = "该后端的主机入站规则不能代替 Docker 发布端口保护"
			default:
				capability.Hook = "DOCKER-USER"
				variant, wanted := 0, "nftables"
				if backend == "iptables-legacy" {
					variant, wanted = 1, "legacy"
				}
				index := 2*variant + familyIndex
				switch {
				case !out.Available || out.Scope != "host" || !complete:
					capability.Reason = "完整宿主机内核视图不可用"
				case out.Manager != "direct-candidate" || out.Backend != wanted:
					capability.Reason = "宿主机管理器或内核后端与所选显式 iptables 路径不一致"
				case out.Docker.BackendHint != "iptables":
					capability.Reason = "未观察到 Docker iptables 转发挂接"
				case len(hooks) != 4:
					capability.Reason = "尚未完整读取原生 DOCKER-USER 挂接"
				case !hooks[index].Observed:
					capability.Reason = hooks[index].Reason
				default:
					capability.Observed = true
				}
			}
			out.Docker.Capabilities = append(out.Docker.Capabilities, capability)
		}
	}
	if !out.Docker.Runtime.Available {
		out.Docker.Reason = out.Docker.Runtime.Reason
	} else if out.Docker.BackendHint != "nftables" && out.Docker.BackendHint != "mixed" {
		out.Docker.Reason = "Docker 端口映射与挂接仅供只读核对，当前不允许发布端口规则写入"
	}
}

func validDockerFirewall(out firewall.Observation) bool {
	value := out.Docker
	runtime := value.Runtime
	if value.Writable || !slices.Contains([]string{"unknown", "nftables", "iptables", "mixed"}, value.BackendHint) || value.Evidence == nil || len(value.Evidence) > firewallObjectLimit || !dockerFirewallText(value.Reason, 2048) || runtime.Ports == nil || !dockerFirewallText(runtime.Reason, 2048) {
		return false
	}
	if !runtime.Available {
		if runtime.EngineHash != "" || runtime.Version != "" || runtime.APIVersion != "" || runtime.SnapshotHash != "" || runtime.ObservedAt != 0 || runtime.Rootless || runtime.Swarm != "" || runtime.Networks != 0 || runtime.Containers != 0 || runtime.PublishedPorts != 0 || len(runtime.Ports) != 0 || runtime.Truncated {
			return false
		}
	} else if !out.Available || out.Scope != "host" || !firewalldDigest(runtime.EngineHash) || !firewalldDigest(runtime.SnapshotHash) || !dockerFirewallText(runtime.Version, 64) || runtime.APIVersion != dockerapi.Version || runtime.ObservedAt <= 0 || !slices.Contains([]string{"inactive", "pending", "active", "error", "locked"}, runtime.Swarm) || runtime.Networks < 0 || runtime.Networks > 128 || runtime.Containers < 0 || runtime.Containers > 128 || runtime.PublishedPorts < 0 || runtime.PublishedPorts > 1024 || len(runtime.Ports) != min(128, runtime.PublishedPorts) || runtime.Truncated != (runtime.PublishedPorts > len(runtime.Ports)) {
		return false
	}
	seen := map[string]bool{}
	for _, port := range runtime.Ports {
		if !firewalldDigest(port.ContainerID) || !slices.Contains([]string{"unknown", "ipv4", "ipv6"}, port.Family) || !slices.Contains([]string{"tcp", "udp", "sctp"}, port.Protocol) || port.HostPort < 0 || port.HostPort > 65535 || port.ContainerPort < 1 || port.ContainerPort > 65535 || port.HostPort == 0 && port.HostIP == "" || port.NetworkIDs == nil || len(port.NetworkIDs) > 16 || !slices.Contains([]string{"bridge_nat_candidate", "unconfirmed"}, port.Path) || !dockerFirewallText(port.Reason, 2048) {
			return false
		}
		if port.HostIP != "" {
			ip, err := netip.ParseAddr(port.HostIP)
			if err != nil || ip.Zone() != "" || ip.Is4In6() || (port.Family != "ipv4" && port.Family != "ipv6") || ip.Is4() != (port.Family == "ipv4") {
				return false
			}
		} else if port.Family != "unknown" {
			return false
		}
		for index, network := range port.NetworkIDs {
			if !firewalldDigest(network) || index > 0 && network <= port.NetworkIDs[index-1] {
				return false
			}
		}
		key := port.ContainerID + ":" + dockerFirewallPortKey(dockerFirewallPort{IP: port.HostIP, PublicPort: port.HostPort, PrivatePort: port.ContainerPort, Type: port.Protocol})
		if seen[key] || port.Path == "bridge_nat_candidate" && (runtime.Rootless || runtime.Swarm != "inactive" || port.Protocol == "sctp" || port.HostPort == 0 || port.HostIP == "" || len(port.NetworkIDs) != 1) {
			return false
		}
		seen[key] = true
	}
	if value.Capabilities == nil || len(value.Capabilities) != 0 && len(value.Capabilities) != 10 || runtime.Available && len(value.Capabilities) != 10 {
		return false
	}
	seen = map[string]bool{}
	for _, capability := range value.Capabilities {
		key := capability.Backend + ":" + capability.Family
		if seen[key] || !slices.Contains([]string{"direct-nftables", "iptables-nft", "iptables-legacy", "firewalld", "ufw"}, capability.Backend) || !slices.Contains([]string{"ipv4", "ipv6"}, capability.Family) || !slices.Contains([]string{"", "DOCKER-USER", "forward"}, capability.Hook) || capability.Supported || !dockerFirewallText(capability.Reason, 2048) || capability.Observed && (!runtime.Available || runtime.Rootless || runtime.Swarm != "inactive" || !validIPTablesBackend(capability.Backend) || capability.Hook != "DOCKER-USER" || value.BackendHint != "iptables") {
			return false
		}
		seen[key] = true
	}
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= 320<<10
}
