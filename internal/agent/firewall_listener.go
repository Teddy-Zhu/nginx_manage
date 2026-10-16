package agent

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/remotelisten"
)

// The caller holds the listener mutex, preserving listener -> firewall lock
// order until the candidate has been saved and bound. Neither the saved draft
// nor the module switch describes what the independently maintained rules do.
func (f *hostFirewall) checkListener(ctx context.Context, config remotelisten.Config) error {
	if !config.Enabled {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policyUncertain {
		return fault.Unavailable("防火墙独立策略记录不可核对，禁止变更远程入口")
	}
	if f.state.Schema == 0 {
		return nil // No independent policy has been registered on this node.
	}
	if f.state.Schema != firewallRuntimeSchema || f.problem != "" || f.activeLocked() {
		return fault.Conflict("防火墙存在待确认、待恢复或不可核对状态")
	}
	current, err := f.snapshotContext(ctx, f.state.Confirmed)
	if err != nil || !current.TableExists || current.NamespaceID != f.state.CurrentKernel.NamespaceID || current.Fingerprint != f.state.CurrentKernel.Fingerprint {
		return fault.Conflict("无法证明当前受管防火墙对象；须先核对或恢复，再变更远程入口")
	}
	if f.state.Confirmed == nil || f.state.Confirmed.Action == "remove" {
		return nil // A proven empty owned table cannot reject the candidate.
	}
	host, rawPort, err := net.SplitHostPort(config.Listen)
	if err != nil {
		return fault.Invalid("管理监听地址无效")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return fault.Invalid("管理监听 IP 无效")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return fault.Invalid("管理监听端口无效")
	}
	sources := make([]string, 0, len(config.AllowedSources))
	for _, raw := range config.AllowedSources {
		source, err := netip.ParsePrefix(raw)
		if err != nil {
			return fault.Invalid("管理监听允许来源无效")
		}
		// Go's tcp listener may accept IPv4 on an IPv6 wildcard. Both ACL
		// families must therefore be checked; a specific bind is single-family.
		if address.Is6() && address.IsUnspecified() || address.Is4() == source.Addr().Is4() {
			sources = append(sources, raw)
		}
	}
	if len(sources) == 0 {
		return fault.Invalid("管理监听地址族没有可用的允许来源")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return firewall.CheckTCPIngress(ctx, f.state.Confirmed.Policy, f.state.Confirmed.Protections, port, sources)
}
