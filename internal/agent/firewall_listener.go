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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ufwPreparingLocked() {
		return fault.Conflict("UFW 计划正在准备，请先取消或等待完成后变更管理入口")
	}
	if !config.Enabled {
		f.protectionObservedAt = time.Time{}
		return nil
	}
	if f.policyUncertain {
		return fault.Unavailable("防火墙独立策略记录不可核对，禁止变更远程入口")
	}
	record := f.state.Confirmed
	if f.firewalldState != nil {
		if f.problem != "" || f.activeLocked() || f.firewalldState.Call != nil {
			return fault.Conflict("firewalld 存在待确认、待恢复或不可核对状态")
		}
		if _, err := f.firewalldConfirmedSnapshot(ctx); err != nil {
			return fault.Unavailable("firewalld 已确认配置无法完整核对，禁止变更远程入口")
		}
		record = f.firewalldState.Confirmed
	} else if f.ufwState != nil {
		if f.problem != "" || f.activeLocked() {
			return fault.Conflict("UFW 存在待确认、待恢复或不可核对状态")
		}
		if err := f.reconcileUFWConfirmedLocked(ctx); err != nil {
			return fault.Unavailable("UFW 已确认配置与运行状态无法核对，禁止变更远程入口")
		}
		record = f.confirmedRecord()
	} else if f.state.Schema == 0 {
		return nil // No independent policy has been registered on this node.
	} else {
		if f.state.Schema != firewallRuntimeSchema || f.problem != "" || f.activeLocked() {
			return fault.Conflict("防火墙存在待确认、待恢复或不可核对状态")
		}
		current, err := f.snapshotContext(ctx, f.state.Confirmed)
		if err != nil || !current.TableExists || current.NamespaceID != f.state.CurrentKernel.NamespaceID || current.Fingerprint != f.state.CurrentKernel.Fingerprint {
			return fault.Conflict("无法证明当前受管防火墙对象；须先核对或恢复，再变更远程入口")
		}
	}
	if record == nil || record.Action == "remove" {
		return nil // A proven empty owned object cannot reject the candidate.
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
	if err := firewall.CheckTCPIngress(ctx, record.Policy, record.Protections, port, sources); err != nil {
		return err
	}
	// The caller is about to change or confirm listener context. A cached
	// observation of the former confirmed ingress is no longer current.
	f.protectionObservedAt = time.Time{}
	return nil
}
