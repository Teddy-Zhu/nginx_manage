package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"time"

	"nginxpanel/internal/firewall"
)

func validateFirewallProtectionBasis(b firewallProtectionBasis) error {
	invalid := func() error { return errors.New("防火墙独立保护依据无效") }
	if b.SSHProfile != "openssh" && b.SSHProfile != "none" || b.SSHListeners == nil || len(b.SSHListeners) > 512 || b.SSHProfile == "none" && len(b.SSHListeners) != 0 || len(b.AllowedSources) == 0 || len(b.AllowedSources) > 32 {
		return invalid()
	}
	host, port, err := net.SplitHostPort(b.Listener)
	address, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || address.Is4In6() || address.Zone() != "" || address.IsLoopback() || number < 1024 || number > 65535 || portErr != nil || net.JoinHostPort(address.String(), strconv.Itoa(number)) != b.Listener {
		return invalid()
	}
	source, err := netip.ParseAddr(b.ControlSource)
	if err != nil || source.Is4In6() || source.IsLoopback() || source.IsUnspecified() || source.Zone() != "" || source.String() != b.ControlSource {
		return invalid()
	}
	allowed := false
	seen := map[string]bool{}
	for _, raw := range b.AllowedSources {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.String() != raw || seen[raw] {
			return invalid()
		}
		seen[raw] = true
		allowed = allowed || prefix.Contains(source)
	}
	if !allowed || !sort.StringsAreSorted(b.SSHListeners) {
		return invalid()
	}
	seen = map[string]bool{}
	for _, raw := range b.SSHListeners {
		listener, err := netip.ParseAddrPort(raw)
		if err != nil || listener.Port() == 0 || listener.Addr().Zone() != "" || listener.String() != raw || seen[raw] {
			return invalid()
		}
		seen[raw] = true
	}
	return nil
}

func protectionObservation(state, planID, reason string) firewall.ProtectionObservation {
	return firewall.ProtectionObservation{State: state, PlanID: planID, SSHListeners: []string{}, Protections: []firewall.Protection{}, Reason: reason}
}

// Caller holds listener -> firewall locks. The original actual source is fixed
// by the root plan, so neither polling clients nor forwarded headers can add
// sources to the observation or alter the independently confirmed protection.
func (f *hostFirewall) observeProtectionsLocked(ctx context.Context, record *firewallPolicyRecord) firewall.ProtectionObservation {
	if record == nil || record.Action == "remove" {
		return protectionObservation("not_applicable", "", "尚无已确认的过滤规则需要核对保护来源")
	}
	out := protectionObservation("unavailable", record.PlanID, "当前 SSH 监听或保护来源无法完整读取；请检查宿主机后重新计划")
	out.SSHProfile = f.sshMode
	if !f.remote.available || f.remote.problem != "" || f.remote.closed || f.remote.pendingLocked() {
		out.Reason = "管理入口待确认、待恢复或授权不可用，保护依据暂不可核对"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	current := f.remote.state.Confirmed
	protections, listeners, err := firewallProtectionSet(ctx, record.Policy, f.sshMode, current.Listen, current.AllowedSources, record.ProtectionBasis.ControlSource)
	out.ObservedAt = time.Now().Unix()
	if errors.Is(err, errFirewallProtectionSources) {
		out.State, out.SSHListeners = "changed", listeners
		out.Reason = "当前 SSH 地址族缺少可核对的保护来源；原规则保留，请调整管理来源并重新计划"
		return out
	}
	if err != nil {
		return out
	}
	out.SSHListeners, out.Protections = listeners, protections
	actual, err := json.Marshal(protections)
	if err != nil {
		return out
	}
	expected, err := json.Marshal(record.Protections)
	if err != nil {
		return out
	}
	allowed, previousAllowed := slices.Clone(current.AllowedSources), slices.Clone(record.ProtectionBasis.AllowedSources)
	sort.Strings(allowed)
	sort.Strings(previousAllowed)
	if !current.Enabled || current.Listen != record.ProtectionBasis.Listener || !slices.Equal(allowed, previousAllowed) || f.sshMode != record.ProtectionBasis.SSHProfile || !slices.Equal(listeners, record.ProtectionBasis.SSHListeners) || string(actual) != string(expected) {
		out.State, out.Reason = "changed", "SSH 监听、保护来源或管理入口已变化；原确认规则保留，请重新计划、应用并确认"
		return out
	}
	out.State, out.Reason = "current", ""
	return out
}

func (f *hostFirewall) protectionObservationLocked() firewall.ProtectionObservation {
	if f.policyUncertain || f.problem != "" {
		return protectionObservation("unavailable", "", "独立策略不可核对，保护状态未知")
	}
	if f.activeLocked() || f.firewalldState != nil && f.firewalldState.Call != nil {
		return protectionObservation("unavailable", "", "变更进行中；确认前将重新核对候选保护来源")
	}
	record := f.confirmedRecord()
	if record == nil || record.Action == "remove" {
		return protectionObservation("not_applicable", "", "尚无已确认的过滤规则需要核对保护来源")
	}
	if f.protectionObservation.PlanID != record.PlanID || f.protectionObservedAt.IsZero() || time.Since(f.protectionObservedAt) > 45*time.Second {
		return protectionObservation("unavailable", record.PlanID, "保护来源核对尚未完成或已过期，请刷新状态")
	}
	return f.protectionObservation
}
