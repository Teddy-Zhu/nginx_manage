package firewall

import (
	"context"
	"net/netip"
	"sort"

	"nginxpanel/internal/fault"
)

// CheckTCPIngress proves that this application's confirmed INPUT program does
// not reject any requested source on a fresh TCP connection. Each named rule
// interface and the remaining interfaces are evaluated separately. It does not
// certify other base chains, host routing, listeners or external firewalls.
func CheckTCPIngress(ctx context.Context, policy Policy, protections []Protection, port int, sources []string) error {
	if port < 1 || port > 65535 || len(sources) == 0 || len(sources) > 32 || len(protections) > 128 {
		return fault.Invalid("管理入口核对范围无效")
	}
	normalized, err := policy.Normalize()
	if err != nil {
		return err
	}
	if normalized.Backend != "direct-nftables" {
		return fault.Unavailable("当前管理入口核对仅支持 direct-nftables")
	}
	requested := make([]netip.Prefix, 0, len(sources))
	for _, source := range sources {
		prefix, err := sourcePrefix(source)
		if err != nil {
			return fault.Invalid("管理入口核对来源无效")
		}
		requested = append(requested, prefix)
	}
	budget := ingressBudget{remaining: 1 << 20, ctx: ctx}
	if err := budget.spend(); err != nil {
		return err
	}
	// Guards precede all business rules and apply on every ingress interface.
	for _, protection := range protections {
		if protection.Service != "management" && protection.Service != "ssh" || protection.Family != "ipv4" && protection.Family != "ipv6" || protection.Port < 1 || protection.Port > 65535 || len(protection.Sources) == 0 || len(protection.Sources) > 32 {
			return fault.Invalid("已确认保护项无效")
		}
		for _, source := range protection.Sources {
			prefix, err := sourcePrefix(source)
			if err != nil || prefix.Addr().Is4() != (protection.Family == "ipv4") {
				return fault.Invalid("已确认保护来源无效")
			}
			if protection.Port == port {
				requested, err = budget.subtract(requested, prefix)
				if err != nil {
					return err
				}
			}
		}
	}
	if len(requested) == 0 {
		return nil
	}
	type ingressRule struct {
		Rule
		sources []netip.Prefix
	}
	rules := make([]ingressRule, 0, len(normalized.Rules))
	interfaces := map[string]bool{"": true}
	for _, rule := range normalized.Rules {
		if !rule.Enabled || rule.Scope != "host_input" || rule.Protocol != "tcp" || rule.Interface == "lo" {
			continue
		}
		matches := false
		for _, interval := range rule.Ports {
			if interval.From <= port && port <= interval.To {
				matches = true
				break
			}
		}
		if matches {
			entry := ingressRule{Rule: rule, sources: make([]netip.Prefix, 0, max(2, len(rule.Sources)))}
			if len(rule.Sources) == 0 {
				if rule.Family != "ipv6" {
					entry.sources = append(entry.sources, netip.MustParsePrefix("0.0.0.0/0"))
				}
				if rule.Family != "ipv4" {
					entry.sources = append(entry.sources, netip.MustParsePrefix("::/0"))
				}
			} else {
				for _, source := range rule.Sources {
					prefix, _ := netip.ParsePrefix(source) // Normalize validated the family and canonical form.
					entry.sources = append(entry.sources, prefix)
				}
			}
			rules = append(rules, entry)
			interfaces[rule.Interface] = true
		}
	}
	orderedInterfaces := make([]string, 0, len(interfaces))
	for name := range interfaces {
		orderedInterfaces = append(orderedInterfaces, name)
	}
	sort.Strings(orderedInterfaces)
	for _, name := range orderedInterfaces {
		pending := append([]netip.Prefix(nil), requested...)
		for _, rule := range rules {
			if err := budget.spend(); err != nil {
				return err
			}
			if len(pending) == 0 {
				break
			}
			if rule.Interface != "" && rule.Interface != name {
				continue
			}
			for _, source := range rule.sources {
				if rule.Action == "allow" {
					pending, err = budget.subtract(pending, source)
					if err != nil {
						return err
					}
					continue
				}
				for _, remaining := range pending {
					if err := budget.spend(); err != nil {
						return err
					}
					if remaining.Overlaps(source) {
						return fault.Conflict("已确认防火墙规则 " + rule.ID + " 会阻止候选管理来源；请先调整并确认防火墙策略")
					}
				}
			}
		}
		// Unmatched new connections return through the chain's ACCEPT policy.
	}
	return nil
}

type ingressBudget struct {
	remaining int
	ctx       context.Context
}

func (b *ingressBudget) spend() error {
	if err := b.ctx.Err(); err != nil {
		return fault.Unavailable("管理入口防火墙核对已取消或超时")
	}
	b.remaining--
	if b.remaining < 0 {
		return fault.Unavailable("管理入口防火墙核对超过计算预算；请简化来源或规则")
	}
	return nil
}

// Subtracting one CIDR from another produces at most address-bits fragments.
// Keeping the unmatched set, rather than sampling addresses, detects a denied
// subnet even when the rest of the requested CIDR was allowed earlier.
func (b *ingressBudget) subtract(pending []netip.Prefix, allowed netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(pending))
	for _, prefix := range pending {
		if err := b.spend(); err != nil {
			return nil, err
		}
		if !prefix.Overlaps(allowed) {
			out = append(out, prefix)
		} else if prefix.Bits() < allowed.Bits() {
			for prefix.Bits() < allowed.Bits() {
				if err := b.spend(); err != nil {
					return nil, err
				}
				bits := prefix.Bits()
				left := netip.PrefixFrom(prefix.Addr(), bits+1)
				address := prefix.Addr().AsSlice()
				address[bits/8] |= 1 << (7 - bits%8)
				rightAddress, _ := netip.AddrFromSlice(address)
				right := netip.PrefixFrom(rightAddress, bits+1)
				if left.Contains(allowed.Addr()) {
					out = append(out, right)
					prefix = left
				} else {
					out = append(out, left)
					prefix = right
				}
			}
		}
		if len(out) > MaxEntries {
			return nil, fault.Unavailable("管理入口核对来源分段超过 8192 项；请简化来源或规则")
		}
	}
	return out, nil
}
