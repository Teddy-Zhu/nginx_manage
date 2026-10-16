package fail2ban

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const HostProtectionSourceLimit = 128

// These are root-approved TCP peer ranges, separate from jail ignore_ips and
// any forwarded client identity. An empty proxy list explicitly means none.
type HostInputProtectionPolicy struct {
	AdminSources []string `json:"admin_sources"`
	ProxySources []string `json:"proxy_sources"`
}

func (p HostInputProtectionPolicy) Normalize() (HostInputProtectionPolicy, error) {
	out := HostInputProtectionPolicy{AdminSources: []string{}, ProxySources: []string{}}
	if p.AdminSources == nil || len(p.AdminSources) == 0 || len(p.AdminSources) > HostProtectionSourceLimit || p.ProxySources == nil || len(p.ProxySources) > HostProtectionSourceLimit {
		return out, errors.New("须明确管理来源及代理来源，每类最多 128 项，管理来源不能为空")
	}
	normalize := func(sources []string) ([]string, error) {
		set, err := (firewall.NFTBanSet{Addresses: []string{}, Protected: sources}).Normalize()
		if err != nil {
			return nil, err
		}
		for _, raw := range set.Protected {
			prefix, _ := netip.ParsePrefix(raw)
			address := prefix.Addr()
			if prefix.Bits() == 0 || address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
				return nil, errors.New("宿主机动作保护须为单播来源，不能使用默认网段、未指定、多播或广播地址")
			}
		}
		return set.Protected, nil
	}
	var err error
	if out.AdminSources, err = normalize(p.AdminSources); err != nil {
		return out, err
	}
	out.ProxySources, err = normalize(p.ProxySources)
	return out, err
}

func (p HostInputProtectionPolicy) Hash() string {
	raw, _ := json.Marshal(p)
	return secure.Hash(raw)
}

type HostInputProtectionView struct {
	At           int64    `json:"at"`
	State        string   `json:"state"`
	Verified     bool     `json:"verified"`
	ID           string   `json:"id"`
	ApprovedAt   int64    `json:"approved_at"`
	PolicyHash   string   `json:"policy_hash"`
	AdminSources []string `json:"admin_sources"`
	ProxySources []string `json:"proxy_sources"`
	Reason       string   `json:"reason"`
}

func EmptyHostInputProtection(reason string) HostInputProtectionView {
	return HostInputProtectionView{At: time.Now().Unix(), State: "unavailable", AdminSources: []string{}, ProxySources: []string{}, Reason: reason}
}

func (v HostInputProtectionView) Valid() bool {
	if v.At <= 0 || v.ApprovedAt < 0 || v.AdminSources == nil || v.ProxySources == nil || len(v.AdminSources) > HostProtectionSourceLimit || len(v.ProxySources) > HostProtectionSourceLimit {
		return false
	}
	switch v.State {
	case "unavailable", "unapproved", "approved", "stale", "revoked":
	default:
		return false
	}
	if v.Verified != (v.State == "approved") || !v.Verified && v.Reason == "" || v.Verified && v.Reason != "" {
		return false
	}
	if v.ID == "" {
		return (v.State == "unavailable" || v.State == "unapproved") && v.ApprovedAt == 0 && v.PolicyHash == "" && len(v.AdminSources) == 0 && len(v.ProxySources) == 0
	}
	policy := HostInputProtectionPolicy{AdminSources: v.AdminSources, ProxySources: v.ProxySources}
	if !policyID.MatchString(v.ID) || v.ApprovedAt == 0 || policy.Hash() != v.PolicyHash {
		return false
	}
	if v.State == "revoked" {
		return len(v.AdminSources) == 0 && len(v.ProxySources) == 0
	}
	if v.State == "unapproved" {
		return false
	}
	normalized, err := policy.Normalize()
	return err == nil && normalized.Hash() == v.PolicyHash
}
