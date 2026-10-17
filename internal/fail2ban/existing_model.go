package fail2ban

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"nginxpanel/internal/fault"
)

var existingJailName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// ExistingJailPolicy describes tuning only; filter, backend, logs, ports and
// action remain part of the separately reviewed source profile.
type ExistingJailPolicy struct {
	Enabled   bool     `json:"enabled"`
	BanTime   int64    `json:"ban_time"`
	FindTime  int64    `json:"find_time"`
	MaxRetry  int      `json:"max_retry"`
	IgnoreIPs []string `json:"ignore_ips"`
}

func (p ExistingJailPolicy) Normalize() (ExistingJailPolicy, error) {
	values, err := normalizeJailTuning(p.BanTime, p.FindTime, p.MaxRetry, p.IgnoreIPs)
	if err != nil {
		return p, err
	}
	p.IgnoreIPs = values
	return p, nil
}
func normalizeJailTuning(banTime, findTime int64, maxRetry int, ignoreIPs []string) ([]string, error) {
	if (banTime != -1 && (banTime < 1 || banTime > 31536000)) || findTime < 1 || findTime > 86400 || maxRetry < 1 || maxRetry > 1000 || ignoreIPs == nil || len(ignoreIPs) > 64 {
		return nil, fault.Invalid("封禁时间、统计窗口、重试阈值或白名单超出限制")
	}
	values := append([]string{}, ignoreIPs...)
	seen := map[string]bool{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
			value = ip.Unmap().String()
		} else if prefix, err := netip.ParsePrefix(value); err == nil && !prefix.Addr().Is4In6() {
			value = prefix.Masked().String()
		} else {
			return nil, fault.Invalid("白名单只支持数值 IP 或 CIDR")
		}
		if seen[value] {
			return nil, fault.Invalid("白名单地址重复")
		}
		seen[value], values[i] = true, value
	}
	sort.Strings(values)
	return values, nil
}

type ExistingJailProfile struct {
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	LogSource string `json:"log_source"`
	Ports     []int  `json:"ports"`
}

func (p ExistingJailProfile) Validate() error {
	if !existingJailName.MatchString(p.Name) || strings.HasPrefix(p.Name, "nginxpanel-") || p.Profile != "sshd-nftables-input" || p.LogSource != "auth-log" && p.LogSource != "secure-log" && p.LogSource != "systemd" || p.Ports == nil || len(p.Ports) == 0 || len(p.Ports) > 16 {
		return fault.Invalid("已有 jail 仅接纳固定 SSH/nftables INPUT 配置及明确日志来源")
	}
	previous := 0
	for _, port := range p.Ports {
		if port < 1 || port > 65535 || port <= previous {
			return fault.Invalid("SSH 端口须升序、唯一且在 1–65535 范围")
		}
		previous = port
	}
	return nil
}

type ExistingJailPlan struct {
	At          int64               `json:"at"`
	BindingID   string              `json:"binding_id"`
	Target      string              `json:"target"`
	BanProof    string              `json:"ban_proof"`
	NativeProof string              `json:"native_proof"`
	Profile     ExistingJailProfile `json:"profile"`
	Before      ExistingJailPolicy  `json:"before"`
	After       ExistingJailPolicy  `json:"after"`
	Jails       []string            `json:"jails"`
	Impacts     []string            `json:"impacts"`
}
