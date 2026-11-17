package fail2ban

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

const ContainerImage = "crazymax/fail2ban:debian"
const ContainerName = "nginxpanel-fail2ban"

type ContainerRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Enabled  bool   `json:"enabled"`
	Ports    []int  `json:"ports"`
	MaxRetry int    `json:"max_retry"`
	FindTime int    `json:"find_time"`
	BanTime  int    `json:"ban_time"`
}
type ContainerConfig struct {
	Revision  int64           `json:"revision"`
	Image     string          `json:"image"`
	AutoStart bool            `json:"auto_start"`
	Whitelist []string        `json:"whitelist"`
	Rules     []ContainerRule `json:"rules"`
}
type ContainerJail struct {
	ID            string   `json:"id"`
	Running       bool     `json:"running"`
	Banned        []string `json:"banned"`
	CurrentFailed int64    `json:"current_failed"`
	TotalFailed   int64    `json:"total_failed"`
	CurrentBanned int64    `json:"current_banned"`
	TotalBanned   int64    `json:"total_banned"`
	Error         string   `json:"error"`
}
type ContainerStatus struct {
	State     string          `json:"state"`
	Installed bool            `json:"installed"`
	Running   bool            `json:"running"`
	Ready     bool            `json:"ready"`
	Config    ContainerConfig `json:"config"`
	Jails     []ContainerJail `json:"jails"`
	Logs      string          `json:"logs"`
	Error     string          `json:"error"`
}
type ContainerRequest struct {
	Action  string           `json:"action"`
	Config  *ContainerConfig `json:"config,omitempty"`
	JailID  string           `json:"jail_id,omitempty"`
	Address string           `json:"address,omitempty"`
}

func (c ContainerConfig) Validate() error {
	if c.Rules == nil || c.Whitelist == nil || c.Revision < 0 || len(c.Image) > 256 || c.Image == "" || strings.ContainsAny(c.Image, " \t\r\n\x00") || len(c.Rules) > 32 || len(c.Whitelist) > 128 {
		return errors.New("登录防护配置无效")
	}
	seen := map[string]bool{}
	for _, r := range c.Rules {
		if !policyID.MatchString(r.ID) || seen[r.ID] || strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 || !slices.Contains([]string{"ssh", "panel", "nginx"}, r.Kind) || r.MaxRetry < 1 || r.MaxRetry > 1000 || r.FindTime < 10 || r.FindTime > 604800 || r.BanTime < 10 || r.BanTime > 31536000 || len(r.Ports) < 1 || len(r.Ports) > 15 {
			return errors.New("防护规则的名称、端口或时间无效")
		}
		seen[r.ID] = true
		ports := map[int]bool{}
		for _, p := range r.Ports {
			if p < 1 || p > 65535 || ports[p] {
				return errors.New("防护端口无效或重复")
			}
			ports[p] = true
		}
	}
	for _, value := range c.Whitelist {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Zone() == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.IsMulticast() || ip.IsUnspecified() {
			return errors.New("白名单需要有效的 IP 地址或网段")
		}
	}
	return nil
}
func (r ContainerRequest) Validate() error {
	switch r.Action {
	case "install", "configure", "update":
		if r.Action == "update" && r.Config == nil && r.JailID == "" && r.Address == "" {
			return nil
		}
		if r.Config != nil && r.JailID == "" && r.Address == "" {
			return r.Config.Validate()
		}
	case "start", "stop", "restart", "uninstall", "logs":
		if r.Config == nil && r.JailID == "" && r.Address == "" {
			return nil
		}
	case "ban", "unban":
		ip, err := netip.ParseAddr(r.Address)
		if r.Config == nil && policyID.MatchString(r.JailID) && err == nil && ip.Zone() == "" && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified() {
			return nil
		}
	}
	return errors.New("登录防护操作无效")
}
