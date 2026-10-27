// Package frps defines the built-in FRP server configuration and software contract.
package frps

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

const Image = "ghcr.io/fatedier/frps:v0.71.1"

type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}
type Config struct {
	Image         string      `json:"image"`
	AutoStart     bool        `json:"auto_start"`
	BindAddress   string      `json:"bind_address"`
	BindPort      int         `json:"bind_port"`
	Token         string      `json:"token"`
	TLSOnly       bool        `json:"tls_only"`
	AllowPorts    []PortRange `json:"allow_ports"`
	HTTPPort      int         `json:"http_port"`
	HTTPSPort     int         `json:"https_port"`
	SubdomainHost string      `json:"subdomain_host"`
}
type Stats struct {
	Version     string `json:"version"`
	Clients     int64  `json:"clients"`
	Proxies     int64  `json:"proxies"`
	Connections int64  `json:"connections"`
	TrafficIn   int64  `json:"traffic_in"`
	TrafficOut  int64  `json:"traffic_out"`
}
type Status struct {
	Installed bool   `json:"installed"`
	State     string `json:"state"`
	Config    Config `json:"config"`
	TokenSet  bool   `json:"token_set"`
	Stats     *Stats `json:"stats,omitempty"`
	Error     string `json:"error"`
}
type Request struct {
	Action string  `json:"action"`
	Config *Config `json:"config,omitempty"`
}

func Default() Config {
	return Config{Image: Image, AutoStart: true, BindAddress: "0.0.0.0", BindPort: 7000, TLSOnly: true, AllowPorts: []PortRange{{From: 10000, To: 20000}}}
}
func (c Config) Validate() error {
	if c.Image == "" || len(c.Image) > 256 || strings.ContainsAny(c.Image, " \t\r\n\x00") || len(c.Token) > 512 || strings.ContainsAny(c.Token, "\r\n\x00") || len(c.AllowPorts) > 16 {
		return errors.New("FRP 的下载来源、访问密钥或端口设置无效")
	}
	ip, err := netip.ParseAddr(c.BindAddress)
	if err != nil || ip.Zone() != "" || ip.IsMulticast() {
		return errors.New("请填写有效的监听地址")
	}
	if c.BindPort < 1 || c.BindPort > 65535 || c.HTTPPort < 0 || c.HTTPPort > 65535 || c.HTTPSPort < 0 || c.HTTPSPort > 65535 {
		return errors.New("端口必须在 1 到 65535 之间，网站转发未开启时使用 0")
	}
	used := map[int]bool{c.BindPort: true}
	for _, port := range []int{c.HTTPPort, c.HTTPSPort} {
		if port == 0 {
			continue
		}
		if used[port] {
			return errors.New("连接端口和网站转发端口不能重复")
		}
		used[port] = true
	}
	if c.SubdomainHost != "" {
		if len(c.SubdomainHost) > 253 || !strings.Contains(c.SubdomainHost, ".") {
			return errors.New("请填写有效的子域名后缀")
		}
		for _, label := range strings.Split(c.SubdomainHost, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return errors.New("子域名后缀格式无效")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return errors.New("子域名后缀格式无效")
				}
			}
		}
	}
	ranges := append([]PortRange{}, c.AllowPorts...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].From < ranges[j].From })
	end := 0
	for _, r := range ranges {
		if r.From < 1 || r.To < r.From || r.To > 65535 {
			return errors.New("允许映射的端口范围无效")
		}
		if r.From <= end {
			return errors.New("允许映射的端口不能重复或重叠")
		}
		end = r.To
		for p := range used {
			if p >= r.From && p <= r.To {
				return errors.New("允许映射的端口不能包含 FRP 的连接端口或网站转发端口")
			}
		}
	}
	return nil
}
func (r Request) Validate() error {
	switch r.Action {
	case "install", "configure":
		if r.Config != nil {
			return r.Config.Validate()
		}
	case "start", "stop", "restart", "update", "uninstall", "logs":
		if r.Config == nil {
			return nil
		}
	}
	return errors.New("FRP 操作参数无效")
}
