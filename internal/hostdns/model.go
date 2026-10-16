package hostdns

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const SourceLimit = 16 << 10

type Config struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
	IPv4    *Family  `json:"ipv4"`
	IPv6    *Family  `json:"ipv6"`
}
type Family struct {
	Servers   []string `json:"servers"`
	Search    []string `json:"search"`
	Automatic bool     `json:"automatic"`
}
type Connection struct {
	Target         string   `json:"target"`
	Name           string   `json:"name"`
	Interface      string   `json:"interface"`
	Method4        string   `json:"method4"`
	Method6        string   `json:"method6"`
	Applied        *Config  `json:"applied"`
	Persistent     *Config  `json:"persistent"`
	Effective      *Config  `json:"effective"`
	RoutingDomains []string `json:"routing_domains"`
	SourceHash     string   `json:"source_hash"`
	Writable       bool     `json:"writable"`
	Reason         string   `json:"reason"`
}
type Status struct {
	OperationID string `json:"operation_id"`
	PlanID      string `json:"plan_id"`
	State       string `json:"state"`
	Stage       string `json:"stage"`
	Deadline    int64  `json:"deadline"`
	SourceHash  string `json:"source_hash"`
	Error       string `json:"error"`
}
type DNSServer struct {
	Address    string `json:"address"`
	Source     string `json:"source"`
	Port       uint16 `json:"port"`
	ServerName string `json:"server_name"`
}
type DNSDomain struct {
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Routing bool   `json:"routing"`
}
type LinkDNS struct {
	Servers []DNSServer `json:"servers"`
	Domains []DNSDomain `json:"domains"`
}
type NetworkDNS struct {
	Servers        []string `json:"servers"`
	Search         []string `json:"search"`
	RoutingDomains []string `json:"routing_domains"`
	DHCP4          *bool    `json:"dhcp4"`
	DHCP6          *bool    `json:"dhcp6"`
	IPv6RA         *bool    `json:"ipv6_ra"`
	DNR4           *bool    `json:"dnr4"`
	DNR6           *bool    `json:"dnr6"`
	DNRRA          *bool    `json:"dnr_ra"`
	Domains4       *string  `json:"domains4"`
	Domains6       *string  `json:"domains6"`
	DomainsRA      *string  `json:"domains_ra"`
}
type NetworkLink struct {
	Target        string      `json:"target"`
	Interface     string      `json:"interface"`
	Index         int32       `json:"index"`
	State         string      `json:"state"`
	Owner         string      `json:"owner"`
	LoadedSources []string    `json:"loaded_sources"`
	DiskSources   []string    `json:"disk_sources"`
	SourceHash    string      `json:"source_hash"`
	Persistent    *NetworkDNS `json:"persistent"`
	Loaded        *LinkDNS    `json:"loaded"`
	Effective     *LinkDNS    `json:"effective"`
	Writable      bool        `json:"writable"`
	Reason        string      `json:"reason"`
}
type Observation struct {
	Links       []NetworkLink `json:"links"`
	Connections []Connection  `json:"connections"`
	Owner       string        `json:"owner"`
	Source      string        `json:"source"`
	LinkTarget  string        `json:"link_target"`
	Writable    bool          `json:"writable"`
	Reason      string        `json:"reason"`
	SourceHash  string        `json:"source_hash"`
	Current     Config        `json:"current"`
	Persistent  *Config       `json:"persistent"`
	Pending     *Status       `json:"pending"`
}
type PlanInput struct {
	Target         string   `json:"target"`
	SourceHash     string   `json:"source_hash"`
	Config         Config   `json:"config"`
	VerifyNames    []string `json:"verify_names"`
	TimeoutSeconds int64    `json:"timeout_seconds"`
	Takeover       bool     `json:"takeover"`
}
type Plan struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Input     PlanInput `json:"input"`
	Before    Config    `json:"before"`
	CreatedAt int64     `json:"created_at"`
	ExpiresAt int64     `json:"expires_at"`
	Impact    string    `json:"impact"`
}

func (p Plan) Hash() string { p.ID = ""; b, _ := json.Marshal(p); return secure.Hash(b) }
func Hostname(s string) bool {
	if !utf8.ValidString(s) || len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n\x00") {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (p PlanInput) Validate() error {
	if !p.Takeover || len(p.SourceHash) != 64 || p.TimeoutSeconds < 45 || p.TimeoutSeconds > 180 {
		return fault.Invalid("须明确接管并提供源版本，确认期限须为 45–180 秒")
	}
	if len(p.VerifyNames) < 1 || len(p.VerifyNames) > 2 {
		return fault.Invalid("需配置 1–2 个验证域名")
	}
	if err := p.Config.Validate(p.Target); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range p.VerifyNames {
		if !Hostname(s) || seen[strings.ToLower(s)] {
			return fault.Invalid("验证域名无效或重复")
		}
		seen[strings.ToLower(s)] = true
	}
	for _, name := range p.VerifyNames {
		if _, err := netip.ParseAddr(name); err == nil || !strings.Contains(name, ".") || strings.EqualFold(strings.TrimSuffix(name, "."), "localhost") || strings.HasSuffix(strings.ToLower(strings.TrimSuffix(name, ".")), ".localhost") {
			return fault.Invalid("验证域名须为非 IP 的完整域名")
		}
	}
	return nil
}

// Validate checks only the portable DNS configuration, without granting takeover.
func (c Config) Validate(target string) error {
	if target == "" || NetworkdTarget(target) {
		if c.IPv4 != nil || c.IPv6 != nil || len(c.Servers) < 1 || len(c.Servers) > 3 {
			return fault.Invalid("静态 DNS 需配置 1–3 个地址，不能同时提供地址族设置")
		}
		if err := validateFamily(Family{Servers: c.Servers, Search: c.Search}, 0); err != nil {
			return err
		}
		if target != "" {
			for _, server := range c.Servers {
				ip, _ := netip.ParseAddr(server)
				if ip.Zone() != "" {
					return fault.Invalid("networkd 静态 DNS 暂不接受带接口区域的地址")
				}
			}
		}
	} else {
		if !ValidTarget(target) || len(c.Servers) != 0 || len(c.Search) != 0 || c.IPv4 == nil && c.IPv6 == nil {
			return fault.Invalid("连接 DNS 目标或配置无效")
		}
		hasDNS := false
		for i, f := range []*Family{c.IPv4, c.IPv6} {
			if f != nil {
				if err := validateFamily(*f, 4+2*i); err != nil {
					return err
				}
				hasDNS = hasDNS || f.Automatic || len(f.Servers) > 0
			}
		}
		if !hasDNS {
			return fault.Invalid("至少一个地址族须配置 DNS 地址或启用自动获取")
		}
	}
	return nil
}

var targetPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@[a-zA-Z0-9_.:-]{1,15}$`)
var networkdTargetPattern = regexp.MustCompile(`^networkd:[a-zA-Z0-9_.:-]{1,15}$`)

func NetworkdTarget(target string) bool { return networkdTargetPattern.MatchString(target) }
func ValidTarget(target string) bool {
	return targetPattern.MatchString(target) || NetworkdTarget(target)
}

// Normalize only after validation. Canonical addresses and non-null arrays
// keep observed, desired and API representations consistent.
func (p PlanInput) Normalize() PlanInput {
	addresses := func(src []string) []string {
		out := []string{}
		for _, s := range src {
			ip, _ := netip.ParseAddr(s)
			out = append(out, ip.String())
		}
		return out
	}
	p.Config.Servers = addresses(p.Config.Servers)
	p.Config.Search = append([]string{}, p.Config.Search...)
	if NetworkdTarget(p.Target) {
		for i, domain := range p.Config.Search {
			p.Config.Search[i] = strings.ToLower(strings.TrimSuffix(domain, "."))
		}
	}
	family := func(f *Family) *Family {
		if f == nil {
			return nil
		}
		copy := *f
		copy.Servers = addresses(f.Servers)
		copy.Search = append([]string{}, f.Search...)
		return &copy
	}
	p.Config.IPv4 = family(p.Config.IPv4)
	p.Config.IPv6 = family(p.Config.IPv6)
	return p
}

func validateFamily(f Family, family int) error {
	if len(f.Servers) > 3 || len(f.Search) > 6 || len(strings.Join(f.Search, " ")) > 253 {
		return fault.Invalid("每类 DNS 最多 3 个地址及 6 个搜索域，搜索域合计最多 253 字节")
	}
	seen := map[string]bool{}
	for _, s := range f.Servers {
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || family == 4 && !ip.Is4() || family == 6 && !ip.Is6() || family != 0 && ip.Zone() != "" || seen[ip.String()] {
			return fault.Invalid("DNS 地址无效、重复或地址族不匹配")
		}
		if zone := ip.Zone(); zone != "" && (len(zone) > 15 || strings.Trim(zone, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "") {
			return fault.Invalid("IPv6 DNS 接口区域无效")
		}
		seen[ip.String()] = true
	}
	seen = map[string]bool{}
	for _, s := range f.Search {
		canonical := strings.ToLower(strings.TrimSuffix(s, "."))
		if !Hostname(s) || seen[canonical] {
			return fault.Invalid("搜索域无效或重复")
		}
		seen[canonical] = true
	}
	return nil
}

type Desired struct {
	Target     string `json:"target"`
	Version    int64  `json:"version"`
	Config     Config `json:"config"`
	SourceHash string `json:"source_hash"`
	UpdatedAt  int64  `json:"updated_at"`
}
type Task struct {
	ID          string `json:"id"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Stage       string `json:"stage"`
	Error       string `json:"error"`
	Decision    string `json:"decision"`
}
type Overview struct {
	Observed Observation `json:"observed"`
	Desired  []Desired   `json:"desired"`
	Task     *Task       `json:"task"`
}
type Change struct {
	TaskID string `json:"task_id"`
}
