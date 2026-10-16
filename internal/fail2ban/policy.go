package fail2ban

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const PolicyBytes = 64 << 10
const MaxJails = 32

var policyID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DesiredJail carries logical sources and typed actions, never a host path,
// service, socket, arbitrary filter or executable action.
type DesiredJail struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Template   string   `json:"template"`
	ResourceID string   `json:"resource_id"`
	Action     string   `json:"action"`
	BanTime    int64    `json:"ban_time"`
	FindTime   int64    `json:"find_time"`
	MaxRetry   int      `json:"max_retry"`
	IgnoreIPs  []string `json:"ignore_ips"`
}
type Policy struct {
	Jails []DesiredJail `json:"jails"`
}
type PolicyView struct {
	Version   int64  `json:"version"`
	Policy    Policy `json:"policy"`
	UpdatedAt int64  `json:"updated_at"`
}
type PolicyInput struct {
	BaseVersion int64  `json:"base_version"`
	Policy      Policy `json:"policy"`
}
type Template struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Category      string         `json:"category"`
	Format        string         `json:"format"`
	BanTime       int64          `json:"ban_time"`
	FindTime      int64          `json:"find_time"`
	MaxRetry      int            `json:"max_retry"`
	FilterSHA256  string         `json:"filter_sha256"`
	SamplesSHA256 string         `json:"samples_sha256"`
	Samples       []FilterSample `json:"samples"`
}

func Templates() []Template {
	out := []Template{
		{ID: Authorization401Template, Name: "HTTP 认证响应 401", Description: "统计携带 Authorization 后返回的 HTTP 401，排除无认证头的首次挑战；不覆盖仅凭 Cookie 认证的失败", Category: "http_access", Format: "nginxpanel_http", BanTime: 600, FindTime: 600, MaxRetry: 10},
		{ID: HTTP401Template, Name: "Nginx HTTP 401", Description: "统计站点结构化访问日志中的全部 HTTP 401，包含首次认证挑战；请按实际流量设置阈值", Category: "http_access", Format: "nginxpanel_http", BanTime: 600, FindTime: 600, MaxRetry: 10},
	}
	for i := range out {
		out[i].FilterSHA256, out[i].SamplesSHA256 = FilterIdentity(out[i].ID)
		out[i].Samples = FilterSamples(out[i].ID)
	}
	return out
}
func DefaultPolicy() Policy   { return Policy{Jails: []DesiredJail{}} }
func (p Policy) Hash() string { raw, _ := json.Marshal(p); return secure.Hash(raw) }
func (p Policy) Normalize() (Policy, error) {
	out := DefaultPolicy()
	if p.Jails == nil || len(p.Jails) > MaxJails {
		return out, fault.Invalid("jail 必须为数组且最多 32 项")
	}
	ids, sources := map[string]bool{}, map[string]bool{}
	for _, j := range p.Jails {
		j.Name = strings.TrimSpace(j.Name)
		if !policyID.MatchString(j.ID) || !policyID.MatchString(j.ResourceID) || ids[j.ID] || j.Name == "" || len(j.Name) > 120 || !utf8.ValidString(j.Name) || strings.IndexFunc(j.Name, unicode.IsControl) >= 0 {
			return out, fault.Invalid("jail 标识、名称或站点标识无效")
		}
		if !KnownTemplate(j.Template) {
			return out, fault.Invalid("请选择内置 jail 模板")
		}
		if j.Action != "host-input" && j.Action != "docker-forward" && j.Action != "nginx-client" {
			return out, fault.Invalid("jail 动作须为宿主机入口、Docker 转发或 Nginx 客户端")
		}
		if (j.BanTime != -1 && (j.BanTime < 1 || j.BanTime > 31536000)) || j.FindTime < 1 || j.FindTime > 86400 || j.MaxRetry < 1 || j.MaxRetry > 1000 || j.IgnoreIPs == nil || len(j.IgnoreIPs) > 64 {
			return out, fault.Invalid("封禁时间、统计窗口、重试阈值或白名单超出限制")
		}
		key := j.Template + ":" + j.ResourceID
		if sources[key] {
			return out, fault.Invalid("同一站点不能重复配置相同 jail 模板")
		}
		ids[j.ID], sources[key] = true, true
		j.IgnoreIPs = append([]string{}, j.IgnoreIPs...)
		seen := map[string]bool{}
		for i, value := range j.IgnoreIPs {
			value = strings.TrimSpace(value)
			if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
				value = addr.Unmap().String()
			} else if prefix, err := netip.ParsePrefix(value); err == nil && !prefix.Addr().Is4In6() {
				value = prefix.Masked().String()
			} else {
				return out, fault.Invalid("白名单只支持数值 IP 或 CIDR")
			}
			if seen[value] {
				return out, fault.Invalid("白名单地址重复")
			}
			seen[value] = true
			j.IgnoreIPs[i] = value
		}
		sort.Strings(j.IgnoreIPs)
		out.Jails = append(out.Jails, j)
	}
	sort.Slice(out.Jails, func(i, j int) bool { return out.Jails[i].ID < out.Jails[j].ID })
	raw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if len(raw) > PolicyBytes {
		return out, fault.Invalid("jail 配置超过 64 KiB")
	}
	return out, nil
}
