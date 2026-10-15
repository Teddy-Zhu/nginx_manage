package hostdns

import (
	"encoding/json"
	"net/netip"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const SourceLimit = 16 << 10

type Config struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
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
type Observation struct {
	Owner      string  `json:"owner"`
	Source     string  `json:"source"`
	LinkTarget string  `json:"link_target"`
	Writable   bool    `json:"writable"`
	Reason     string  `json:"reason"`
	SourceHash string  `json:"source_hash"`
	Current    Config  `json:"current"`
	Persistent *Config `json:"persistent"`
	Pending    *Status `json:"pending"`
}
type PlanInput struct {
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
	if len(p.Config.Servers) < 1 || len(p.Config.Servers) > 3 || len(p.Config.Search) > 6 || len(p.VerifyNames) < 1 || len(p.VerifyNames) > 2 {
		return fault.Invalid("需配置 1–3 个 DNS 地址、最多 6 个搜索域及 1–2 个验证域名")
	}
	seen := map[string]bool{}
	for _, s := range p.Config.Servers {
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || seen[ip.String()] {
			return fault.Invalid("DNS 地址无效或重复")
		}
		if zone := ip.Zone(); zone != "" {
			if len(zone) > 15 || strings.Trim(zone, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
				return fault.Invalid("IPv6 DNS 接口区域无效")
			}
		}
		seen[ip.String()] = true
	}
	for _, list := range [][]string{p.Config.Search, p.VerifyNames} {
		seen = map[string]bool{}
		for _, s := range list {
			if !Hostname(s) || seen[strings.ToLower(s)] {
				return fault.Invalid("搜索域或验证域名无效、重复")
			}
			seen[strings.ToLower(s)] = true
		}
	}
	for _, name := range p.VerifyNames {
		if _, err := netip.ParseAddr(name); err == nil || !strings.Contains(name, ".") || strings.EqualFold(strings.TrimSuffix(name, "."), "localhost") || strings.HasSuffix(strings.ToLower(strings.TrimSuffix(name, ".")), ".localhost") {
			return fault.Invalid("验证域名须为非 IP 的完整域名")
		}
	}
	if len(strings.Join(p.Config.Search, " ")) > 253 {
		return fault.Invalid("搜索域合计不能超过 253 字节")
	}
	return nil
}

type Desired struct {
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
	Desired  *Desired    `json:"desired"`
	Task     *Task       `json:"task"`
}
type Change struct {
	TaskID string `json:"task_id"`
}
