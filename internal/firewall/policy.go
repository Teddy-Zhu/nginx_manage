package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const MaxRules = 1000
const MaxEntries = 8192
const PolicyBytes = 256 << 10

type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}
type Rule struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Enabled   bool        `json:"enabled"`
	Scope     string      `json:"scope"`
	Family    string      `json:"family"`
	Protocol  string      `json:"protocol"`
	Ports     []PortRange `json:"ports"`
	Sources   []string    `json:"sources"`
	Action    string      `json:"action"`
	Priority  int         `json:"priority"`
	Interface string      `json:"interface"`
	Comment   string      `json:"comment"`
}

// Backend is a target binding. Rules contain no tool paths or executable text.
// Saving desired policy does not claim that it is active in the kernel.
type Policy struct {
	Backend string `json:"backend"`
	Rules   []Rule `json:"rules"`
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
type PreviewInput struct {
	Version int64 `json:"version"`
}
type PreviewEntry struct {
	BackendPriority *int      `json:"backend_priority"`
	Expression      string    `json:"expression"`
	RuleID          string    `json:"rule_id"`
	Family          string    `json:"family"`
	Protocol        string    `json:"protocol"`
	Source          string    `json:"source"`
	Ports           PortRange `json:"ports"`
	Action          string    `json:"action"`
	Interface       string    `json:"interface"`
	Priority        int       `json:"priority"`
}
type Preview struct {
	Firewalld           *FirewalldPreview `json:"firewalld"`
	TransactionHash     string            `json:"transaction_hash"`
	TransactionBytes    int               `json:"transaction_bytes"`
	TransactionMessages int               `json:"transaction_messages"`
	Kernel              KernelView        `json:"kernel"`
	Version             int64             `json:"version"`
	PolicyHash          string            `json:"policy_hash"`
	Backend             string            `json:"backend"`
	Compiled            bool              `json:"compiled"`
	CanApply            bool              `json:"can_apply"`
	Table               string            `json:"table"`
	Chain               string            `json:"chain"`
	Hook                string            `json:"hook"`
	Priority            int               `json:"priority"`
	DefaultPolicy       string            `json:"default_policy"`
	LogicalRules        int               `json:"logical_rules"`
	GeneratedRules      int               `json:"generated_rules"`
	ProgramHash         string            `json:"program_hash"`
	Entries             []PreviewEntry    `json:"entries"`
	Truncated           bool              `json:"truncated"`
	ObservedAt          int64             `json:"observed_at"`
	Errors              []string          `json:"errors"`
	Warnings            []string          `json:"warnings"`
}

var ruleIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func requiredPolicyObject(raw []byte, out any, fields ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(out); e != nil {
		return e
	}
	var values map[string]json.RawMessage
	if e := json.Unmarshal(raw, &values); e != nil {
		return e
	}
	for _, field := range fields {
		value, ok := values[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fault.Invalid("防火墙请求缺少必填字段：" + field)
		}
	}
	return nil
}
func (r *Rule) UnmarshalJSON(raw []byte) error {
	type wire Rule
	var value wire
	if e := requiredPolicyObject(raw, &value, "id", "name", "enabled", "scope", "family", "protocol", "ports", "sources", "action", "priority", "interface", "comment"); e != nil {
		return e
	}
	*r = Rule(value)
	return nil
}
func (p *Policy) UnmarshalJSON(raw []byte) error {
	type wire Policy
	var value wire
	if e := requiredPolicyObject(raw, &value, "backend", "rules"); e != nil {
		return e
	}
	*p = Policy(value)
	return nil
}
func (p *PolicyInput) UnmarshalJSON(raw []byte) error {
	type wire PolicyInput
	var value wire
	if e := requiredPolicyObject(raw, &value, "base_version", "policy"); e != nil {
		return e
	}
	*p = PolicyInput(value)
	return nil
}

func DefaultPolicy() Policy   { return Policy{Backend: "direct-nftables", Rules: []Rule{}} }
func (p Policy) Hash() string { raw, _ := json.Marshal(p); return secure.Hash(raw) }
func policyText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func sourcePrefix(source string) (netip.Prefix, error) {
	if address, e := netip.ParseAddr(source); e == nil {
		if address.Zone() != "" || address.Is4In6() {
			return netip.Prefix{}, fmt.Errorf("invalid source")
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	prefix, e := netip.ParsePrefix(source)
	if e != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("invalid source")
	}
	return prefix, nil
}

// Normalize owns its slices and rejects an ambiguous family/source pairing.
// Port union and source ordering preserve the OR semantics within one rule.
func (p Policy) Normalize() (Policy, error) {
	if !slices.Contains([]string{"direct-nftables", "iptables-nft", "iptables-legacy", "firewalld", "ufw"}, p.Backend) || p.Rules == nil || len(p.Rules) > MaxRules {
		return Policy{}, fault.Invalid("防火墙后端或规则数量无效，最多 1000 条规则")
	}
	out := Policy{Backend: p.Backend, Rules: make([]Rule, 0, len(p.Rules))}
	seen := map[string]bool{}
	for index, r := range p.Rules {
		invalid := func(message string) (Policy, error) {
			return Policy{}, fault.Invalid(fmt.Sprintf("第 %d 条规则：%s", index+1, message))
		}
		if !ruleIDPattern.MatchString(r.ID) || r.ID == "00000000-0000-0000-0000-000000000000" || seen[r.ID] {
			return invalid("ID 必须为不重复的规范 UUID")
		}
		seen[r.ID] = true
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" || !policyText(r.Name, 512) || utf8.RuneCountInString(r.Name) > 128 || !policyText(r.Comment, 2048) || utf8.RuneCountInString(r.Comment) > 512 {
			return invalid("名称最多 128 字，备注最多 512 字，且不能包含控制字符")
		}
		if !slices.Contains([]string{"host_input", "docker_published"}, r.Scope) || !slices.Contains([]string{"ipv4", "ipv6", "both"}, r.Family) || !slices.Contains([]string{"tcp", "udp"}, r.Protocol) || !slices.Contains([]string{"allow", "deny", "reject"}, r.Action) || r.Priority < 0 || r.Priority > 1000000 {
			return invalid("流量范围、地址族、协议、动作或顺序无效")
		}
		if r.Interface != "" && (!interfacePattern.MatchString(r.Interface) || r.Interface == "." || r.Interface == "..") {
			return invalid("接口名须为 1–15 字节的实际接口名")
		}
		if len(r.Ports) < 1 || len(r.Ports) > 16 || r.Sources == nil || len(r.Sources) > 32 {
			return invalid("需提供 1–16 个端口区间及最多 32 个来源；空来源列表表示任意来源")
		}
		ports := slices.Clone(r.Ports)
		for _, port := range ports {
			if port.From < 1 || port.To > 65535 || port.To < port.From {
				return invalid("端口区间须处于 1–65535 且起点不大于终点")
			}
		}
		sort.Slice(ports, func(i, j int) bool {
			if ports[i].From != ports[j].From {
				return ports[i].From < ports[j].From
			}
			return ports[i].To < ports[j].To
		})
		r.Ports = []PortRange{}
		for _, port := range ports {
			last := len(r.Ports) - 1
			if last >= 0 && port.From <= r.Ports[last].To+1 {
				r.Ports[last].To = max(r.Ports[last].To, port.To)
			} else {
				r.Ports = append(r.Ports, port)
			}
		}
		r.Sources = make([]string, 0, len(p.Rules[index].Sources))
		sources := map[string]bool{}
		v4, v6 := false, false
		for _, source := range p.Rules[index].Sources {
			prefix, e := sourcePrefix(source)
			if e != nil {
				return invalid("来源须为 IP 地址或网络起点 CIDR，不能使用区域或映射地址")
			}
			if prefix.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
			canonical := prefix.String()
			if sources[canonical] {
				return invalid("来源规范化后重复")
			}
			sources[canonical] = true
			r.Sources = append(r.Sources, canonical)
		}
		if r.Family == "ipv4" && v6 || r.Family == "ipv6" && v4 || r.Family == "both" && len(r.Sources) > 0 && (!v4 || !v6) {
			return invalid("来源须覆盖所选地址族；双栈规则需同时提供 IPv4 和 IPv6 来源或使用空列表")
		}
		sort.Strings(r.Sources)
		out.Rules = append(out.Rules, r)
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Priority != out.Rules[j].Priority {
			return out.Rules[i].Priority < out.Rules[j].Priority
		}
		return out.Rules[i].ID < out.Rules[j].ID
	})
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > PolicyBytes {
		return Policy{}, fault.Invalid("防火墙策略超过 256 KiB")
	}
	return out, nil
}
