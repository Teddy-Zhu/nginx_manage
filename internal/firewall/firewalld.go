package firewall

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const FirewalldHostPolicy = "nginxpanel-host"
const FirewalldHostPriority = -100
const FirewalldPolicyReadBytes = 512 << 10
const FirewalldPolicyReadTotalBytes = 2 << 20

// Leave room inside the observed dictionary budget for typed-field framing,
// default settings and the future root-owned identity metadata.
const FirewalldProgramBytes = 480 << 10

// These are official policy settings, not shell arguments or direct rules.
// The caller must separately establish ownership, runtime/permanent recovery
// and entry protections before sending any of these settings to the manager.
type FirewalldSettings struct {
	Priority     int32    `json:"priority"`
	Target       string   `json:"target"`
	IngressZones []string `json:"ingress_zones"`
	EgressZones  []string `json:"egress_zones"`
	RichRules    []string `json:"rich_rules"`
}
type FirewalldProgram struct {
	Settings FirewalldSettings
	Entries  []PreviewEntry
	Hash     string
	Bytes    int
}
type FirewalldPreview struct {
	Policy        string   `json:"policy"`
	Priority      int32    `json:"priority"`
	Target        string   `json:"target"`
	IngressZones  []string `json:"ingress_zones"`
	EgressZones   []string `json:"egress_zones"`
	SettingsBytes int      `json:"settings_bytes"`
}

func CompileFirewalld(policy Policy) (*FirewalldProgram, error) {
	normalized, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if normalized.Backend != "firewalld" {
		return nil, fault.Invalid("firewalld 编译器不接受其他目标后端")
	}
	for _, rule := range normalized.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Scope != "host_input" {
			return nil, fault.Unavailable("firewalld 主机 policy 不承接 Docker 发布端口，不能转换为主机入站规则")
		}
		if rule.Interface != "" {
			return nil, fault.Unavailable("firewalld rich rules 不提供入站接口选择；不能把规则接口隐式替换为 zone 绑定")
		}
	}
	program := &FirewalldProgram{
		Settings: FirewalldSettings{Priority: FirewalldHostPriority, Target: "CONTINUE", IngressZones: []string{"ANY"}, EgressZones: []string{"HOST"}, RichRules: []string{}},
		Entries:  []PreviewEntry{},
	}
	for _, rule := range normalized.Rules {
		if !rule.Enabled {
			continue
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			if rule.Family != "both" && rule.Family != family {
				continue
			}
			sources := []string{""}
			if len(rule.Sources) > 0 {
				sources = []string{}
				for _, source := range rule.Sources {
					prefix, _ := netip.ParsePrefix(source)
					if prefix.Addr().Is4() == (family == "ipv4") {
						sources = append(sources, source)
					}
				}
			}
			for _, source := range sources {
				for _, port := range rule.Ports {
					if len(program.Entries) >= MaxEntries {
						return nil, fault.Invalid("firewalld 规则展开后超过 8192 条，请缩小端口和来源组合")
					}
					// Every expanded rule has a distinct negative priority. This
					// preserves policy order even across different verdicts; zero
					// would group rules by action, and equal priorities are unordered.
					priority := -32768 + len(program.Entries)
					var text strings.Builder
					text.WriteString("rule family=\"")
					text.WriteString(family)
					text.WriteString("\" priority=\"")
					text.WriteString(strconv.Itoa(priority))
					text.WriteByte('"')
					if source != "" {
						text.WriteString(" source address=\"")
						text.WriteString(source)
						text.WriteByte('"')
					}
					text.WriteString(" port port=\"")
					text.WriteString(strconv.Itoa(port.From))
					if port.To != port.From {
						text.WriteByte('-')
						text.WriteString(strconv.Itoa(port.To))
					}
					text.WriteString("\" protocol=\"")
					text.WriteString(rule.Protocol)
					text.WriteString("\" ")
					switch rule.Action {
					case "allow":
						text.WriteString("accept")
					case "deny":
						text.WriteString("drop")
					case "reject":
						kind := "icmp-port-unreachable"
						if family == "ipv6" {
							kind = "icmp6-port-unreachable"
						}
						if rule.Protocol == "tcp" {
							kind = "tcp-reset"
						}
						text.WriteString("reject type=\"")
						text.WriteString(kind)
						text.WriteByte('"')
					}
					rich := text.String()
					program.Settings.RichRules = append(program.Settings.RichRules, rich)
					program.Entries = append(program.Entries, PreviewEntry{RuleID: rule.ID, Family: family, Protocol: rule.Protocol, Source: source, Ports: port, Action: rule.Action, Priority: rule.Priority, BackendPriority: &priority, Expression: rich})
				}
			}
		}
	}
	raw, err := json.Marshal(program.Settings)
	if err != nil {
		return nil, err
	}
	if len(raw) > FirewalldProgramBytes {
		return nil, fault.Invalid("firewalld policy 配置超过 480 KiB，请缩小规则组合")
	}
	program.Bytes = len(raw)
	program.Hash = secure.Hash(append([]byte("firewalld:policy:v1:"+FirewalldHostPolicy+"\x00"), raw...))
	return program, nil
}

func (p *FirewalldProgram) Preview() *FirewalldPreview {
	return &FirewalldPreview{Policy: FirewalldHostPolicy, Priority: p.Settings.Priority, Target: p.Settings.Target, IngressZones: append([]string{}, p.Settings.IngressZones...), EgressZones: append([]string{}, p.Settings.EgressZones...), SettingsBytes: p.Bytes}
}
