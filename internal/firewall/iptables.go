package firewall

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const IPTablesHostChain = "NGINXPANEL-HOST"
const IPTablesProgramBytes = 2 << 20

// Arguments contain only a generated rule specification. No command, chain
// mutation, executable path, ownership claim or caller-supplied shell enters it.
type IPTablesRule struct {
	Arguments []string `json:"arguments"`
}
type IPTablesFamilyProgram struct {
	Family string         `json:"family"`
	Binary string         `json:"binary"`
	Rules  []IPTablesRule `json:"rules"`
}
type IPTablesProgram struct {
	Backend         string
	Families        []IPTablesFamilyProgram
	Entries         []PreviewEntry
	Hash            string
	Bytes           int
	BaseRules       int
	ProtectionRules int
}
type IPTablesPreview struct {
	ProgramBytes    int                     `json:"program_bytes"`
	BaseRules       int                     `json:"base_rules"`
	ProtectionRules int                     `json:"protection_rules"`
	Families        []IPTablesFamilyPreview `json:"families"`
}
type IPTablesFamilyPreview struct {
	Family         string `json:"family"`
	Binary         string `json:"binary"`
	GeneratedRules int    `json:"generated_rules"`
}

func CompileIPTables(policy Policy) (*IPTablesProgram, error) {
	return CompileIPTablesProtected(policy, nil)
}

// Entry protections precede business rules within each family. An allow uses
// ACCEPT and may finish the caller's filter traversal; unmatched traffic returns
// to its remaining rules. Docker forwarding needs a different verdict contract.
func CompileIPTablesProtected(policy Policy, protections []Protection) (*IPTablesProgram, error) {
	normalized, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"iptables-nft", "iptables-legacy"}, normalized.Backend) {
		return nil, fault.Invalid("iptables 编译器只接受显式 nft 或 legacy 后端")
	}
	guards, err := protectionPolicy(protections, normalized.Backend)
	if err != nil {
		return nil, err
	}
	guards, err = guards.Normalize()
	if err != nil {
		return nil, err
	}
	program := &IPTablesProgram{Backend: normalized.Backend, Families: []IPTablesFamilyProgram{}, Entries: []PreviewEntry{}}
	families := map[string]*IPTablesFamilyProgram{}
	count := 0
	appendRule := func(family string, args []string) error {
		if count >= MaxEntries {
			return fault.Invalid("包含保护项的 iptables 规则展开后超过 8192 条，请缩小端口和来源组合")
		}
		families[family].Rules = append(families[family].Rules, IPTablesRule{Arguments: args})
		count++
		return nil
	}
	for section, rules := range [][]Rule{guards.Rules, normalized.Rules} {
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			if rule.Scope != "host_input" {
				return nil, fault.Unavailable("iptables 主机入站编译不承接 Docker 发布端口；转发路径须另行核对 DOCKER-USER 与原始目的信息")
			}
			if strings.HasPrefix(rule.Interface, "-") {
				return nil, fault.Invalid("iptables 接口名称不能以连字符开头")
			}
			for _, family := range []string{"ipv4", "ipv6"} {
				if rule.Family != "both" && rule.Family != family {
					continue
				}
				sources := []string{"0.0.0.0/0"}
				if family == "ipv6" {
					sources[0] = "::/0"
				}
				if len(rule.Sources) > 0 {
					sources = []string{}
					for _, source := range rule.Sources {
						prefix, _ := netip.ParsePrefix(source)
						if prefix.Addr().Is4() == (family == "ipv4") {
							sources = append(sources, source)
						}
					}
				}
				if len(sources) == 0 {
					continue
				}
				if families[family] == nil {
					binary := normalized.Backend
					if family == "ipv6" {
						binary = "ip6tables-" + strings.TrimPrefix(binary, "iptables-")
					}
					families[family] = &IPTablesFamilyProgram{Family: family, Binary: binary, Rules: []IPTablesRule{}}
					for _, args := range [][]string{{"-i", "lo", "-j", "RETURN"}, {"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"}} {
						if err = appendRule(family, args); err != nil {
							return nil, err
						}
						program.BaseRules++
					}
				}
				for _, source := range sources {
					for _, ports := range rule.Ports {
						port := strconv.Itoa(ports.From)
						if ports.From != ports.To {
							port += ":" + strconv.Itoa(ports.To)
						}
						args := []string{"-p", rule.Protocol, "-m", rule.Protocol, "--dport", port, "-s", source, "-m", "conntrack", "--ctstate", "NEW"}
						if rule.Interface != "" {
							args = append(args, "-i", rule.Interface)
						}
						comment := "nginxpanel:host:v1:" + rule.ID
						args = append(args, "-m", "comment", "--comment", comment)
						switch rule.Action {
						case "allow":
							args = append(args, "-j", "ACCEPT")
						case "deny":
							args = append(args, "-j", "DROP")
						case "reject":
							reject := "icmp-port-unreachable"
							if family == "ipv6" {
								reject = "icmp6-port-unreachable"
							}
							if rule.Protocol == "tcp" {
								reject = "tcp-reset"
							}
							args = append(args, "-j", "REJECT", "--reject-with", reject)
						}
						if err = appendRule(family, args); err != nil {
							return nil, err
						}
						if section == 0 {
							program.ProtectionRules++
						}
						program.Entries = append(program.Entries, PreviewEntry{RuleID: rule.ID, Family: family, Protocol: rule.Protocol, Source: source, Ports: ports, Action: rule.Action, Interface: rule.Interface, Priority: rule.Priority, Expression: families[family].Binary + " -t filter -A " + IPTablesHostChain + " " + strings.Join(args, " ")})
					}
				}
			}
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if compiled := families[family]; compiled != nil {
			program.Families = append(program.Families, *compiled)
		}
	}
	raw, err := json.Marshal(struct {
		Backend, Table, Chain, Hook, DefaultTarget string
		Families                                   []IPTablesFamilyProgram
	}{normalized.Backend, "filter", IPTablesHostChain, "INPUT", "RETURN", program.Families})
	if err != nil {
		return nil, err
	}
	if len(raw) > IPTablesProgramBytes {
		return nil, fault.Invalid("iptables 完整生成参数超过 2 MiB，请缩小规则组合")
	}
	program.Bytes, program.Hash = len(raw), secure.Hash(append([]byte("iptables:host:v1:\x00"), raw...))
	return program, nil
}

func (p *IPTablesProgram) Preview() *IPTablesPreview {
	out := &IPTablesPreview{ProgramBytes: p.Bytes, BaseRules: p.BaseRules, ProtectionRules: p.ProtectionRules, Families: []IPTablesFamilyPreview{}}
	for _, family := range p.Families {
		out.Families = append(out.Families, IPTablesFamilyPreview{Family: family.Family, Binary: family.Binary, GeneratedRules: len(family.Rules)})
	}
	return out
}
