package firewall

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const DockerTargetBytes = 96 << 10
const IPTablesDockerChain = "NGINXPANEL-DOCKER"

// Targets belong to one local planning request, never to a portable Policy.
// The report hashes select evidence; they grant neither ownership nor execution.
type DockerTargets struct {
	EngineHash   string              `json:"engine_hash"`
	SnapshotHash string              `json:"snapshot_hash"`
	Bindings     []DockerRuleBinding `json:"bindings"`
}

type DockerRuleBinding struct {
	RuleID         string `json:"rule_id"`
	ContainerID    string `json:"container_id"`
	NetworkID      string `json:"network_id"`
	Family         string `json:"family"`
	Protocol       string `json:"protocol"`
	HostIP         string `json:"host_ip"`
	HostPort       int    `json:"host_port"`
	ContainerPort  int    `json:"container_port"`
	Destination    string `json:"destination"`
	InputInterface string `json:"input_interface"`
}

// Only the host resolver supplies the endpoint and bridge. A binding is not a
// packet trace, an execution grant, or a claim about other published mappings.
type DockerResolvedBinding struct {
	Binding          DockerRuleBinding `json:"binding"`
	ContainerAddress string            `json:"container_address"`
	OutputInterface  string            `json:"output_interface"`
}

type DockerLocalAddress struct {
	Interface string `json:"interface"`
	Family    string `json:"family"`
	Address   string `json:"address"`
}

type DockerPlan struct {
	EngineHash         string                  `json:"engine_hash"`
	SnapshotHash       string                  `json:"snapshot_hash"`
	ConfigurationHash  string                  `json:"configuration_hash"`
	BindingsHash       string                  `json:"bindings_hash"`
	ObservedAt         int64                   `json:"observed_at"`
	Ports              []DockerPublishedPort   `json:"ports"`
	Truncated          bool                    `json:"truncated"`
	Addresses          []DockerLocalAddress    `json:"addresses"`
	Bindings           []DockerResolvedBinding `json:"bindings"`
	Compiled           bool                    `json:"compiled"`
	ProgramHash        string                  `json:"program_hash"`
	ProgramBytes       int                     `json:"program_bytes"`
	GeneratedRules     int                     `json:"generated_rules"`
	HostProgramHash    string                  `json:"host_program_hash"`
	HostGeneratedRules int                     `json:"host_generated_rules"`
	Entries            []PreviewEntry          `json:"entries"`
	EntriesTruncated   bool                    `json:"entries_truncated"`
	Warnings           []string                `json:"warnings"`
	Reason             string                  `json:"reason"`
}

var dockerDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func HasDockerRules(policy Policy) bool {
	return slices.ContainsFunc(policy.Rules, func(rule Rule) bool { return rule.Enabled && rule.Scope == "docker_published" })
}

func HostPolicy(policy Policy) Policy {
	out := Policy{Backend: policy.Backend, Rules: []Rule{}}
	for _, rule := range policy.Rules {
		if rule.Scope == "host_input" {
			out.Rules = append(out.Rules, rule)
		}
	}
	return out
}

func DockerTargetAddress(value, family string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.String() == value && ip.Zone() == "" && !ip.Is4In6() && ip.Is4() == (family == "ipv4") && (family == "ipv4" || family == "ipv6") && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func DockerTargetInterface(value string) bool {
	return interfacePattern.MatchString(value) && value != "." && value != ".." && !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, ":+")
}

func dockerBindingKey(binding DockerRuleBinding) string {
	raw, _ := json.Marshal(binding)
	return string(raw)
}

// Each selected rule/family/host-port must be covered explicitly. A port range
// cannot silently shrink to the subset currently published by Docker.
func (targets DockerTargets) Normalize(policy Policy) (DockerTargets, error) {
	policy, err := policy.Normalize()
	if err != nil {
		return DockerTargets{}, err
	}
	invalid := func() (DockerTargets, error) {
		return DockerTargets{}, fault.Invalid("Docker 目标绑定无效、重复、未完整覆盖规则或超过 128 项")
	}
	if !HasDockerRules(policy) || !dockerDigest.MatchString(targets.EngineHash) || !dockerDigest.MatchString(targets.SnapshotHash) || targets.Bindings == nil || len(targets.Bindings) < 1 || len(targets.Bindings) > 128 {
		return invalid()
	}
	rules := map[string]Rule{}
	needed := map[string]bool{}
	coverageKey := func(id, family string, port int) string { return id + ":" + family + ":" + strconv.Itoa(port) }
	for _, rule := range policy.Rules {
		if !rule.Enabled || rule.Scope != "docker_published" {
			continue
		}
		rules[rule.ID] = rule
		for _, family := range []string{"ipv4", "ipv6"} {
			if rule.Family != "both" && rule.Family != family {
				continue
			}
			for _, ports := range rule.Ports {
				if ports.To-ports.From+1 > 128 {
					return invalid()
				}
				for port := ports.From; port <= ports.To; port++ {
					needed[coverageKey(rule.ID, family, port)] = true
					if len(needed) > 128 {
						return invalid()
					}
				}
			}
		}
	}
	out := targets
	out.Bindings = slices.Clone(targets.Bindings)
	seen := map[string]bool{}
	paths := map[string]bool{}
	for _, binding := range out.Bindings {
		rule, ok := rules[binding.RuleID]
		key := dockerBindingKey(binding)
		covered := coverageKey(binding.RuleID, binding.Family, binding.HostPort)
		path := covered + ":" + binding.Destination + ":" + binding.InputInterface
		if !ok || seen[key] || paths[path] || !dockerDigest.MatchString(binding.ContainerID) || !dockerDigest.MatchString(binding.NetworkID) || binding.Protocol != rule.Protocol || !DockerTargetAddress(binding.Destination, binding.Family) || binding.ContainerPort < 1 || binding.ContainerPort > 65535 || !DockerTargetInterface(binding.InputInterface) || rule.Interface != "" && rule.Interface != binding.InputInterface {
			return invalid()
		}
		if _, exists := needed[covered]; !exists {
			return invalid()
		}
		host, err := netip.ParseAddr(binding.HostIP)
		if err != nil || host.String() != binding.HostIP || host.Zone() != "" || host.Is4In6() || host.Is4() != (binding.Family == "ipv4") || !host.IsUnspecified() && binding.HostIP != binding.Destination {
			return invalid()
		}
		seen[key], paths[path], needed[covered] = true, true, false
	}
	for _, missing := range needed {
		if missing {
			return invalid()
		}
	}
	slices.SortFunc(out.Bindings, func(a, b DockerRuleBinding) int { return strings.Compare(dockerBindingKey(a), dockerBindingKey(b)) })
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > DockerTargetBytes {
		return invalid()
	}
	return out, nil
}

func DockerPlanHash(policy Policy, plan *DockerPlan) string {
	if plan == nil || !plan.Compiled {
		return ""
	}
	return secure.Hash([]byte("docker:combined-preview:v1:\x00" + policy.Hash() + ":" + plan.ConfigurationHash + ":" + plan.HostProgramHash + ":" + plan.ProgramHash))
}

// This separate program cannot enter the host INPUT generation executor.
// RETURN hands an allowed mapping back to DOCKER-USER and Docker's traversal.
type DockerIPTablesProgram struct {
	Backend, BindingsHash, Hash string
	Families                    []IPTablesFamilyProgram
	Entries                     []PreviewEntry
	Bytes                       int
}

func CompileDockerIPTables(policy Policy, targets DockerTargets, resolved []DockerResolvedBinding) (*DockerIPTablesProgram, error) {
	policy, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	targets, err = targets.Normalize(policy)
	if err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"iptables-nft", "iptables-legacy"}, policy.Backend) || len(resolved) != len(targets.Bindings) {
		return nil, fault.Invalid("Docker 编译要求显式 iptables 后端和完整目标解析")
	}
	resolved = slices.Clone(resolved)
	slices.SortFunc(resolved, func(a, b DockerResolvedBinding) int {
		return strings.Compare(dockerBindingKey(a.Binding), dockerBindingKey(b.Binding))
	})
	for index, binding := range resolved {
		if binding.Binding != targets.Bindings[index] || !DockerTargetAddress(binding.ContainerAddress, binding.Binding.Family) || binding.ContainerAddress == binding.Binding.Destination || !DockerTargetInterface(binding.OutputInterface) || binding.OutputInterface == binding.Binding.InputInterface {
			return nil, fault.Invalid("Docker 容器端点或 bridge 出口解析无效")
		}
	}
	raw, err := json.Marshal(struct {
		Targets  DockerTargets
		Resolved []DockerResolvedBinding
	}{targets, resolved})
	if err != nil {
		return nil, err
	}
	out := &DockerIPTablesProgram{Backend: policy.Backend, BindingsHash: secure.Hash(append([]byte("docker:targets:v1:\x00"), raw...)), Families: []IPTablesFamilyProgram{}, Entries: []PreviewEntry{}}
	count := 0
	for _, family := range []string{"ipv4", "ipv6"} {
		binary := policy.Backend
		if family == "ipv6" {
			binary = "ip6tables-" + strings.TrimPrefix(binary, "iptables-")
		}
		compiled := IPTablesFamilyProgram{Family: family, Binary: binary, Rules: []IPTablesRule{}}
		for _, rule := range policy.Rules {
			for _, binding := range resolved {
				b := binding.Binding
				if b.RuleID != rule.ID || b.Family != family {
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
				for _, source := range sources {
					args := []string{"-i", b.InputInterface, "-o", binding.OutputInterface, "-p", b.Protocol, "-m", b.Protocol, "-d", binding.ContainerAddress, "--dport", strconv.Itoa(b.ContainerPort), "-s", source, "-m", "conntrack", "--ctstate", "NEW", "--ctdir", "ORIGINAL", "--ctproto", b.Protocol, "--ctorigdst", b.Destination, "--ctorigdstport", strconv.Itoa(b.HostPort), "-m", "comment", "--comment", "nginxpanel:docker:v1:" + rule.ID}
					switch rule.Action {
					case "allow":
						args = append(args, "-j", "RETURN")
					case "deny":
						args = append(args, "-j", "DROP")
					case "reject":
						reject := "icmp-port-unreachable"
						if family == "ipv6" {
							reject = "icmp6-port-unreachable"
						}
						if b.Protocol == "tcp" {
							reject = "tcp-reset"
						}
						args = append(args, "-j", "REJECT", "--reject-with", reject)
					}
					text, err := IPTablesRuleText(args)
					if err != nil {
						return nil, err
					}
					count++
					if count > MaxEntries {
						return nil, fault.Invalid("Docker 目标与来源展开后超过 8192 条")
					}
					compiled.Rules = append(compiled.Rules, IPTablesRule{Arguments: args})
					out.Entries = append(out.Entries, PreviewEntry{RuleID: rule.ID, Family: family, Protocol: b.Protocol, Source: source, Ports: PortRange{From: b.HostPort, To: b.HostPort}, Action: rule.Action, Interface: b.InputInterface, Priority: rule.Priority, Expression: binary + " -t filter -A " + IPTablesDockerChain + " " + text})
				}
			}
		}
		if len(compiled.Rules) > 0 {
			out.Families = append(out.Families, compiled)
		}
	}
	raw, err = json.Marshal(struct {
		Backend, PolicyHash, BindingsHash, Chain, Hook, DefaultTarget string
		Families                                                      []IPTablesFamilyProgram
	}{out.Backend, policy.Hash(), out.BindingsHash, IPTablesDockerChain, "DOCKER-USER", "RETURN", out.Families})
	if err != nil {
		return nil, err
	}
	if len(raw) > IPTablesProgramBytes {
		return nil, fault.Invalid("Docker 完整生成参数超过 2 MiB")
	}
	out.Bytes, out.Hash = len(raw), secure.Hash(append([]byte("iptables:docker:v1:\x00"), raw...))
	return out, nil
}
