package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"nginxpanel/internal/fault"
)

// A final unrestricted port rule is an intentional fallback, not an
// accidental conflict with the exceptions above it.
func defaultPortRule(rule Rule) bool {
	return rule.Enabled && rule.Scope == "host_input" && rule.Family == "both" &&
		rule.Interface == "" && len(rule.Sources) == 0 &&
		len(rule.Ports) == 1 && rule.Ports[0] == (PortRange{From: 1, To: 65535})
}

func portCoverage(a, b Rule) bool {
	for _, target := range b.Ports {
		covered := false
		for _, source := range a.Ports {
			if source.From <= target.From && source.To >= target.To {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func ruleIntervals(rule Rule, family string) []addressInterval {
	if rule.Family != "both" && rule.Family != family {
		return nil
	}
	if len(rule.Sources) != 0 {
		return sourceIntervals(rule.Sources, family)
	}
	if family == "ipv4" {
		return []addressInterval{{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")}}
	}
	return []addressInterval{{netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}}
}

func intervalsCover(source, target []addressInterval) bool {
	i := 0
	for _, interval := range target {
		for i < len(source) && source[i].Last.Compare(interval.First) < 0 {
			i++
		}
		if i == len(source) || source[i].First.Compare(interval.First) > 0 || source[i].Last.Compare(interval.Last) < 0 {
			return false
		}
	}
	return true
}

// Check individual complete shadows; partial overlaps remain confirmable.
// Intervals are merged once, including GeoIP sets, rather than compared by CIDR.
func policyProblems(policy Policy) []string {
	ranges := make([][2][]addressInterval, len(policy.Rules))
	for i, rule := range policy.Rules {
		if rule.Enabled {
			ranges[i] = [2][]addressInterval{ruleIntervals(rule, "ipv4"), ruleIntervals(rule, "ipv6")}
		}
	}
	problems := []string{}
	for j, b := range policy.Rules {
		if !b.Enabled {
			continue
		}
		for i := 0; i < j; i++ {
			a := policy.Rules[i]
			if !a.Enabled || a.Scope != b.Scope || a.Interface != "" && a.Interface != b.Interface ||
				a.Protocol != "any" && a.Protocol != b.Protocol || !portCoverage(a, b) {
				continue
			}
			if intervalsCover(ranges[i][0], ranges[j][0]) && intervalsCover(ranges[i][1], ranges[j][1]) {
				kind := "完全覆盖，无法生效，请将其移到前面或修改访问范围"
				if a.Action == b.Action {
					kind = "包含，无需重复添加，请删除或合并重复规则"
				}
				problems = append(problems, fmt.Sprintf("规则“%s”已被前面的“%s”%s", b.Name, a.Name, kind))
				break
			}
		}
		if len(problems) == 8 {
			break
		}
	}
	return problems
}

func checkPolicyOrder(policy Policy) error {
	if problems := policyProblems(policy); len(problems) > 0 {
		return fault.New(409, "FIREWALL_RULE_SHADOWED", strings.Join(problems, "；"))
	}
	return nil
}

func matchHash(rule Rule) string {
	rule.Priority = 0
	rule.Name = ""
	rule.Comment = ""
	rule.Countries = nil
	rule.GeoIPUpdatedAt = 0
	raw, _ := json.Marshal(rule)
	return string(raw)
}

// Existing overlaps are unchanged unless either match or their relative order changes.
func policyConflicts(policy, previous Policy) []string {
	old := map[string]Rule{}
	positions := map[string]int{}
	for i, rule := range previous.Rules {
		old[rule.ID] = rule
		positions[rule.ID] = i
	}
	ranges := make([]map[string][]addressInterval, len(policy.Rules))
	for i, rule := range policy.Rules {
		ranges[i] = map[string][]addressInterval{"ipv4": sourceIntervals(rule.Sources, "ipv4"), "ipv6": sourceIntervals(rule.Sources, "ipv6")}
	}
	conflicts := []string{}
	for i, a := range policy.Rules {
		if !a.Enabled {
			continue
		}
		for j := i + 1; j < len(policy.Rules); j++ {
			b := policy.Rules[j]
			if defaultPortRule(b) && !defaultPortRule(a) && (j == len(policy.Rules)-1 || j == len(policy.Rules)-2 && defaultPortRule(policy.Rules[j+1])) {
				continue
			}
			if !b.Enabled || a.Action == b.Action || a.Action != "allow" && b.Action != "allow" || a.Scope != b.Scope || a.Interface != "" && b.Interface != "" && a.Interface != b.Interface || a.Protocol != "any" && b.Protocol != "any" && a.Protocol != b.Protocol {
				continue
			}
			oldA, okA := old[a.ID]
			oldB, okB := old[b.ID]
			if okA && okB && positions[a.ID] < positions[b.ID] && matchHash(a) == matchHash(oldA) && matchHash(b) == matchHash(oldB) {
				continue
			}
			ports := false
			for _, x := range a.Ports {
				for _, y := range b.Ports {
					if x.From <= y.To && y.From <= x.To {
						ports = true
						break
					}
				}
			}
			if !ports {
				continue
			}
			overlaps := false
			for _, family := range []string{"ipv4", "ipv6"} {
				if a.Family != "both" && a.Family != family || b.Family != "both" && b.Family != family {
					continue
				}
				if len(a.Sources) > 0 && len(ranges[i][family]) == 0 || len(b.Sources) > 0 && len(ranges[j][family]) == 0 {
					continue
				}
				if len(a.Sources) == 0 || len(b.Sources) == 0 {
					overlaps = true
					break
				}
				x, y := ranges[i][family], ranges[j][family]
				left, right := 0, 0
				for left < len(x) && right < len(y) {
					if x[left].First.Compare(y[right].Last) <= 0 && y[right].First.Compare(x[left].Last) <= 0 {
						overlaps = true
						break
					}
					if x[left].Last.Compare(y[right].Last) < 0 {
						left++
					} else {
						right++
					}
				}
				if overlaps {
					break
				}
			}
			if overlaps {
				conflicts = append(conflicts, a.Name+" / "+b.Name)
				if len(conflicts) == 8 {
					return conflicts
				}
			}
		}
	}
	return conflicts
}
func conflictMessage(names []string) string {
	return "以下规则的访问范围重叠且处理方式不同：" + strings.Join(names, "；") + "。列表中靠前的规则优先生效，请确认覆盖现有匹配行为。"
}
