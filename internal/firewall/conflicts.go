package firewall

import (
	"encoding/json"
	"strings"
)

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
