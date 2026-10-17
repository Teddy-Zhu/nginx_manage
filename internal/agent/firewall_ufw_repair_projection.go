package agent

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
)

// Repair inserts only packets recompiled from the root confirmation. No chain
// declarations are emitted: --noflush would still flush a declared user chain.
// The current native file supplies positions and proves every foreign packet.
func ufwRepairProjection(raw []byte, family string, before []ufwReloadChain, owned []ufwNativeRule) ([]ufwReloadChain, []byte, error) {
	invalid := errors.New("UFW 运行漂移不能证明仅缺失原确认规则，禁止修复")
	file, err := parseUFWNative(raw, family, true)
	if err != nil {
		return nil, nil, err
	}
	if _, err = ufwUnownedRules(file, family, owned); err != nil {
		return nil, nil, err
	}
	expected, err := ufwReloadConfigured(raw, family)
	if err != nil {
		return nil, nil, err
	}
	names := ufwNativeChainNames(family)
	if len(names) == 0 || len(before) != len(names) {
		return nil, nil, invalid
	}
	input := names[0]
	packets := map[string]string{}
	for _, rule := range owned {
		if rule.Family != family {
			continue
		}
		for _, packet := range rule.Packets {
			chain, key, insert, err := ufwKernelRuleKey(packet, family, true)
			if err != nil || insert || chain != input || !strings.HasPrefix(packet, "-A "+input+" ") || packets[key] != "" {
				return nil, nil, invalid
			}
			packets[key] = packet[len("-A "+input+" "):]
		}
	}
	after := make([]ufwReloadChain, len(before))
	var payload strings.Builder
	payload.WriteString("*filter\n")
	missing, count := 0, 0
	for index, chain := range before {
		if chain.Name != names[index] || !chain.Present && len(chain.Rules) != 0 || chain.Name == input && !chain.Present {
			return nil, nil, invalid
		}
		rules := expected[chain.Name]
		if !chain.Present && len(rules) != 0 {
			return nil, nil, invalid
		}
		count += len(rules) + len(chain.Rules)
		if count > 2*firewall.MaxEntries {
			return nil, nil, invalid
		}
		after[index] = ufwReloadChain{Name: chain.Name, Present: chain.Present, Rules: slices.Clone(rules)}
		occurrences := map[string]int{}
		for _, key := range rules {
			occurrences[key]++
		}
		cursor := 0
		for position, key := range rules {
			if cursor < len(chain.Rules) && chain.Rules[cursor] == key {
				cursor++
				continue
			}
			// Equal foreign selectors make absence/position ambiguous. Never
			// infer ownership from an indistinguishable kernel expression.
			packet := packets[key]
			if chain.Name != input || packet == "" || occurrences[key] != 1 {
				return nil, nil, invalid
			}
			fmt.Fprintf(&payload, "-I %s %d %s\n", input, position+1, packet)
			missing++
		}
		if cursor != len(chain.Rules) {
			return nil, nil, invalid
		}
	}
	if missing == 0 {
		return after, nil, nil
	}
	payload.WriteString("COMMIT\n")
	if payload.Len() > firewall.UFWReadBytes {
		return nil, nil, invalid
	}
	return after, []byte(payload.String()), nil
}

func ufwRepairUserPath(family string) string {
	if family == "ipv4" {
		return "/etc/ufw/user.rules"
	}
	return "/etc/ufw/user6.rules"
}
