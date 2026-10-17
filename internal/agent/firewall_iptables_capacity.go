package agent

import (
	"errors"
	"slices"

	"nginxpanel/internal/firewall"
)

type iptablesNFTFamilyBudget struct {
	Bytes, Objects int
	Chains         []firewall.Chain
}

// Only the compiler's closed host-input grammar is admitted. These options
// produce inline payload/meta/bitwise/range/verdict/counter or xt statements,
// not anonymous sets or separate stateful objects. Each option pair reserves
// 512 bytes of schema-1 JSON structure and six bytes per value byte; the rule
// envelope separately reserves identities and maximum-width counters/handles.
// Adding an option requires reviewing this bound as well as the compiler.
func iptablesNFTRuleBytes(chain string, args []string) (int, error) {
	if _, err := firewall.IPTablesRuleText(args); err != nil || len(args)%2 != 0 {
		return 0, errors.New("iptables 生成规则不满足 nft JSON 容量语法")
	}
	reserved := 512 + 6*len(chain)
	for i := 0; i < len(args); i += 2 {
		switch args[i] {
		case "-m":
			if !slices.Contains([]string{"tcp", "udp", "conntrack", "comment"}, args[i+1]) {
				return 0, errors.New("iptables 匹配模块未纳入 nft JSON 容量准入")
			}
		case "-p", "--dport", "-s", "-i", "--ctstate", "--comment", "-j", "--reject-with":
		default:
			return 0, errors.New("iptables 生成选项未纳入 nft JSON 容量准入")
		}
		reserved += 512 + 6*len(args[i+1])
	}
	return reserved, nil
}

func iptablesNFTGenerationBudget(generation *firewall.IPTablesGeneration, docker bool) (iptablesNFTFamilyBudget, error) {
	anchor, ruleBytes := firewall.IPTablesHostChain, iptablesNFTRuleBytes
	if docker {
		anchor, ruleBytes = firewall.IPTablesDockerChain, dockerIPTablesNFTRuleBytes
	}
	out := iptablesNFTFamilyBudget{
		Bytes: 2 * 1024, Objects: len(generation.Rules) + 4,
		Chains: []firewall.Chain{{Name: anchor, Rules: 1}, {Name: generation.Chain, Rules: len(generation.Rules)}},
	}
	for _, rule := range append([]firewall.IPTablesRule{{Arguments: generation.Hook}, {Arguments: generation.Pointer}}, generation.Rules...) {
		// The generation chain name is the longest of the three identities.
		reserved, err := ruleBytes(generation.Chain, rule.Arguments)
		if err != nil {
			return out, err
		}
		out.Bytes += reserved
	}
	return out, nil
}
