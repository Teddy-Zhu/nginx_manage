package agent

import (
	"encoding/json"
	"errors"
	"fmt"
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

func iptablesNFTGenerationBudget(generation *firewall.IPTablesGeneration) (iptablesNFTFamilyBudget, error) {
	out := iptablesNFTFamilyBudget{
		Bytes: 2 * 1024, Objects: len(generation.Rules) + 4,
		Chains: []firewall.Chain{{Name: firewall.IPTablesHostChain, Rules: 1}, {Name: generation.Chain, Rules: len(generation.Rules)}},
	}
	for _, rule := range append([]firewall.IPTablesRule{{Arguments: generation.Hook}, {Arguments: generation.Pointer}}, generation.Rules...) {
		// The generation chain name is the longest of the three identities.
		reserved, err := iptablesNFTRuleBytes(generation.Chain, rule.Arguments)
		if err != nil {
			return out, err
		}
		out.Bytes += reserved
	}
	return out, nil
}

// Reserve the largest old/new contribution independently for each family, so
// every partially switched and compensated combination remains observable.
// Native-save proofs identify the current owned chains before their actual JSON
// bytes are deducted. INPUT hooks and JSON separators remain in the baseline,
// making this conservative without charging for an entire second generation.
func (snapshot iptablesRegistrationSnapshot) admitReadback(program, previous *firewall.IPTablesRuntimeProgram, targets ...*firewall.IPTablesRuntimeProgram) error {
	capacity := snapshot.NFT
	if !capacity.complete() {
		return errors.New("完整 nft JSON 容量或 schema 1 无法核对")
	}
	programs := []*firewall.IPTablesRuntimeProgram{program, previous}
	if targets == nil {
		targets = programs
	}
	backend := ""
	for _, program := range programs {
		if program == nil {
			continue
		}
		if !validIPTablesBackend(program.Backend) || backend != "" && backend != program.Backend {
			return errors.New("iptables 容量准入的后端不一致")
		}
		backend = program.Backend
	}
	if backend == "" {
		return errors.New("iptables 容量准入缺少原程序")
	}
	projectedBytes, projectedObjects := capacity.Bytes+capacity.NumberGrowth, capacity.Objects
	if backend == "iptables-legacy" {
		if projectedBytes > nftRulesetReadBytes {
			return errors.New("完整 nft JSON 视图未保留数值增长的读取容量")
		}
		return nil
	}
	owned := map[string]bool{}
	for _, image := range snapshot.Images {
		if proveIPTablesGeneration(image, nil) == nil {
			continue
		}
		var matched *firewall.IPTablesGeneration
		for _, program := range programs {
			if generation := iptablesGeneration(program, image.Family); generation != nil {
				if _, err := repairIPTablesMaterial(image, *generation); err == nil {
					matched = generation
					break
				}
			}
		}
		if matched == nil {
			return errors.New("iptables 当前受管范围无法用于 nft JSON 容量核对")
		}
		family := "ip"
		if image.Family == "ipv6" {
			family = "ip6"
		}
		for _, name := range []string{firewall.IPTablesHostChain, matched.Chain} {
			if chain := image.chain("filter", name); chain != nil {
				key := nftReadbackKey(family, "filter", name)
				scope, exists := capacity.Scopes[key]
				if !exists || scope.Rules != len(chain.Rules) || scope.Objects != len(chain.Rules)+1 {
					return errors.New("nft JSON 与 iptables 当前受管范围在容量核对期间变化")
				}
				owned[key] = true
				projectedBytes -= scope.Bytes + scope.NumberGrowth
				projectedObjects -= scope.Objects
			}
		}
	}
	if projectedBytes < 0 || projectedObjects < 0 {
		return errors.New("nft JSON 当前范围容量无效")
	}
	metadata := []firewall.Table{}
	for _, ruleset := range snapshot.Observed.Rulesets {
		if ruleset.ID != "nftables" || !ruleset.Available {
			continue
		}
		for _, table := range ruleset.Tables {
			view := table
			view.Chains = []firewall.Chain{}
			for _, chain := range table.Chains {
				if !owned[nftReadbackKey(table.Family, table.Name, chain.Name)] {
					view.Chains = append(view.Chains, chain)
				}
			}
			metadata = append(metadata, view)
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		maximum := iptablesNFTFamilyBudget{}
		metadataBytes := 0
		for _, program := range targets {
			generation := iptablesGeneration(program, family)
			if generation == nil {
				continue
			}
			reserved, err := iptablesNFTGenerationBudget(generation)
			if err != nil {
				return err
			}
			maximum.Bytes = max(maximum.Bytes, reserved.Bytes)
			maximum.Objects = max(maximum.Objects, reserved.Objects)
			raw, err := json.Marshal(reserved.Chains)
			if err != nil {
				return err
			}
			if len(raw) > metadataBytes {
				maximum.Chains, metadataBytes = reserved.Chains, len(raw)
			}
		}
		if maximum.Objects == 0 {
			continue
		}
		projectedBytes += maximum.Bytes
		projectedObjects += maximum.Objects
		nftFamily := "ip"
		if family == "ipv6" {
			nftFamily = "ip6"
		}
		found := false
		for index := range metadata {
			table := &metadata[index]
			if table.Family != nftFamily || table.Name != "filter" {
				continue
			}
			for ci := range table.Chains {
				chain := &table.Chains[ci]
				for _, candidate := range maximum.Chains {
					if chain.Name == candidate.Name {
						return errors.New("nft JSON 候选链存在未核对的同名范围")
					}
				}
				if chain.Name == "INPUT" {
					chain.Rules++
					found = true
				}
			}
			table.Chains = append(table.Chains, maximum.Chains...)
		}
		if !found {
			return errors.New("nft JSON 缺少候选地址族的 filter/INPUT 容量依据")
		}
	}
	if projectedBytes > nftRulesetReadBytes || projectedObjects > firewallObjectLimit {
		return fmt.Errorf("iptables 候选及原策略恢复的完整 nft JSON 容量需要 %d 字节、%d 项，超过 4 MiB 或 16384 项预算", projectedBytes, projectedObjects)
	}
	return boundedFirewallTables(metadata)
}
