package agent

import (
	"errors"
	"slices"

	"nginxpanel/internal/firewall"
)

// This closed grammar includes original conntrack tuples and bridge output.
// It reserves inline nft statements with the same conservative option budget
// as INPUT; no sets, maps or external stateful objects are generated.
func dockerIPTablesNFTRuleBytes(chain string, args []string) (int, error) {
	if _, err := firewall.IPTablesRuleText(args); err != nil || len(args)%2 != 0 {
		return 0, errors.New("Docker 规则不满足 nft JSON 容量语法")
	}
	reserved := 512 + 6*len(chain)
	for i := 0; i < len(args); i += 2 {
		switch args[i] {
		case "-m":
			if !slices.Contains([]string{"tcp", "udp", "conntrack", "comment"}, args[i+1]) {
				return 0, errors.New("Docker 匹配模块未纳入 nft JSON 容量准入")
			}
		case "-p", "--dport", "-s", "-d", "-i", "-o", "--ctstate", "--ctdir", "--ctproto", "--ctorigdst", "--ctorigdstport", "--comment", "-j", "--reject-with":
		default:
			return 0, errors.New("Docker 生成选项未纳入 nft JSON 容量准入")
		}
		reserved += 512 + 6*len(args[i+1])
	}
	return reserved, nil
}

func admitDockerInitialReadback(snapshot iptablesRegistrationSnapshot, program *firewall.DockerIPTablesRuntimeProgram, host, previous *firewall.IPTablesRuntimeProgram) error {
	projected, err := projectDockerInitialReadback(snapshot, program)
	if err != nil {
		return err
	}
	return projected.admitReadback(host, previous)
}

// Reserve Docker first, then let INPUT's existing capacity accounting remove
// and replace only its authenticated old chains. Both contributions therefore
// share one full-ruleset limit, including metadata and counter growth.
func projectDockerInitialReadback(snapshot iptablesRegistrationSnapshot, program *firewall.DockerIPTablesRuntimeProgram) (iptablesRegistrationSnapshot, error) {
	capacity := snapshot.NFT
	if !capacity.complete() || program == nil || !validIPTablesBackend(program.Backend) {
		return snapshot, errors.New("Docker 代际计划缺少完整 nft JSON 读取容量依据")
	}
	projectedBytes, projectedObjects := capacity.Bytes+capacity.NumberGrowth, capacity.Objects
	metadata := []firewall.Table{}
	for _, ruleset := range snapshot.Observed.Rulesets {
		if ruleset.ID != "nftables" || !ruleset.Available {
			continue
		}
		for _, table := range ruleset.Tables {
			view := table
			view.Chains = slices.Clone(table.Chains)
			metadata = append(metadata, view)
		}
	}
	if program.Backend == "iptables-nft" {
		for _, generation := range program.Families {
			projectedBytes += 2 * 1024
			projectedObjects += len(generation.Rules) + 4
			for _, rule := range append([]firewall.IPTablesRule{{Arguments: generation.Hook}, {Arguments: generation.Pointer}}, generation.Rules...) {
				reserved, err := dockerIPTablesNFTRuleBytes(generation.Chain, rule.Arguments)
				if err != nil {
					return snapshot, err
				}
				projectedBytes += reserved
			}
			family := "ip"
			if generation.Family == "ipv6" {
				family = "ip6"
			}
			var hook *iptablesImageChain
			for _, image := range snapshot.Images {
				if image.Family == generation.Family {
					hook = image.chain("filter", "DOCKER-USER")
				}
			}
			scope, exists := capacity.Scopes[nftReadbackKey(family, "filter", "DOCKER-USER")]
			if hook == nil || !exists || scope.Rules != len(hook.Rules) || scope.Objects != len(hook.Rules)+1 {
				return snapshot, errors.New("nft JSON 与原生 DOCKER-USER 在容量核对期间变化")
			}
			found := false
			for ti := range metadata {
				table := &metadata[ti]
				if table.Family != family || table.Name != "filter" {
					continue
				}
				for ci := range table.Chains {
					chain := &table.Chains[ci]
					if chain.Name == firewall.IPTablesDockerChain || chain.Name == generation.Chain {
						return snapshot, errors.New("nft JSON 存在未核对的同名 Docker 代际链")
					}
					if chain.Name == "DOCKER-USER" {
						chain.Rules++
						found = true
					}
				}
				table.Chains = append(table.Chains, firewall.Chain{Name: firewall.IPTablesDockerChain, Rules: 1}, firewall.Chain{Name: generation.Chain, Rules: len(generation.Rules)})
			}
			if !found {
				return snapshot, errors.New("nft JSON 缺少当前地址族的 DOCKER-USER 容量依据")
			}
		}
	}
	if projectedBytes > nftRulesetReadBytes || projectedObjects > firewallObjectLimit {
		return snapshot, errors.New("Docker 候选及补偿的完整 nft JSON 读取容量超过 4 MiB 或 16384 项")
	}
	if err := boundedFirewallTables(metadata); err != nil {
		return snapshot, err
	}
	snapshot.NFT.Bytes = projectedBytes - capacity.NumberGrowth
	snapshot.NFT.Objects = projectedObjects
	snapshot.Observed.Rulesets = slices.Clone(snapshot.Observed.Rulesets)
	for index := range snapshot.Observed.Rulesets {
		if snapshot.Observed.Rulesets[index].ID == "nftables" {
			snapshot.Observed.Rulesets[index].Tables = metadata
		}
	}
	return snapshot, nil
}
