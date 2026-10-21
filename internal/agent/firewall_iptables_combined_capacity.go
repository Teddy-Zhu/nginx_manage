package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"nginxpanel/internal/firewall"
)

// A materialized INPUT header has fixed names/type/hook/policy and bounded
// numeric handles/counters. Reserve its complete schema-1 object separately
// from the generation's two owned chains and entry rule.
const iptablesNFTInputChainBytes = 1024

func (snapshot iptablesRegistrationSnapshot) admitTransitionReadback(v *iptablesTransition) error {
	if v == nil {
		return errors.New("iptables 容量准入缺少原联合意图")
	}
	return snapshot.admitCombinedReadback(
		iptablesProgramPair{Host: v.Program, Docker: v.Docker},
		iptablesProgramPair{Host: iptablesPreviousProgram(v), Docker: iptablesPreviousDocker(v)},
	)
}

// A family commits INPUT and Docker together. Reserve the largest complete
// old/new pair per family, including families switched in different directions.
// Only native-proven owned chains can be deducted from the actual nft JSON.
// Entry hooks and JSON separators stay in the baseline as a conservative bound.
func (snapshot iptablesRegistrationSnapshot) admitCombinedReadback(next, previous iptablesProgramPair, targets ...iptablesProgramPair) error {
	capacity := snapshot.NFT
	if !capacity.complete() {
		return errors.New("完整 nft JSON 容量或 schema 1 无法核对")
	}
	programs := []iptablesProgramPair{next, previous}
	if targets == nil {
		targets = programs
	}
	backend := ""
	for _, pair := range append(slices.Clone(programs), targets...) {
		backends := []string{}
		if pair.Host != nil {
			backends = append(backends, pair.Host.Backend)
		}
		if pair.Docker != nil {
			if pair.Docker.Program == nil {
				return errors.New("Docker 容量准入缺少原完整程序")
			}
			backends = append(backends, pair.Docker.Program.Backend)
		}
		for _, current := range backends {
			if !validIPTablesBackend(current) || backend != "" && backend != current {
				return errors.New("iptables 联合容量准入的后端不一致")
			}
			backend = current
		}
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
	images := map[string]iptablesImage{}
	for _, image := range snapshot.Images {
		if image.Family != "ipv4" && image.Family != "ipv6" {
			return errors.New("iptables 容量核对的原生地址族无效")
		}
		if _, exists := images[image.Family]; exists {
			return errors.New("iptables 容量核对的原生地址族重复")
		}
		images[image.Family] = image
		var host, docker *firewall.IPTablesGeneration
		matched := false
		for _, pair := range programs {
			h, d := iptablesGeneration(pair.Host, image.Family), dockerIPTablesGeneration(pair.Docker, image.Family)
			// Both scopes may prove only their original ordered subsets.
			// Unknown, duplicated or mixed generations cannot release capacity.
			if _, _, _, err := classifyIPTablesConfirmedScope(image, h, d, true); err == nil {
				host, docker, matched = h, d, true
				break
			}
		}
		if !matched {
			return errors.New("iptables 当前 INPUT/Docker 范围无法证明为同一原代际，不能扣减容量")
		}
		for _, scope := range []struct {
			anchor     string
			generation *firewall.IPTablesGeneration
		}{{firewall.IPTablesHostChain, host}, {firewall.IPTablesDockerChain, docker}} {
			if scope.generation == nil {
				continue
			}
			for _, name := range []string{scope.anchor, scope.generation.Chain} {
				chain := image.chain("filter", name)
				if chain == nil {
					continue
				}
				key := nftReadbackKey(iptablesNFTFamily(image.Family), "filter", name)
				actual, exists := capacity.Scopes[key]
				if owned[key] || !exists || actual.Rules != len(chain.Rules) || actual.Objects != len(chain.Rules)+1 {
					return errors.New("nft JSON 与 iptables 当前受管范围在容量核对期间变化")
				}
				owned[key] = true
				projectedBytes -= actual.Bytes + actual.NumberGrowth
				projectedObjects -= actual.Objects
			}
		}
	}
	if len(images) != 2 || projectedBytes < 0 || projectedObjects < 0 {
		return errors.New("nft JSON 当前范围容量或双地址族原生依据无效")
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
		metadataBytes, tableIndex := 0, -1
		var largest firewall.Table
		for _, pair := range targets {
			host, docker := iptablesGeneration(pair.Host, family), dockerIPTablesGeneration(pair.Docker, family)
			reserved := iptablesNFTFamilyBudget{}
			for index, generation := range []*firewall.IPTablesGeneration{host, docker} {
				if generation == nil {
					continue
				}
				budget, err := iptablesNFTGenerationBudget(generation, index == 1)
				if err != nil {
					return err
				}
				reserved.Bytes += budget.Bytes
				reserved.Objects += budget.Objects
				reserved.Chains = append(reserved.Chains, budget.Chains...)
			}
			if reserved.Objects == 0 {
				continue
			}
			index, projected, materializedInput, err := projectIPTablesReadbackTable(metadata, capacity, images[family], host, docker, reserved.Chains)
			if err != nil {
				return err
			}
			if materializedInput {
				reserved.Bytes += iptablesNFTInputChainBytes
				reserved.Objects++
			}
			maximum.Bytes = max(maximum.Bytes, reserved.Bytes)
			maximum.Objects = max(maximum.Objects, reserved.Objects)
			raw, err := json.Marshal(projected)
			if err != nil {
				return err
			}
			if len(raw) > metadataBytes {
				largest, tableIndex, metadataBytes = projected, index, len(raw)
			}
		}
		projectedBytes += maximum.Bytes
		projectedObjects += maximum.Objects
		if tableIndex >= 0 {
			metadata[tableIndex] = largest
		}
	}
	if projectedBytes > nftRulesetReadBytes || projectedObjects > firewallObjectLimit {
		return fmt.Errorf("iptables 联合候选及原策略恢复的完整 nft JSON 容量需要 %d 字节、%d 项，超过 4 MiB 或 16384 项预算", projectedBytes, projectedObjects)
	}
	return boundedFirewallTables(metadata)
}

func iptablesNFTFamily(family string) string {
	if family == "ipv6" {
		return "ip6"
	}
	return "ip"
}

// Metadata has a separate IPC limit. Select the largest complete per-family
// table projection rather than independently mixing host and Docker versions.
func projectIPTablesReadbackTable(metadata []firewall.Table, capacity nftReadbackBudget, image iptablesImage, host, docker *firewall.IPTablesGeneration, chains []firewall.Chain) (int, firewall.Table, bool, error) {
	for index, table := range metadata {
		if table.Family != iptablesNFTFamily(image.Family) || table.Name != "filter" {
			continue
		}
		table.Chains = slices.Clone(table.Chains)
		materializedInput := false
		for _, chain := range table.Chains {
			for _, candidate := range chains {
				if chain.Name == candidate.Name {
					return 0, firewall.Table{}, false, errors.New("nft JSON 候选链存在未核对的同名范围")
				}
			}
		}
		for _, entry := range []struct {
			name       string
			generation *firewall.IPTablesGeneration
		}{{"INPUT", host}, {"DOCKER-USER", docker}} {
			if entry.generation == nil {
				continue
			}
			actual := image.chain("filter", entry.name)
			scope, exists := capacity.Scopes[nftReadbackKey(table.Family, "filter", entry.name)]
			ci := slices.IndexFunc(table.Chains, func(chain firewall.Chain) bool { return chain.Name == entry.name })
			// iptables-nft-save synthesizes an empty ACCEPT INPUT even when
			// Docker has only materialized FORWARD in nft. Admit only this
			// exact absence; the transaction must create and budget the base
			// chain. DOCKER-USER and any populated or contradictory entry
			// still require matching native and nft evidence.
			if actual != nil && entry.name == "INPUT" && !exists && ci < 0 && actual.Policy == "ACCEPT" && len(actual.Rules) == 0 {
				priority := int64(0)
				table.Chains = append(table.Chains, firewall.Chain{Name: "INPUT", Type: "filter", Hook: "input", Priority: &priority, Policy: "accept", Rules: 1})
				materializedInput = true
				continue
			}
			if actual == nil || !exists || ci < 0 || scope.Rules != len(actual.Rules) || scope.Objects != len(actual.Rules)+1 || table.Chains[ci].Rules != scope.Rules {
				return 0, firewall.Table{}, false, errors.New("nft JSON 与原生 INPUT/DOCKER-USER 入口在容量核对期间变化")
			}
			table.Chains[ci].Rules++
		}
		table.Chains = append(table.Chains, chains...)
		return index, table, materializedInput, nil
	}
	return 0, firewall.Table{}, false, errors.New("nft JSON 缺少候选地址族的 filter 容量依据")
}
