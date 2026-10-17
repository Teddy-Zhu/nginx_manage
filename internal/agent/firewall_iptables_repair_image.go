package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type iptablesRepairMaterial struct {
	Family, Binary, BeforeHash, InputHash string
	Before, After                         iptablesImage
	Input                                 []byte
	Missing                               int
}

// Each surviving managed rule must retain its full original identity and
// relative position. Unknown/duplicated/reordered content is never rewritten.
func repairIPTablesMaterial(before iptablesImage, generation firewall.IPTablesGeneration) (iptablesRepairMaterial, error) {
	return repairIPTablesScopedMaterial(before, generation, iptablesGenerationScope{Entry: "INPUT", Anchor: firewall.IPTablesHostChain, Prove: proveIPTablesGeneration}, iptablesOwnedRuleKey)
}

func repairDockerIPTablesMaterial(before iptablesImage, generation firewall.IPTablesGeneration) (iptablesRepairMaterial, error) {
	return repairIPTablesScopedMaterial(before, generation, iptablesGenerationScope{Entry: "DOCKER-USER", Anchor: firewall.IPTablesDockerChain, UserEntry: true, Prove: proveDockerIPTablesGeneration}, dockerIPTablesRuleKey)
}

func repairIPTablesScopedMaterial(before iptablesImage, generation firewall.IPTablesGeneration, scope iptablesGenerationScope, ruleKey func(string, string, []string) (string, error)) (iptablesRepairMaterial, error) {
	var out iptablesRepairMaterial
	invalid := errors.New("iptables 已确认代际存在未知规则、引用或顺序漂移，禁止修复覆盖")
	if before.Family != generation.Family {
		return out, invalid
	}
	input := before.chain("filter", scope.Entry)
	if input == nil || scope.UserEntry && input.Policy != "-" || !scope.UserEntry && input.Policy != "ACCEPT" && input.Policy != "DROP" {
		return out, invalid
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return out, err
	}
	var after iptablesImage
	if err = json.Unmarshal(raw, &after); err != nil {
		return out, err
	}
	var batch bytes.Buffer
	batch.WriteString("*filter\n")
	missing := 0
	write := func(command, chain string, args []string) error {
		text, err := firewall.IPTablesRuleText(args)
		if err != nil {
			return err
		}
		batch.WriteString(command + " " + chain + " " + text + "\n")
		missing++
		return nil
	}
	for _, table := range before.Tables {
		for _, chain := range table.Chains {
			owned := table.Name == "filter" && (chain.Name == generation.Chain || chain.Name == scope.Anchor)
			if strings.HasPrefix(chain.Name, scope.Anchor) && !owned {
				return out, invalid
			}
			if owned {
				if chain.Policy != "-" {
					return out, invalid
				}
				continue
			}
			for position, rule := range chain.Rules {
				if table.Name == "filter" && chain.Name == scope.Entry && position == 0 && slices.Equal(rule, generation.Hook) {
					continue
				}
				reserved := iptablesReservedArgument(rule)
				if scope.UserEntry {
					reserved = false
					for _, arg := range rule {
						reserved = reserved || dockerIPTablesReserved(arg)
					}
				}
				if reserved {
					return out, invalid
				}
			}
		}
	}
	for _, name := range []string{generation.Chain, scope.Anchor} {
		chain := after.chain("filter", name)
		if chain == nil {
			batch.WriteString("-N " + name + "\n")
			missing++
			for index := range after.Tables {
				if after.Tables[index].Name == "filter" {
					after.Tables[index].Chains = append(after.Tables[index].Chains, iptablesImageChain{Name: name, Policy: "-", Rules: [][]string{}})
				}
			}
			chain = after.chain("filter", name)
		}
		expected := [][]string{generation.Pointer}
		if name == generation.Chain {
			expected = [][]string{}
			for _, rule := range generation.Rules {
				expected = append(expected, slices.Clone(rule.Arguments))
			}
		}
		if name == scope.Anchor {
			if len(chain.Rules) > 1 || len(chain.Rules) == 1 && !slices.Equal(chain.Rules[0], generation.Pointer) {
				return out, invalid
			}
			if len(chain.Rules) == 0 {
				if err = write("-I", name+" 1", generation.Pointer); err != nil {
					return out, err
				}
			}
			chain.Rules = expected
			continue
		}
		keys := make(map[string]int, len(expected))
		for position, rule := range expected {
			key, err := ruleKey(name, before.Family, rule)
			if err != nil {
				return out, err
			}
			if _, exists := keys[key]; exists {
				return out, invalid
			}
			keys[key] = position
		}
		positions := map[int]bool{}
		last := -1
		for _, rule := range chain.Rules {
			key, err := ruleKey(name, before.Family, rule)
			position, exists := keys[key]
			if err != nil || !exists || position <= last {
				return out, invalid
			}
			positions[position], last = true, position
		}
		for position, rule := range expected {
			if !positions[position] {
				if err = write("-I", name+" "+strconv.Itoa(position+1), rule); err != nil {
					return out, err
				}
			}
		}
		chain.Rules = expected
	}
	nextInput := after.chain("filter", scope.Entry)
	if len(input.Rules) == 0 || !slices.Equal(input.Rules[0], generation.Hook) {
		if err = write("-I", scope.Entry+" 1", generation.Hook); err != nil {
			return out, err
		}
		nextInput.Rules = append([][]string{slices.Clone(generation.Hook)}, nextInput.Rules...)
	}
	if err = scope.Prove(after, &generation); err != nil {
		return out, err
	}
	if err = after.readbackBudget(); err != nil {
		return out, err
	}
	batch.WriteString("COMMIT\n")
	var program []byte
	if missing != 0 {
		program = batch.Bytes()
	}
	if len(program) > 2*firewall.IPTablesProgramBytes {
		return out, errors.New("iptables 修复批次超过 4 MiB")
	}
	return iptablesRepairMaterial{Family: generation.Family, Binary: generation.Binary, BeforeHash: before.hash(), InputHash: secure.Hash(program), Before: before, After: after, Input: program, Missing: missing}, nil
}

// Missing INPUT and Docker objects are restored in one family transaction.
// Foreign rules are never copied into the repair input or replaced wholesale.
func repairIPTablesCombinedMaterial(before iptablesImage, host, docker *firewall.IPTablesGeneration) (iptablesRepairMaterial, error) {
	if host == nil && docker == nil {
		return iptablesRepairMaterial{}, errors.New("iptables 联合修复缺少原确认地址族")
	}
	foreign, _, _, err := classifyIPTablesConfirmedScope(before, host, docker, true)
	if err != nil {
		return iptablesRepairMaterial{}, err
	}
	out := iptablesRepairMaterial{Family: before.Family, BeforeHash: before.hash(), Before: before, After: before}
	batches := [][]byte{}
	for index, generation := range []*firewall.IPTablesGeneration{host, docker} {
		if generation == nil {
			continue
		}
		if out.Binary != "" && out.Binary != generation.Binary {
			return iptablesRepairMaterial{}, errors.New("iptables 联合修复的地址族工具不一致")
		}
		out.Binary = generation.Binary
		var material iptablesRepairMaterial
		if index == 0 {
			material, err = repairIPTablesMaterial(out.After, *generation)
		} else {
			material, err = repairDockerIPTablesMaterial(out.After, *generation)
		}
		if err != nil {
			return iptablesRepairMaterial{}, err
		}
		out.After, out.Missing = material.After, out.Missing+material.Missing
		if len(material.Input) != 0 {
			batches = append(batches, material.Input)
		}
	}
	restored, err := iptablesCombinedForeignImage(out.After, host, docker)
	if err != nil || restored.hash() != foreign.hash() {
		return iptablesRepairMaterial{}, errors.New("iptables 联合修复改变其他规则，拒绝生成批次")
	}
	if len(batches) != 0 {
		out.Input, err = joinIPTablesFilterBatches(batches, 2*firewall.IPTablesProgramBytes)
		if err != nil {
			return iptablesRepairMaterial{}, err
		}
	}
	out.InputHash = secure.Hash(out.Input)
	return out, nil
}
