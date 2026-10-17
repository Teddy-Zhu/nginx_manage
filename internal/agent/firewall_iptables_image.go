package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type iptablesImageChain struct {
	Name, Policy string
	Rules        [][]string
}

type iptablesImageTable struct {
	Name   string
	Chains []iptablesImageChain
}

type iptablesImage struct {
	Family string
	Tables []iptablesImageTable
}

// The complete export is validated before extracting any owned scope. Foreign
// extensions remain opaque argument arrays; they are never fed to an executor.
func parseIPTablesImage(raw []byte, family string) (iptablesImage, error) {
	out := iptablesImage{Family: family, Tables: []iptablesImageTable{}}
	if family != "ipv4" && family != "ipv6" || len(raw) > 1<<20 {
		return out, errors.New("iptables 原生导出的地址族或大小无效")
	}
	if _, err := xtablesInventory(raw, family); err != nil {
		return out, err
	}
	current := -1
	indices := map[string]int{}
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "*"):
			current = len(out.Tables)
			out.Tables = append(out.Tables, iptablesImageTable{Name: line[1:], Chains: []iptablesImageChain{}})
			indices = map[string]int{}
		case line == "COMMIT":
			current = -1
		case strings.HasPrefix(line, ":"):
			words := strings.Fields(line[1:])
			indices[words[0]] = len(out.Tables[current].Chains)
			out.Tables[current].Chains = append(out.Tables[current].Chains, iptablesImageChain{Name: words[0], Policy: words[1], Rules: [][]string{}})
		case strings.HasPrefix(line, "-A "):
			args, err := xtablesWords(line)
			if err != nil {
				return out, err
			}
			index := indices[args[1]]
			out.Tables[current].Chains[index].Rules = append(out.Tables[current].Chains[index].Rules, slices.Clone(args[2:]))
		}
	}
	return out, nil
}

func (image iptablesImage) hash() string {
	// Declaration order across distinct chains/tables is not packet order.
	// Rule order within every chain is retained exactly.
	tables := slices.Clone(image.Tables)
	for index := range tables {
		tables[index].Chains = slices.Clone(tables[index].Chains)
		slices.SortFunc(tables[index].Chains, func(a, b iptablesImageChain) int { return strings.Compare(a.Name, b.Name) })
	}
	slices.SortFunc(tables, func(a, b iptablesImageTable) int { return strings.Compare(a.Name, b.Name) })
	raw, _ := json.Marshal(iptablesImage{Family: image.Family, Tables: tables})
	return secure.Hash(append([]byte("iptables:image:v1:\x00"), raw...))
}

func (image iptablesImage) chain(table, name string) *iptablesImageChain {
	for ti := range image.Tables {
		if image.Tables[ti].Name != table {
			continue
		}
		for ci := range image.Tables[ti].Chains {
			if image.Tables[ti].Chains[ci].Name == name {
				return &image.Tables[ti].Chains[ci]
			}
		}
	}
	return nil
}

func iptablesReservedArgument(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, firewall.IPTablesHostChain) || strings.HasPrefix(arg, "nginxpanel:host:") {
			return true
		}
	}
	return false
}

func iptablesOwnedRuleKey(chain, family string, args []string) (string, error) {
	text, err := firewall.IPTablesRuleText(args)
	if err != nil {
		return "", err
	}
	// Reuse the existing closed xtables matcher for transport, conntrack,
	// comments and verdicts. It preserves module order and normalizes only
	// explicit numeric/protocol defaults, source masks and state ordering.
	_, key, _, err := ufwKernelRuleKey("-A "+chain+" "+text, family, false)
	return key, err
}

func proveIPTablesGeneration(image iptablesImage, generation *firewall.IPTablesGeneration) error {
	if generation != nil && image.Family != generation.Family {
		return errors.New("iptables 代际规则地址族与当前导出不一致")
	}
	for _, table := range image.Tables {
		for _, chain := range table.Chains {
			owned := generation != nil && table.Name == "filter" && (chain.Name == firewall.IPTablesHostChain || chain.Name == generation.Chain)
			if strings.HasPrefix(chain.Name, firewall.IPTablesHostChain) && !owned {
				return errors.New("存在没有原代际回执的目标链，拒绝接管或删除")
			}
			if owned {
				if chain.Policy != "-" {
					return errors.New("iptables 受管链不是普通用户链")
				}
				if chain.Name == firewall.IPTablesHostChain {
					if len(chain.Rules) != 1 || !slices.Equal(chain.Rules[0], generation.Pointer) {
						return errors.New("iptables 受管入口指针与原完整代际程序不一致")
					}
					continue
				}
				if len(chain.Rules) != len(generation.Rules) {
					return errors.New("iptables 代际链规则数量与原程序不一致")
				}
				for index, rule := range generation.Rules {
					expected, err := iptablesOwnedRuleKey(chain.Name, image.Family, rule.Arguments)
					if err != nil {
						return err
					}
					actual, err := iptablesOwnedRuleKey(chain.Name, image.Family, chain.Rules[index])
					if err != nil || actual != expected {
						return errors.New("iptables 代际链完整规则、顺序或身份与原程序不一致")
					}
				}
				continue
			}
			for index, rule := range chain.Rules {
				if generation != nil && table.Name == "filter" && chain.Name == "INPUT" && index == 0 && slices.Equal(rule, generation.Hook) {
					continue
				}
				if iptablesReservedArgument(rule) {
					return errors.New("存在其他链、位置或所有者对目标链和标记的引用，保留现场")
				}
			}
		}
	}
	if generation != nil {
		input, anchor, rules := image.chain("filter", "INPUT"), image.chain("filter", firewall.IPTablesHostChain), image.chain("filter", generation.Chain)
		if input == nil || len(input.Rules) == 0 || !slices.Equal(input.Rules[0], generation.Hook) || anchor == nil || rules == nil {
			return errors.New("iptables 固定入口、首位跳转或代际链缺失")
		}
	}
	return nil
}

type iptablesInitialMaterial struct {
	Family, Binary, BeforeHash, AfterHash, CandidateHash, PreviousHash string
	Before, After                                                      iptablesImage
	Candidate, Previous                                                []byte
}

// Initial admission is fail-if-exists: -N never flushes an existing chain.
// Recovery deletes the exact generated rules, then deletes empty chains. It
// contains no historical foreign rule, policy replacement or global flush.
func initialIPTablesMaterial(before iptablesImage, generation firewall.IPTablesGeneration) (iptablesInitialMaterial, error) {
	var out iptablesInitialMaterial
	if before.Family != generation.Family || proveIPTablesGeneration(before, nil) != nil {
		return out, errors.New("iptables 原始空命名空间无法完整证明")
	}
	input := before.chain("filter", "INPUT")
	if input == nil || input.Policy != "ACCEPT" && input.Policy != "DROP" {
		return out, errors.New("iptables 原 filter/INPUT 及默认策略无法核对")
	}
	// Clone via the typed image so no slice in the original is mutated.
	raw, err := json.Marshal(before)
	if err != nil {
		return out, err
	}
	var after iptablesImage
	if err = json.Unmarshal(raw, &after); err != nil {
		return out, err
	}
	nextInput := after.chain("filter", "INPUT")
	nextInput.Rules = append([][]string{slices.Clone(generation.Hook)}, nextInput.Rules...)
	for index := range after.Tables {
		if after.Tables[index].Name != "filter" {
			continue
		}
		rules := iptablesImageChain{Name: generation.Chain, Policy: "-", Rules: [][]string{}}
		for _, rule := range generation.Rules {
			rules.Rules = append(rules.Rules, slices.Clone(rule.Arguments))
		}
		after.Tables[index].Chains = append(after.Tables[index].Chains, rules, iptablesImageChain{Name: firewall.IPTablesHostChain, Policy: "-", Rules: [][]string{slices.Clone(generation.Pointer)}})
	}
	if err = proveIPTablesGeneration(after, &generation); err != nil {
		return out, err
	}
	var candidate, previous bytes.Buffer
	candidate.WriteString("*filter\n-N " + generation.Chain + "\n-N " + firewall.IPTablesHostChain + "\n")
	previous.WriteString("*filter\n")
	write := func(buffer *bytes.Buffer, command, chain string, args []string) error {
		text, err := firewall.IPTablesRuleText(args)
		if err != nil {
			return err
		}
		buffer.WriteString(command + " " + chain + " " + text + "\n")
		return nil
	}
	if err = write(&previous, "-D", "INPUT", generation.Hook); err != nil {
		return out, err
	}
	if err = write(&previous, "-D", firewall.IPTablesHostChain, generation.Pointer); err != nil {
		return out, err
	}
	for _, rule := range generation.Rules {
		if err = write(&candidate, "-A", generation.Chain, rule.Arguments); err != nil {
			return out, err
		}
		if err = write(&previous, "-D", generation.Chain, rule.Arguments); err != nil {
			return out, err
		}
	}
	if err = write(&candidate, "-A", firewall.IPTablesHostChain, generation.Pointer); err != nil {
		return out, err
	}
	if err = write(&candidate, "-I", "INPUT 1", generation.Hook); err != nil {
		return out, err
	}
	previous.WriteString("-X " + firewall.IPTablesHostChain + "\n-X " + generation.Chain + "\nCOMMIT\n")
	candidate.WriteString("COMMIT\n")
	if candidate.Len()+previous.Len() > 2*firewall.IPTablesProgramBytes {
		return out, errors.New("iptables 代际正反向批次超过 4 MiB")
	}
	return iptablesInitialMaterial{Family: generation.Family, Binary: generation.Binary, BeforeHash: before.hash(), AfterHash: after.hash(), CandidateHash: secure.Hash(candidate.Bytes()), PreviousHash: secure.Hash(previous.Bytes()), Before: before, After: after, Candidate: candidate.Bytes(), Previous: previous.Bytes()}, nil
}
