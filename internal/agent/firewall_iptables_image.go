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
	if family != "ipv4" && family != "ipv6" || len(raw) > iptablesExportBytes {
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

// Reserve a conservative native export budget, including quoted arguments,
// maximum counters and save headers. A candidate must remain fully observable
// with the same parser and byte limits after it is eventually installed.
func (image iptablesImage) readbackBudget() error {
	bytes, objects := 0, 0
	metadata := []firewall.Table{}
	for _, table := range image.Tables {
		bytes += len(table.Name) + 512
		objects += 2
		view := firewall.Table{Family: image.Family, Name: table.Name, Chains: []firewall.Chain{}}
		for _, chain := range table.Chains {
			bytes += len(chain.Name) + len(chain.Policy) + 64
			objects++
			entry := firewall.Chain{Name: chain.Name, Policy: strings.ToLower(chain.Policy), Rules: len(chain.Rules)}
			if chain.Policy != "-" {
				entry.Type, entry.Hook = "builtin", strings.ToLower(chain.Name)
			}
			// false is one byte longer than true, conservatively accounting
			// for the only extra derived flag in the public chain metadata.
			view.Chains = append(view.Chains, entry)
			for _, rule := range chain.Rules {
				line := len(chain.Name) + 5
				for _, arg := range rule {
					line += len(strconv.Quote(arg)) + 1
				}
				if line >= 128<<10 {
					return errors.New("iptables 候选规则超过完整导出的单行预算")
				}
				bytes += line
				objects++
			}
		}
		metadata = append(metadata, view)
	}
	if bytes > iptablesExportBytes || objects > firewallObjectLimit {
		return errors.New("iptables 候选完整规则超过 1 MiB 或 16384 项的后续读取预算")
	}
	return boundedFirewallTables(metadata)
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

type iptablesChangeMaterial struct {
	Family, Binary, BeforeHash, AfterHash, CandidateHash, PreviousHash string
	Before, After                                                      iptablesImage
	Candidate, Previous                                                []byte
}

func iptablesGeneration(program *firewall.IPTablesRuntimeProgram, family string) *firewall.IPTablesGeneration {
	if program != nil {
		for i := range program.Families {
			if program.Families[i].Family == family {
				return &program.Families[i]
			}
		}
	}
	return nil
}

func renderIPTablesChange(before iptablesImage, old, next *firewall.IPTablesGeneration) (iptablesImage, []byte, error) {
	return renderIPTablesScopedChange(before, old, next, iptablesGenerationScope{Entry: "INPUT", Anchor: firewall.IPTablesHostChain, Prove: proveIPTablesGeneration})
}

type iptablesGenerationScope struct {
	Entry, Anchor string
	UserEntry     bool
	Prove         func(iptablesImage, *firewall.IPTablesGeneration) error
}

// Both fixed scopes render only compiler-owned generations. Their distinct
// proof functions retain their ownership grammar; neither renderer declares,
// flushes or serializes a foreign chain or changes a builtin policy.
func renderIPTablesScopedChange(before iptablesImage, old, next *firewall.IPTablesGeneration, scope iptablesGenerationScope) (iptablesImage, []byte, error) {
	if old == nil && next == nil || old != nil && old.Family != before.Family || next != nil && next.Family != before.Family {
		return iptablesImage{}, nil, errors.New("iptables 代际转换地址族无效")
	}
	if scope.Prove == nil || scope.Entry == "" || scope.Anchor == "" || scope.Entry == scope.Anchor {
		return iptablesImage{}, nil, errors.New("iptables 代际转换缺少固定入口或范围证明")
	}
	if err := scope.Prove(before, old); err != nil {
		return iptablesImage{}, nil, err
	}
	entry := before.chain("filter", scope.Entry)
	if entry == nil || scope.UserEntry && entry.Policy != "-" || !scope.UserEntry && entry.Policy != "ACCEPT" && entry.Policy != "DROP" {
		return iptablesImage{}, nil, errors.New("iptables 原 filter 入口及链策略无法核对")
	}
	if old != nil && next != nil && (old.Chain == next.Chain || !slices.Equal(old.Hook, next.Hook)) {
		return iptablesImage{}, nil, errors.New("iptables 新旧代际身份或固定入口冲突")
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return iptablesImage{}, nil, err
	}
	var after iptablesImage
	if err = json.Unmarshal(raw, &after); err != nil {
		return after, nil, err
	}
	var batch bytes.Buffer
	batch.WriteString("*filter\n")
	write := func(command, chain string, args []string) error {
		text, err := firewall.IPTablesRuleText(args)
		if err != nil {
			return err
		}
		batch.WriteString(command + " " + chain + " " + text + "\n")
		return nil
	}
	if next != nil {
		batch.WriteString("-N " + next.Chain + "\n")
		for _, rule := range next.Rules {
			if err = write("-A", next.Chain, rule.Arguments); err != nil {
				return after, nil, err
			}
		}
		if old == nil {
			batch.WriteString("-N " + scope.Anchor + "\n")
			if err = write("-A", scope.Anchor, next.Pointer); err != nil {
				return after, nil, err
			}
			if err = write("-I", scope.Entry+" 1", next.Hook); err != nil {
				return after, nil, err
			}
		} else {
			if err = write("-I", scope.Anchor+" 1", next.Pointer); err != nil {
				return after, nil, err
			}
			if err = write("-D", scope.Anchor, old.Pointer); err != nil {
				return after, nil, err
			}
		}
	} else {
		if err = write("-D", scope.Entry, old.Hook); err != nil {
			return after, nil, err
		}
		if err = write("-D", scope.Anchor, old.Pointer); err != nil {
			return after, nil, err
		}
		batch.WriteString("-X " + scope.Anchor + "\n")
	}
	if old != nil {
		for _, rule := range old.Rules {
			if err = write("-D", old.Chain, rule.Arguments); err != nil {
				return after, nil, err
			}
		}
		batch.WriteString("-X " + old.Chain + "\n")
	}
	batch.WriteString("COMMIT\n")
	for ti := range after.Tables {
		if after.Tables[ti].Name != "filter" {
			continue
		}
		chains := []iptablesImageChain{}
		for _, chain := range after.Tables[ti].Chains {
			if old != nil && chain.Name == old.Chain {
				continue
			}
			if chain.Name == scope.Anchor {
				if next == nil {
					continue
				}
				chain.Rules = [][]string{slices.Clone(next.Pointer)}
			}
			if chain.Name == scope.Entry {
				if old != nil && next == nil {
					chain.Rules = chain.Rules[1:]
				}
				if old == nil {
					chain.Rules = append([][]string{slices.Clone(next.Hook)}, chain.Rules...)
				}
			}
			chains = append(chains, chain)
		}
		if next != nil {
			rules := [][]string{}
			for _, rule := range next.Rules {
				rules = append(rules, slices.Clone(rule.Arguments))
			}
			chains = append(chains, iptablesImageChain{Name: next.Chain, Policy: "-", Rules: rules})
			if old == nil {
				chains = append(chains, iptablesImageChain{Name: scope.Anchor, Policy: "-", Rules: [][]string{slices.Clone(next.Pointer)}})
			}
		}
		after.Tables[ti].Chains = chains
	}
	if err = scope.Prove(after, next); err != nil {
		return after, nil, err
	}
	if err = after.readbackBudget(); err != nil {
		return after, nil, err
	}
	return after, batch.Bytes(), nil
}

func makeIPTablesChangeMaterial(before iptablesImage, old, next *firewall.IPTablesGeneration) (iptablesChangeMaterial, error) {
	var out iptablesChangeMaterial
	after, candidate, err := renderIPTablesChange(before, old, next)
	if err != nil {
		return out, err
	}
	restored, previous, err := renderIPTablesChange(after, next, old)
	if err != nil {
		return out, err
	}
	originalForeign, _, err := iptablesForeignImage(before, old)
	if err != nil {
		return out, err
	}
	restoredForeign, _, err := iptablesForeignImage(restored, old)
	if err != nil || originalForeign.hash() != restoredForeign.hash() {
		return out, errors.New("iptables 正反向代际投影无法还原原始受管范围及第三方配置")
	}
	if len(candidate)+len(previous) > 2*firewall.IPTablesProgramBytes {
		return out, errors.New("iptables 代际正反向批次超过 4 MiB")
	}
	binary := ""
	if next != nil {
		binary = next.Binary
	} else {
		binary = old.Binary
	}
	return iptablesChangeMaterial{Family: before.Family, Binary: binary, BeforeHash: before.hash(), AfterHash: after.hash(), CandidateHash: secure.Hash(candidate), PreviousHash: secure.Hash(previous), Before: before, After: after, Candidate: candidate, Previous: previous}, nil
}
