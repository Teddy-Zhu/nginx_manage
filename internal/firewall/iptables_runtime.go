package firewall

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// The stable entry chain owns one pointer. A new generation is assembled
// separately; no existing user chain is declared or flushed when switching.
type IPTablesGeneration struct {
	Family, Binary, Chain string
	Hook, Pointer         []string
	Rules                 []IPTablesRule
}

type IPTablesRuntimeProgram struct {
	Backend, Owner, PlanID, Action, LogicalHash, Marker, Hash string
	Families                                                  []IPTablesGeneration
	Bytes, BaseRules, ProtectionRules                         int
}

func CompileIPTablesRuntime(policy Policy, protections []Protection, owner, planID, action string) (*IPTablesRuntimeProgram, error) {
	if action != "apply" && action != "remove" {
		return nil, fault.Invalid("iptables 运行计划动作无效")
	}
	const zero = "00000000-0000-0000-0000-000000000000"
	if !ruleIDPattern.MatchString(owner) || !ruleIDPattern.MatchString(planID) || owner == zero || planID == zero || owner == planID {
		return nil, fault.Invalid("iptables 运行计划的本机所有者或计划标识无效")
	}
	compiledPolicy := policy
	if action == "remove" {
		if _, err := policy.Normalize(); err != nil {
			return nil, err
		}
		compiledPolicy = DefaultPolicy()
		compiledPolicy.Backend = policy.Backend
	}
	logical, err := CompileIPTablesProtected(compiledPolicy, protections)
	if err != nil {
		return nil, err
	}
	name := IPTablesHostChain + "-" + secure.Hash([]byte(owner + ":" + planID + ":" + logical.Hash))[:12]
	marker := "nginxpanel:host:generation:v1:" + owner + ":" + planID + ":" + logical.Hash
	out := &IPTablesRuntimeProgram{Backend: logical.Backend, Owner: owner, PlanID: planID, Action: action, LogicalHash: logical.Hash, Marker: marker, Families: []IPTablesGeneration{}, BaseRules: logical.BaseRules, ProtectionRules: logical.ProtectionRules}
	ordinal := 0
	families := logical.Families
	if action == "remove" {
		families = nil
		out.BaseRules, out.ProtectionRules = 0, 0
	}
	for _, family := range families {
		generation := IPTablesGeneration{Family: family.Family, Binary: family.Binary, Chain: name, Hook: []string{"-m", "comment", "--comment", "nginxpanel:host:hook:v1:" + owner, "-j", IPTablesHostChain}, Pointer: []string{"-m", "comment", "--comment", marker, "-j", name}, Rules: []IPTablesRule{}}
		for _, rule := range family.Rules {
			args := slices.Clone(rule.Arguments)
			comment := -1
			for index := range args {
				if args[index] == "--comment" {
					comment = index + 1
				}
			}
			value := marker + ":" + strconv.Itoa(ordinal)
			if comment >= 0 {
				args[comment] = value
			} else {
				// The two baseline RETURN rules also carry the full generation
				// identity; ownership is never inferred from anonymous prefixes.
				target := slices.Index(args, "-j")
				args = slices.Insert(args, target, "-m", "comment", "--comment", value)
			}
			generation.Rules = append(generation.Rules, IPTablesRule{Arguments: args})
			ordinal++
		}
		out.Families = append(out.Families, generation)
	}
	if ordinal+2*len(out.Families) > MaxEntries {
		return nil, fault.Invalid("包含入口跳转和代际指针的 iptables 程序超过 8192 条")
	}
	raw, err := json.Marshal(struct {
		Backend, Owner, PlanID, Action, LogicalHash string
		Families                                    []IPTablesGeneration
	}{out.Backend, owner, planID, action, out.LogicalHash, out.Families})
	if err != nil {
		return nil, err
	}
	if len(raw) > IPTablesProgramBytes {
		return nil, fault.Invalid("包含完整代际身份的 iptables 程序超过 2 MiB")
	}
	out.Bytes, out.Hash = len(raw), secure.Hash(append([]byte("iptables:runtime:v2:\x00"), raw...))
	return out, nil
}

// Generated tokens contain no whitespace, quoting, escapes or restore syntax.
// Foreign save text is deliberately never sent through this renderer.
func IPTablesRuleText(args []string) (string, error) {
	if len(args) == 0 || len(args) > 64 {
		return "", fault.Invalid("iptables 生成参数数量无效")
	}
	for _, arg := range args {
		if arg == "" || len(arg) > 255 {
			return "", fault.Invalid("iptables 生成参数长度无效")
		}
		for _, c := range arg {
			if c < 0x21 || c > 0x7e || strings.ContainsRune("\"'\\#", c) {
				return "", fault.Invalid("iptables 生成参数包含不支持的原生语法")
			}
		}
	}
	return strings.Join(args, " "), nil
}
