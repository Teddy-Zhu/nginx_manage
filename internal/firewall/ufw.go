package firewall

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const UFWCommentPrefix = "nginxpanel:host:v1:"
const UFWProgramBytes = 2 << 20
const UFWReadBytes = 2 << 20

// Only generated arguments may reach a future executor, never report strings
// or shell input. Compilation establishes neither ownership nor placement.
type UFWRule struct {
	Arguments []string `json:"arguments"`
}
type UFWProgram struct {
	Rules               []UFWRule
	Entries             []PreviewEntry
	Hash                string
	Bytes               int
	ProtectionRules     int
	ProtectionOverrides int
}

func CompileUFW(policy Policy) (*UFWProgram, error) {
	normalized, err := policy.Normalize()
	if err != nil {
		return nil, err
	}
	if normalized.Backend != "ufw" {
		return nil, fault.Invalid("UFW 编译器不接受其他目标后端")
	}
	program := &UFWProgram{Rules: []UFWRule{}, Entries: []PreviewEntry{}}
	selectors := map[string]bool{}
	for _, rule := range normalized.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Scope != "host_input" {
			return nil, fault.Unavailable("UFW 入站规则不承接 Docker 发布端口，不能将转发流量转换为主机入站规则")
		}
		if strings.HasPrefix(rule.Interface, "-") {
			return nil, fault.Invalid("UFW 接口名称不能以连字符开头，避免与命令选项混淆")
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			if rule.Family != "both" && rule.Family != family {
				continue
			}
			anywhere := "0.0.0.0/0"
			if family == "ipv6" {
				anywhere = "::/0"
			}
			sources := []string{anywhere}
			if len(rule.Sources) > 0 {
				sources = []string{}
				for _, source := range rule.Sources {
					prefix, _ := netip.ParsePrefix(source)
					if prefix.Addr().Is4() == (family == "ipv4") {
						sources = append(sources, source)
					}
				}
			}
			for _, source := range sources {
				for _, ports := range rule.Ports {
					if len(program.Rules) >= MaxEntries {
						return nil, fault.Invalid("UFW 规则展开后超过 8192 条，请缩小端口和来源组合")
					}
					// UFW matches selectors before action/comment and can update an
					// existing rule. Duplicate selectors cannot preserve rule order.
					selector, e := json.Marshal(struct {
						Family, Protocol, Source, Interface string
						Ports                               PortRange
					}{family, rule.Protocol, source, rule.Interface, ports})
					if e != nil {
						return nil, e
					}
					if selectors[string(selector)] {
						return nil, fault.Invalid("UFW 存在重复匹配条件；后续添加可能更新原动作或注释，请合并重复规则")
					}
					selectors[string(selector)] = true
					comment := UFWCommentPrefix + rule.ID + ":" + secure.Hash(selector)[:16]
					args := []string{rule.Action, "in"}
					if rule.Interface != "" {
						args = append(args, "on", rule.Interface)
					}
					port := strconv.Itoa(ports.From)
					if ports.To != ports.From {
						port += ":" + strconv.Itoa(ports.To)
					}
					args = append(args, "proto", rule.Protocol, "from", source, "to", anywhere, "port", port, "comment", comment)
					program.Rules = append(program.Rules, UFWRule{Arguments: args})
					program.Entries = append(program.Entries, PreviewEntry{RuleID: rule.ID, Family: family, Protocol: rule.Protocol, Source: source, Ports: ports, Action: rule.Action, Interface: rule.Interface, Priority: rule.Priority, Expression: "ufw " + strings.Join(args, " ")})
				}
			}
		}
	}
	return finishUFW(program)
}

func finishUFW(program *UFWProgram) (*UFWProgram, error) {
	if len(program.Rules) > MaxEntries {
		return nil, fault.Invalid("包含保护项的 UFW 命令超过 8192 条")
	}
	raw, err := json.Marshal(program.Rules)
	if err != nil {
		return nil, err
	}
	if len(raw) > UFWProgramBytes {
		return nil, fault.Invalid("UFW 命令参数超过 2 MiB，请缩小规则组合")
	}
	program.Bytes = len(raw)
	program.Hash = secure.Hash(append([]byte("ufw:host:v1:\x00"), raw...))
	return program, nil
}

func CompileUFWProtected(policy Policy, protections []Protection) (*UFWProgram, error) {
	base, err := CompileUFW(policy)
	if err != nil {
		return nil, err
	}
	guards, err := protectionPolicy(protections, "ufw")
	if err != nil {
		return nil, err
	}
	out := &UFWProgram{Rules: []UFWRule{}, Entries: []PreviewEntry{}}
	seen := map[string]bool{}
	selector := func(rule UFWRule) string {
		// Action and the final comment pair are not UFW match selectors.
		return strings.Join(rule.Arguments[1:len(rule.Arguments)-2], "\x00")
	}
	for _, guard := range guards.Rules {
		compiled, err := CompileUFW(Policy{Backend: "ufw", Rules: []Rule{guard}})
		if err != nil {
			return nil, err
		}
		for i, rule := range compiled.Rules {
			key := selector(rule)
			if !seen[key] {
				seen[key] = true
				out.Rules = append(out.Rules, rule)
				out.Entries = append(out.Entries, compiled.Entries[i])
			}
		}
	}
	out.ProtectionRules = len(out.Rules)
	for i, rule := range base.Rules {
		if seen[selector(rule)] {
			// The guard must win; sending the same selector twice would update
			// it in UFW, including when the business action is deny/reject.
			out.ProtectionOverrides++
			continue
		}
		out.Rules = append(out.Rules, rule)
		out.Entries = append(out.Entries, base.Entries[i])
	}
	return finishUFW(out)
}

func CompileUFWOwned(policy Policy, protections []Protection, owner, planID string) (*UFWProgram, error) {
	const zero = "00000000-0000-0000-0000-000000000000"
	if !ruleIDPattern.MatchString(owner) || !ruleIDPattern.MatchString(planID) || owner == zero || planID == zero || owner == planID {
		return nil, fault.Invalid("UFW 所有者与计划身份无效")
	}
	program, err := CompileUFWProtected(policy, protections)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for index, rule := range program.Rules {
		raw, err := json.Marshal(rule)
		if err != nil {
			return nil, err
		}
		comment := UFWCommentPrefix + owner + ":" + planID + ":" + secure.Hash(raw)[:16]
		if seen[comment] {
			return nil, fault.Invalid("UFW 生成规则身份重复")
		}
		seen[comment] = true
		rule.Arguments[len(rule.Arguments)-1] = comment
		program.Entries[index].Expression = "ufw " + strings.Join(rule.Arguments, " ")
	}
	return finishUFW(program)
}

func CompileUFWRuntime(policy Policy, protections []Protection, action, owner, planID string) (*UFWProgram, error) {
	if action == "apply" {
		return CompileUFWOwned(policy, protections, owner, planID)
	}
	if action != "remove" {
		return nil, fault.Invalid("UFW 动作须为 apply 或 remove")
	}
	normalized, err := policy.Normalize()
	if err != nil || normalized.Backend != "ufw" {
		return nil, fault.Invalid("UFW 移除策略无效")
	}
	return CompileUFWOwned(Policy{Backend: "ufw", Rules: []Rule{}}, nil, owner, planID)
}
