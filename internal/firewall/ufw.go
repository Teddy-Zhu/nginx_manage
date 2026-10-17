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
const UFWProgramBytes = 480 << 10
const UFWReadBytes = 512 << 10

// Only generated arguments may reach a future executor, never report strings
// or shell input. Compilation establishes neither ownership nor placement.
type UFWRule struct {
	Arguments []string `json:"arguments"`
}
type UFWProgram struct {
	Rules   []UFWRule
	Entries []PreviewEntry
	Hash    string
	Bytes   int
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
	raw, err := json.Marshal(program.Rules)
	if err != nil {
		return nil, err
	}
	if len(raw) > UFWProgramBytes {
		return nil, fault.Invalid("UFW 命令参数超过 480 KiB，请缩小规则组合")
	}
	program.Bytes = len(raw)
	program.Hash = secure.Hash(append([]byte("ufw:host:v1:\x00"), raw...))
	return program, nil
}
