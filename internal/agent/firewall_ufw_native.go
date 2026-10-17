package agent

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/firewall"
)

// UFW keeps ordinary comments in tuples, not in the kernel expressions. A
// matching tuple alone therefore proves neither its packet match nor ownership.
type ufwNativeRule struct {
	Family  string   `json:"family"`
	Tuple   string   `json:"tuple"`
	Packets []string `json:"packets"`
}

type ufwNativeFile struct {
	Rules     []ufwNativeRule
	Logging   []string
	Rate      []string
	Limiting  bool
	Bootstrap bool
}

func ufwNativeIdentity(family string) (prefix, anywhere string, ok bool) {
	switch family {
	case "ipv4":
		return "ufw", "0.0.0.0/0", true
	case "ipv6":
		return "ufw6", "::/0", true
	}
	return "", "", false
}

// Only the compiler's explicit TCP/UDP, single-family input subset is modeled.
// The entire generated packet expression must match, including reject behavior.
func expectedUFWNative(rule firewall.UFWRule, entry firewall.PreviewEntry) (ufwNativeRule, error) {
	out := ufwNativeRule{Family: entry.Family, Packets: []string{}}
	prefix, anywhere, ok := ufwNativeIdentity(entry.Family)
	source, err := netip.ParsePrefix(entry.Source)
	if !ok || err != nil || source.String() != source.Masked().String() || source.Addr().Is4() != (entry.Family == "ipv4") || entry.Protocol != "tcp" && entry.Protocol != "udp" || entry.Ports.From < 1 || entry.Ports.To > 65535 || entry.Ports.From > entry.Ports.To || len(rule.Arguments) < 3 {
		return out, errors.New("UFW 生成规则的地址族或匹配条件无效")
	}
	if len(entry.Interface) > 15 || strings.HasPrefix(entry.Interface, "-") || strings.ContainsAny(entry.Interface, " \t\r\n\x00") {
		return out, errors.New("UFW 生成规则的接口无效")
	}
	comment := rule.Arguments[len(rule.Arguments)-1]
	if !strings.HasPrefix(comment, firewall.UFWCommentPrefix) || len(comment) > 128 || strings.ContainsAny(comment, " \t\r\n\x00") {
		return out, errors.New("UFW 生成规则的注释无效")
	}
	ports := strconv.Itoa(entry.Ports.From)
	if entry.Ports.From != entry.Ports.To {
		ports += ":" + strconv.Itoa(entry.Ports.To)
	}
	args := []string{entry.Action, "in"}
	packet := []string{"-A", prefix + "-user-input"}
	direction := "in"
	if entry.Interface != "" {
		args = append(args, "on", entry.Interface)
		packet = append(packet, "-i", entry.Interface)
		direction += "_" + entry.Interface
	}
	args = append(args, "proto", entry.Protocol, "from", entry.Source, "to", anywhere, "port", ports, "comment", comment)
	if !slices.Equal(args, rule.Arguments) {
		return out, errors.New("UFW 生成参数与预览条目不一致")
	}
	sourceText := source.String()
	if source.Bits() == source.Addr().BitLen() {
		sourceText = source.Addr().String()
	}
	out.Tuple = "### tuple ### " + strings.Join([]string{entry.Action, entry.Protocol, ports, anywhere, "any", sourceText, direction, "comment=" + hex.EncodeToString([]byte(comment))}, " ")
	packet = append(packet, "-p", entry.Protocol)
	if entry.Ports.From != entry.Ports.To {
		packet = append(packet, "-m", "multiport", "--dports", ports)
	} else {
		packet = append(packet, "--dport", ports)
	}
	if sourceText != anywhere {
		packet = append(packet, "-s", sourceText)
	}
	switch entry.Action {
	case "allow":
		packet = append(packet, "-j", "ACCEPT")
	case "deny":
		packet = append(packet, "-j", "DROP")
	case "reject":
		packet = append(packet, "-j", "REJECT")
		if entry.Protocol == "tcp" {
			packet = append(packet, "--reject-with", "tcp-reset")
		}
	default:
		return out, errors.New("UFW 生成规则的动作无效")
	}
	out.Packets = append(out.Packets, strings.Join(packet, " "))
	return out, nil
}

func ufwNonemptyLines(text string) []string {
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func ufwStandardRate(prefix string, limiting bool, lines []string) bool {
	if !limiting {
		return len(lines) == 0
	}
	base := []string{"-A " + prefix + "-user-limit -j REJECT", "-A " + prefix + "-user-limit-accept -j ACCEPT"}
	log := "-A " + prefix + "-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \""
	return slices.Equal(lines, base) || slices.Equal(lines, append([]string{log}, base...))
}

// These exact empty templates are shipped by official UFW 0.36.2. Arbitrary
// native rules without tuples are not a template and must never be discarded.
func ufwBootstrapLines(prefix string) []string {
	lines := []string{"*filter", ":" + prefix + "-user-input - [0:0]", ":" + prefix + "-user-output - [0:0]", ":" + prefix + "-user-forward - [0:0]"}
	if prefix == "ufw" {
		lines = append(lines, ":ufw-user-limit - [0:0]", ":ufw-user-limit-accept - [0:0]", "### RULES ###",
			"-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \"", "-A ufw-user-limit -j REJECT", "-A ufw-user-limit-accept -j ACCEPT")
	} else {
		lines = append(lines, "### RULES ###")
	}
	return append(lines, "COMMIT")
}

func parseUFWNative(raw []byte, family string, bootstrap bool) (*ufwNativeFile, error) {
	prefix, _, ok := ufwNativeIdentity(family)
	if !ok || len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, errors.New("UFW 原生用户规则的地址族、大小或编码无效")
	}
	text := string(raw)
	for _, char := range text {
		if char < 0x20 && char != '\n' || char == 0x7f {
			return nil, errors.New("UFW 原生用户规则包含未知控制字符")
		}
	}
	out := &ufwNativeFile{Rules: []ufwNativeRule{}, Logging: []string{}, Rate: []string{}}
	if bootstrap && slices.Equal(ufwNonemptyLines(text), ufwBootstrapLines(prefix)) {
		out.Bootstrap = true
		return out, nil
	}
	header := "*filter\n"
	for _, suffix := range []string{"user-input", "user-output", "user-forward", "before-logging-input", "before-logging-output", "before-logging-forward", "user-logging-input", "user-logging-output", "user-logging-forward", "after-logging-input", "after-logging-output", "after-logging-forward", "logging-deny", "logging-allow"} {
		header += ":" + prefix + "-" + suffix + " - [0:0]\n"
	}
	rest, ok := strings.CutPrefix(text, header)
	if !ok {
		return nil, errors.New("UFW 原生用户规则的链定义无法完整核对")
	}
	limitHeader := ":" + prefix + "-user-limit - [0:0]\n:" + prefix + "-user-limit-accept - [0:0]\n"
	rest, out.Limiting = strings.CutPrefix(rest, limitHeader)
	rest, ok = strings.CutPrefix(rest, "### RULES ###\n")
	if !ok {
		return nil, errors.New("UFW 原生用户规则缺少规则段")
	}
	rules, rest, ok := strings.Cut(rest, "\n### END RULES ###\n")
	if !ok {
		return nil, errors.New("UFW 原生用户规则段不完整")
	}
	for _, line := range ufwNonemptyLines(rules) {
		switch {
		case strings.HasPrefix(line, "### tuple ### "):
			if len(out.Rules) >= firewall.MaxEntries || len(out.Rules) > 0 && len(out.Rules[len(out.Rules)-1].Packets) == 0 {
				return nil, errors.New("UFW 原生 tuple 缺少规则或超过预算")
			}
			out.Rules = append(out.Rules, ufwNativeRule{Family: family, Tuple: line, Packets: []string{}})
		case strings.HasPrefix(line, "-A "+prefix+"-") && len(out.Rules) > 0:
			last := &out.Rules[len(out.Rules)-1]
			last.Packets = append(last.Packets, line)
		default:
			return nil, errors.New("UFW 原生规则段包含未绑定 tuple 的规则或未知内容")
		}
	}
	if len(out.Rules) > 0 && len(out.Rules[len(out.Rules)-1].Packets) == 0 {
		return nil, errors.New("UFW 原生末尾 tuple 缺少规则")
	}
	rest, ok = strings.CutPrefix(rest, "\n### LOGGING ###\n")
	if !ok {
		return nil, errors.New("UFW 原生用户规则缺少日志段")
	}
	logging, rest, ok := strings.Cut(rest, "### END LOGGING ###\n")
	if !ok {
		return nil, errors.New("UFW 原生日志段不完整")
	}
	out.Logging = ufwNonemptyLines(logging)
	if out.Limiting {
		rest, ok = strings.CutPrefix(rest, "\n### RATE LIMITING ###\n")
		if !ok {
			return nil, errors.New("UFW 原生用户规则缺少限速段")
		}
		rate, tail, found := strings.Cut(rest, "### END RATE LIMITING ###\n")
		if !found {
			return nil, errors.New("UFW 原生限速段不完整")
		}
		out.Rate, rest = ufwNonemptyLines(rate), tail
	}
	if rest != "COMMIT\n" {
		return nil, errors.New("UFW 原生用户规则包含未知尾部")
	}
	for _, lines := range [][]string{out.Logging, out.Rate} {
		for _, line := range lines {
			if !strings.HasPrefix(line, "-A "+prefix+"-") && !strings.HasPrefix(line, "-I "+prefix+"-") {
				return nil, errors.New("UFW 原生辅助规则包含未知内容")
			}
		}
	}
	return out, nil
}

func ufwNativeRuleEqual(a, b ufwNativeRule) bool {
	return a.Family == b.Family && a.Tuple == b.Tuple && slices.Equal(a.Packets, b.Packets)
}

// A dry-run has fixed capability defaults rather than live kernel probes.
// Only the exact official limit auxiliaries may differ for that projection;
// changed user rules or custom logging/rate rules remain a hard conflict.
func ufwNativePreserved(before, candidate *ufwNativeFile, expected ufwNativeRule) (warning string, err error) {
	if candidate.Bootstrap || len(candidate.Rules) != len(before.Rules)+1 || !ufwNativeRuleEqual(candidate.Rules[0], expected) {
		return "", errors.New("UFW dry-run 新增 tuple 与完整原生表达式不匹配")
	}
	for index, rule := range before.Rules {
		if !ufwNativeRuleEqual(rule, candidate.Rules[index+1]) {
			return "", errors.New("UFW dry-run 改变、遗漏或重排既有用户规则")
		}
	}
	prefix, _, _ := ufwNativeIdentity(expected.Family)
	if before.Bootstrap {
		if candidate.Limiting != (expected.Family == "ipv4") || !ufwStandardRate(prefix, candidate.Limiting, candidate.Rate) {
			return "", errors.New("UFW 初始模板的候选限速段存在未知内容")
		}
		return expected.Family + " 原生文件为官方空初始模板；候选包含 UFW 生成的标准链、日志及限速段，尚无运行证明", nil
	}
	if !slices.Equal(before.Logging, candidate.Logging) {
		return "", errors.New("UFW dry-run 改变既有日志段，未准备计划")
	}
	if before.Limiting == candidate.Limiting {
		if !slices.Equal(before.Rate, candidate.Rate) {
			return "", errors.New("UFW dry-run 改变既有限速段，未准备计划")
		}
		return "", nil
	}
	projection := expected.Family == "ipv4" && !before.Limiting && candidate.Limiting || expected.Family == "ipv6" && before.Limiting && !candidate.Limiting
	if !projection || !ufwStandardRate(prefix, before.Limiting, before.Rate) || !ufwStandardRate(prefix, candidate.Limiting, candidate.Rate) {
		return "", errors.New("UFW dry-run 的限速能力差异涉及未知辅助规则")
	}
	return expected.Family + " dry-run 限速链与当前文件不同；官方 dry-run 使用固定能力默认值，不能据此证明实际写入或内核能力", nil
}
