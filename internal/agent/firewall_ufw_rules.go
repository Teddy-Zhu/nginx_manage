package agent

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// The official report merges some IPv4/IPv6 command strings and approximates
// their combined order. Never replay it or treat it as ownership/kernel proof.
func parseUFWAdded(raw []byte) (firewall.UFWRuleInventory, error) {
	out := firewall.EmptyUFWRules("UFW 用户规则报告无法完整解析")
	if len(raw) == 0 || len(raw) > firewall.UFWReadBytes || !utf8.Valid(raw) {
		return out, errors.New("invalid UFW report size or encoding")
	}
	for _, char := range string(raw) {
		if unicode.IsControl(char) && char != '\n' {
			return out, errors.New("UFW report contains control characters")
		}
	}
	const header = "Added user rules (see 'ufw status' for running firewall):"
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) < 2 || lines[0] != header {
		return out, errors.New("unknown UFW report format")
	}
	if len(lines) == 2 && lines[1] == "(None)" {
		out.Available, out.Hash, out.Reason = true, secure.Hash(raw), ""
		return out, nil
	}
	sampleBytes := 0
	for _, line := range lines[1:] {
		if !ufwReportCommand(line) || out.Rules >= firewall.MaxEntries {
			return firewall.EmptyUFWRules("UFW 用户规则报告存在未知内容或超过预算"), errors.New("invalid UFW report command")
		}
		out.Rules++
		if !out.Truncated && len(out.Commands) < 128 && sampleBytes+len(line) <= 64<<10 {
			out.Commands = append(out.Commands, line)
			sampleBytes += len(line)
		} else {
			out.Truncated = true
		}
	}
	out.Available, out.Hash, out.Reason = true, secure.Hash(raw), ""
	return out, nil
}

func ufwReportCommand(line string) bool {
	if len(line) > 4096 {
		return false
	}
	rest, ok := strings.CutPrefix(line, "ufw ")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "route ")
	action, args, ok := strings.Cut(rest, " ")
	return ok && args != "" && (action == "allow" || action == "deny" || action == "reject" || action == "limit")
}

func validUFWRules(in firewall.UFWRuleInventory) bool {
	if in.Commands == nil || len(in.Commands) > 128 || len(in.Reason) > 1024 || in.Rules < 0 || in.Rules > firewall.MaxEntries {
		return false
	}
	if !in.Available {
		return in.Hash == "" && in.Rules == 0 && len(in.Commands) == 0 && !in.Truncated && in.Reason != ""
	}
	if len(in.Hash) != 64 || strings.Trim(in.Hash, "0123456789abcdef") != "" || in.Reason != "" || in.Rules < len(in.Commands) || in.Truncated != (in.Rules > len(in.Commands)) {
		return false
	}
	bytes := 0
	for _, command := range in.Commands {
		if !utf8.ValidString(command) || !ufwReportCommand(command) {
			return false
		}
		for _, char := range command {
			if unicode.IsControl(char) {
				return false
			}
		}
		bytes += len(command)
	}
	return bytes <= 64<<10
}
