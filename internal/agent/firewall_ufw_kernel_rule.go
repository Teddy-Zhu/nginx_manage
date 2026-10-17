package agent

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type ufwKernelOption struct {
	Value string
	Not   bool
}
type ufwKernelMatch struct {
	Name    string
	Options map[string]ufwKernelOption
}
type ufwKernelRule struct {
	Base    map[string]ufwKernelOption
	Matches []ufwKernelMatch
	Target  ufwKernelMatch
}

// Compare only the syntax emitted by UFW's explicit rules and standard logging
// and limit expansions. Unknown extensions stay read-only. Match module order
// is retained: recent/limit are stateful and cannot be sorted as predicates.
func ufwKernelRuleKey(line, family string, native bool) (string, string, bool, error) {
	words, err := xtablesQuotedWords(line, native)
	if err != nil || len(words) < 3 || len(words) > 128 || words[0] != "-A" && (!native || words[0] != "-I") {
		return "", "", false, errors.New("UFW 重载规则语法不可核对")
	}
	_, anywhere, ok := ufwNativeIdentity(family)
	if !ok {
		return "", "", false, errors.New("UFW 重载规则地址族无效")
	}
	out := ufwKernelRule{Base: map[string]ufwKernelOption{
		"-s": {Value: anywhere}, "-d": {Value: anywhere}, "-p": {Value: "0"},
	}, Matches: []ufwKernelMatch{}, Target: ufwKernelMatch{Options: map[string]ufwKernelOption{}}}
	seenBase := map[string]bool{}
	for index := 2; index < len(words); index++ {
		negated := false
		if words[index] == "!" {
			negated = true
			index++
			if index >= len(words) {
				return "", "", false, errors.New("UFW 重载规则否定条件不完整")
			}
		}
		name := words[index]
		arity := 1
		if slices.Contains([]string{"--set", "--update", "--rcheck", "--remove", "--rsource", "--rdest", "--rttl", "--reap"}, name) {
			arity = 0
		}
		value := "true"
		if arity != 0 {
			index++
			if index >= len(words) {
				return "", "", false, errors.New("UFW 重载规则参数不完整")
			}
			value = words[index]
		}
		option := ufwKernelOption{Value: value, Not: negated}
		switch name {
		case "-s", "-d", "-p", "-i", "-o":
			if seenBase[name] {
				return "", "", false, errors.New("UFW 重载规则存在重复基础条件")
			}
			seenBase[name] = true
			if name == "-s" || name == "-d" {
				option.Value, err = ufwKernelAddress(value, family)
			} else if name == "-p" {
				option.Value, err = ufwKernelProtocol(value)
			}
			if err != nil {
				return "", "", false, err
			}
			out.Base[name] = option
		case "-m":
			if negated || !slices.Contains([]string{"tcp", "udp", "multiport", "conntrack", "limit", "recent", "comment"}, value) {
				return "", "", false, errors.New("UFW 重载规则包含未支持的匹配模块")
			}
			for _, match := range out.Matches {
				if match.Name == value && value != "multiport" {
					return "", "", false, errors.New("UFW 重载规则包含重复匹配模块")
				}
			}
			out.Matches = append(out.Matches, ufwKernelMatch{Name: value, Options: map[string]ufwKernelOption{}})
		case "-j":
			if negated || out.Target.Name != "" || !ufwKernelTarget(value, family) {
				return "", "", false, errors.New("UFW 重载规则跳转目标不可核对")
			}
			out.Target.Name = value
		default:
			owner := ufwKernelOptionOwner(name)
			if owner == "" {
				return "", "", false, errors.New("UFW 重载规则包含未支持的参数")
			}
			if owner == "transport" {
				owner = map[string]string{"6": "tcp", "17": "udp"}[out.Base["-p"].Value]
				if owner == "" || out.Base["-p"].Not {
					return "", "", false, errors.New("UFW 端口匹配缺少明确的传输协议")
				}
				found := false
				for _, match := range out.Matches {
					found = found || match.Name == owner
				}
				if !found {
					out.Matches = append(out.Matches, ufwKernelMatch{Name: owner, Options: map[string]ufwKernelOption{}})
				}
			}
			var options map[string]ufwKernelOption
			if owner == "LOG" || owner == "REJECT" {
				if out.Target.Name == owner {
					options = out.Target.Options
				}
			} else {
				for i := len(out.Matches) - 1; i >= 0; i-- {
					if out.Matches[i].Name == owner {
						options = out.Matches[i].Options
						break
					}
				}
			}
			if options == nil {
				return "", "", false, errors.New("UFW 重载参数未绑定对应模块或目标")
			}
			if _, exists := options[name]; exists {
				return "", "", false, errors.New("UFW 重载参数重复")
			}
			options[name] = option
		}
	}
	for index := range out.Matches {
		if err = ufwKernelMatchDefaults(&out.Matches[index], family); err != nil {
			return "", "", false, err
		}
		if out.Matches[index].Name == "tcp" && out.Base["-p"] != (ufwKernelOption{Value: "6"}) || out.Matches[index].Name == "udp" && out.Base["-p"] != (ufwKernelOption{Value: "17"}) {
			return "", "", false, errors.New("UFW 传输匹配模块与协议不一致")
		}
	}
	if out.Target.Name == "REJECT" {
		value := "icmp-port-unreachable"
		if family == "ipv6" {
			value = "icmp6-port-unreachable"
		}
		ufwKernelDefault(out.Target.Options, "--reject-with", value)
	} else if out.Target.Name == "LOG" {
		ufwKernelDefault(out.Target.Options, "--log-level", "4")
		ufwKernelDefault(out.Target.Options, "--log-prefix", "")
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", "", false, err
	}
	return words[1], string(raw), words[0] == "-I", nil
}

func ufwKernelOptionOwner(name string) string {
	switch name {
	case "--dport", "--sport":
		return "transport"
	case "--dports", "--sports", "--ports":
		return "multiport"
	case "--ctstate":
		return "conntrack"
	case "--limit", "--limit-burst":
		return "limit"
	case "--set", "--update", "--rcheck", "--remove", "--seconds", "--hitcount", "--rsource", "--rdest", "--mask", "--name", "--rttl", "--reap":
		return "recent"
	case "--comment":
		return "comment"
	case "--log-prefix", "--log-level":
		return "LOG"
	case "--reject-with":
		return "REJECT"
	}
	return ""
}

func ufwKernelDefault(options map[string]ufwKernelOption, name, value string) {
	if _, present := options[name]; !present {
		options[name] = ufwKernelOption{Value: value}
	}
}

func ufwKernelMatchDefaults(match *ufwKernelMatch, family string) error {
	switch match.Name {
	case "tcp", "udp":
		ufwKernelDefault(match.Options, "--sport", "0:65535")
		ufwKernelDefault(match.Options, "--dport", "0:65535")
	case "limit":
		ufwKernelDefault(match.Options, "--limit", "3/hour")
		ufwKernelDefault(match.Options, "--limit-burst", "5")
		option := match.Options["--limit"]
		value, err := ufwKernelRate(option.Value)
		if err != nil || option.Not || match.Options["--limit-burst"].Not {
			return errors.New("UFW 限速参数不可核对")
		}
		option.Value = value
		match.Options["--limit"] = option
	case "recent":
		mask := "255.255.255.255"
		if family == "ipv6" {
			mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
		}
		ufwKernelDefault(match.Options, "--mask", mask)
		ufwKernelDefault(match.Options, "--name", "DEFAULT")
		ufwKernelDefault(match.Options, "--seconds", "0")
		ufwKernelDefault(match.Options, "--hitcount", "0")
		if _, destination := match.Options["--rdest"]; !destination {
			ufwKernelDefault(match.Options, "--rsource", "true")
		}
		address, err := netip.ParseAddr(match.Options["--mask"].Value)
		if err != nil || address.Is4() != (family == "ipv4") {
			return errors.New("UFW recent 地址掩码不可核对")
		}
		option := match.Options["--mask"]
		option.Value = address.String()
		match.Options["--mask"] = option
	case "conntrack":
		if option, present := match.Options["--ctstate"]; present {
			states := strings.Split(option.Value, ",")
			slices.Sort(states)
			option.Value = strings.Join(states, ",")
			match.Options["--ctstate"] = option
		}
	}
	return nil
}

func ufwKernelAddress(value, family string) (string, error) {
	if !strings.Contains(value, "/") {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return "", errors.New("UFW 重载地址不可核对")
		}
		value = netip.PrefixFrom(address, address.BitLen()).String()
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4() != (family == "ipv4") {
		return "", errors.New("UFW 重载地址族或网段不可核对")
	}
	return prefix.Masked().String(), nil
}

func ufwKernelProtocol(value string) (string, error) {
	protocols := map[string]string{"all": "0", "tcp": "6", "udp": "17", "icmp": "1", "ipv6-icmp": "58", "icmpv6": "58", "esp": "50", "ah": "51", "gre": "47", "igmp": "2", "sctp": "132", "vrrp": "112"}
	if number, known := protocols[value]; known {
		return number, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 || number > 255 {
		return "", errors.New("UFW 重载协议不可核对")
	}
	return strconv.Itoa(number), nil
}

func ufwKernelTarget(target, family string) bool {
	if slices.Contains([]string{"ACCEPT", "DROP", "REJECT", "RETURN", "LOG"}, target) {
		return true
	}
	prefix, _, ok := ufwNativeIdentity(family)
	return ok && slices.Contains([]string{prefix + "-user-logging-input", prefix + "-user-logging-output", prefix + "-user-logging-forward", prefix + "-user-limit", prefix + "-user-limit-accept"}, target)
}

func ufwKernelRate(value string) (string, error) {
	amount, unit, found := strings.Cut(value, "/")
	numerator, err := strconv.ParseInt(amount, 10, 64)
	seconds := map[string]int64{"sec": 1, "second": 1, "min": 60, "minute": 60, "hour": 3600, "day": 86400}[unit]
	if !found || err != nil || numerator <= 0 || numerator > 1<<32 || seconds == 0 {
		return "", errors.New("UFW 限速单位或数值不可核对")
	}
	a, b := numerator, seconds
	for b != 0 {
		a, b = b, a%b
	}
	return strconv.FormatInt(numerator/a, 10) + "/" + strconv.FormatInt(seconds/a, 10), nil
}
