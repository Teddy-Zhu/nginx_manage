package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// This evaluator has a closed vocabulary for a NEW, ORIGINAL incoming tuple.
// Unsupported predicates are not assumed to miss. Source predicates must have
// the same result for every address in the policy's source prefixes.
type dockerNATMatch struct {
	match               bool
	target, destination string
	gotoChain           bool
}

func dockerRuleSources(policy firewall.Policy, binding firewall.DockerRuleBinding) []netip.Prefix {
	out := []netip.Prefix{}
	for _, rule := range policy.Rules {
		if rule.ID != binding.RuleID {
			continue
		}
		for _, source := range rule.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err == nil && prefix.Addr().Is4() == (binding.Family == "ipv4") {
				out = append(out, prefix)
			}
		}
		if len(rule.Sources) == 0 {
			prefix := "::/0"
			if binding.Family == "ipv4" {
				prefix = "0.0.0.0/0"
			}
			out = append(out, netip.MustParsePrefix(prefix))
		}
	}
	return out
}

func dockerNATPrefix(value string, family string) (netip.Prefix, error) {
	if value == "0/0" {
		value = "::/0"
		if family == "ipv4" {
			value = "0.0.0.0/0"
		}
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	return netip.ParsePrefix(value)
}

func dockerNATRule(args []string, binding firewall.DockerRuleBinding, sources []netip.Prefix) (dockerNATMatch, error) {
	out := dockerNATMatch{match: true}
	invalid := errors.New("DNAT 路径包含不能完整解释的条件、目标或部分来源匹配")
	seen, modules := map[string]bool{}, map[string]bool{}
	for i := 0; i < len(args); i++ {
		negated := args[i] == "!"
		if negated {
			i++
			if i >= len(args) {
				return out, invalid
			}
		}
		key := args[i]
		switch key {
		case "--in-interface":
			key = "-i"
		case "--source":
			key = "-s"
		case "--destination":
			key = "-d"
		case "--protocol":
			key = "-p"
		case "--match":
			key = "-m"
		case "--destination-port":
			key = "--dport"
		case "--jump":
			key = "-j"
		case "--goto":
			key = "-g"
		}
		if i+1 >= len(args) || key != "-m" && seen[key] {
			return out, invalid
		}
		i++
		value := args[i]
		seen[key] = true
		matched, predicate := true, true
		switch key {
		case "-i":
			pattern := strings.TrimSuffix(value, "+")
			if !firewall.DockerTargetInterface(pattern) {
				return out, invalid
			}
			matched = binding.InputInterface == value
			if strings.HasSuffix(value, "+") {
				matched = strings.HasPrefix(binding.InputInterface, pattern)
			}
		case "-p":
			protocol := value
			switch value {
			case "6":
				protocol = "tcp"
			case "17":
				protocol = "udp"
			case "0":
				protocol = "all"
			}
			if !slices.Contains([]string{"tcp", "udp", "all", "icmp", "ipv6-icmp", "icmpv6", "sctp", "udplite", "esp", "ah", "gre"}, protocol) {
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 || n > 255 || value != strconv.Itoa(n) {
					return out, invalid
				}
			}
			matched = protocol == "all" || protocol == binding.Protocol
		case "-s", "-d":
			prefix, err := dockerNATPrefix(value, binding.Family)
			if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return out, invalid
			}
			if key == "-d" {
				matched = prefix.Contains(netip.MustParseAddr(binding.Destination))
			} else {
				inside, outside := false, false
				for _, source := range sources {
					if prefix.Bits() <= source.Bits() && prefix.Contains(source.Addr()) {
						inside = true
					} else if !prefix.Overlaps(source) {
						outside = true
					} else {
						return out, invalid
					}
				}
				if inside && outside || !inside && !outside {
					return out, invalid
				}
				matched = inside
			}
		case "-m":
			if negated || modules[value] || !slices.Contains([]string{"tcp", "udp", "comment", "addrtype", "conntrack"}, value) {
				return out, invalid
			}
			modules[value] = true
			predicate = false
			if value == "tcp" || value == "udp" {
				predicate, matched = true, value == binding.Protocol
			}
		case "--dport":
			if !modules[binding.Protocol] {
				return out, invalid
			}
			parts := strings.Split(value, ":")
			if len(parts) < 1 || len(parts) > 2 {
				return out, invalid
			}
			lo, err := strconv.Atoi(parts[0])
			if err != nil || lo < 0 || lo > 65535 {
				return out, invalid
			}
			hi := lo
			if len(parts) == 2 {
				hi, err = strconv.Atoi(parts[1])
			}
			if err != nil || hi < lo || hi > 65535 {
				return out, invalid
			}
			matched = binding.HostPort >= lo && binding.HostPort <= hi
		case "--comment":
			if negated || !modules["comment"] {
				return out, invalid
			}
			predicate = false
		case "--dst-type":
			if !modules["addrtype"] || value != "LOCAL" {
				return out, invalid
			}
			// The selected destination is an actual address on the input interface.
			matched = true
		case "--ctstate":
			if !modules["conntrack"] {
				return out, invalid
			}
			states := strings.Split(value, ",")
			for _, state := range states {
				if !slices.Contains([]string{"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"}, state) {
					return out, invalid
				}
			}
			matched = slices.Contains(states, "NEW")
		case "--ctdir":
			if !modules["conntrack"] || !slices.Contains([]string{"ORIGINAL", "REPLY"}, value) {
				return out, invalid
			}
			matched = value == "ORIGINAL"
		case "-j", "-g":
			if negated || out.target != "" {
				return out, invalid
			}
			predicate, out.target, out.gotoChain = false, value, key == "-g"
		case "--to-destination":
			if negated || out.target != "DNAT" || out.gotoChain {
				return out, invalid
			}
			predicate, out.destination = false, value
		default:
			// Do not scan past an unknown extension: later tokens can be its data.
			return out, invalid
		}
		if predicate && matched == negated {
			out.match = false
			return out, nil
		}
	}
	if out.target == "DNAT" && out.destination == "" || out.target != "DNAT" && out.destination != "" {
		return out, invalid
	}
	return out, nil
}

func proveDockerDNAT(ctx context.Context, image iptablesImage, resolved firewall.DockerResolvedBinding, sources []netip.Prefix, budget *int) (string, int, error) {
	invalid := errors.New("实际 PREROUTING 路径不能证明所选 DOCKER DNAT 映射")
	if image.Family != resolved.Binding.Family || len(sources) == 0 {
		return "", 0, invalid
	}
	root := image.chain("nat", "PREROUTING")
	if root == nil || root.Policy != "ACCEPT" {
		return "", 0, invalid
	}
	type step struct {
		Chain string
		Index int
		Match bool
	}
	trace := []step{}
	active := map[string]bool{}
	var walk func(string, int) (bool, error)
	walk = func(name string, depth int) (bool, error) {
		chain := image.chain("nat", name)
		if depth > 16 || active[name] || chain == nil || name != "PREROUTING" && chain.Policy != "-" {
			return false, invalid
		}
		active[name] = true
		defer delete(active, name)
		for index, args := range chain.Rules {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			*budget--
			if *budget < 0 || len(trace) >= 16384 {
				return false, errors.New("DNAT 路径核对超过读取预算")
			}
			match, err := dockerNATRule(args, resolved.Binding, sources)
			if err != nil {
				return false, err
			}
			trace = append(trace, step{name, index, match.match})
			if !match.match || match.target == "" {
				continue
			}
			switch match.target {
			case "DNAT":
				destination, err := netip.ParseAddrPort(match.destination)
				if name != "DOCKER" || err != nil || destination.Addr().String() != resolved.ContainerAddress || int(destination.Port()) != resolved.Binding.ContainerPort {
					return false, invalid
				}
				return true, nil
			case "RETURN":
				return false, nil
			case "ACCEPT", "DROP", "REJECT", "SNAT", "REDIRECT", "MASQUERADE":
				return false, invalid
			default:
				target := image.chain("nat", match.target)
				if target == nil || target.Policy != "-" {
					return false, invalid
				}
				translated, err := walk(match.target, depth+1)
				if err != nil || translated {
					return translated, err
				}
				if match.gotoChain {
					return false, nil
				}
			}
		}
		return false, nil
	}
	translated, err := walk("PREROUTING", 0)
	if err != nil {
		return "", 0, err
	}
	if !translated {
		return "", 0, invalid
	}
	// Filter generations change during this operation. Bind the complete NAT
	// image and ordered traversal instead; full filter drift has its own proof.
	nat := iptablesImage{Family: image.Family, Tables: []iptablesImageTable{}}
	for _, table := range image.Tables {
		if table.Name == "nat" {
			nat.Tables = append(nat.Tables, table)
		}
	}
	raw, err := json.Marshal(struct {
		NAT     string
		Binding firewall.DockerRuleBinding
		Sources []netip.Prefix
		Trace   []step
	}{nat.hash(), resolved.Binding, sources, trace})
	if err != nil {
		return "", 0, err
	}
	return secure.Hash(append([]byte("docker:dnat-path:v2:\x00"), raw...)), len(trace), nil
}
