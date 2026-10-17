package agent

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"nginxpanel/internal/firewall"
)

// conntrack's save formatter orders options and prints ctproto numerically.
// Extract only our additional tuple predicates, leaving module order and the
// closed transport/comment/verdict grammar to the existing semantic matcher.
func dockerIPTablesRuleKey(chain, family string, args []string) (string, error) {
	invalid := errors.New("Docker 受管规则包含无法核对的参数或 conntrack 条件")
	if _, err := firewall.IPTablesRuleText(args); err != nil || len(args)%2 != 0 {
		return "", invalid
	}
	base, tuple := []string{}, map[string]string{}
	conntrack := false
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if name == "-m" && value == "conntrack" {
			conntrack = true
		}
		if !slices.Contains([]string{"--ctdir", "--ctproto", "--ctorigdst", "--ctorigdstport"}, name) {
			base = append(base, name, value)
			continue
		}
		if !conntrack || tuple[name] != "" {
			return "", invalid
		}
		switch name {
		case "--ctdir":
			if value != "ORIGINAL" && value != "REPLY" {
				return "", invalid
			}
		case "--ctproto":
			protocol, err := ufwKernelProtocol(value)
			if err != nil || protocol != "6" && protocol != "17" {
				return "", invalid
			}
			value = protocol
		case "--ctorigdst":
			address, err := ufwKernelAddress(value, family)
			if err != nil {
				return "", invalid
			}
			value = address
		case "--ctorigdstport":
			ports := strings.Split(value, ":")
			if len(ports) > 2 {
				return "", invalid
			}
			port, err := strconv.Atoi(ports[0])
			if err != nil || port < 1 || port > 65535 {
				return "", invalid
			}
			if len(ports) == 2 {
				end, err := strconv.Atoi(ports[1])
				if err != nil || end != port {
					return "", invalid
				}
			}
			value = strconv.Itoa(port)
		}
		tuple[name] = value
	}
	key, err := iptablesOwnedRuleKey(chain, family, base)
	if err != nil {
		return "", invalid
	}
	raw, err := json.Marshal(struct {
		Rule  string
		Tuple map[string]string
	}{key, tuple})
	return string(raw), err
}
