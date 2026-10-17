package agent

import (
	"errors"
	"slices"

	"nginxpanel/internal/firewall"
)

// This closed grammar includes original conntrack tuples and bridge output.
// It reserves inline nft statements with the same conservative option budget
// as INPUT; no sets, maps or external stateful objects are generated.
func dockerIPTablesNFTRuleBytes(chain string, args []string) (int, error) {
	if _, err := firewall.IPTablesRuleText(args); err != nil || len(args)%2 != 0 {
		return 0, errors.New("Docker 规则不满足 nft JSON 容量语法")
	}
	reserved := 512 + 6*len(chain)
	for i := 0; i < len(args); i += 2 {
		switch args[i] {
		case "-m":
			if !slices.Contains([]string{"tcp", "udp", "conntrack", "comment"}, args[i+1]) {
				return 0, errors.New("Docker 匹配模块未纳入 nft JSON 容量准入")
			}
		case "-p", "--dport", "-s", "-d", "-i", "-o", "--ctstate", "--ctdir", "--ctproto", "--ctorigdst", "--ctorigdstport", "--comment", "-j", "--reject-with":
		default:
			return 0, errors.New("Docker 生成选项未纳入 nft JSON 容量准入")
		}
		reserved += 512 + 6*len(args[i+1])
	}
	return reserved, nil
}
