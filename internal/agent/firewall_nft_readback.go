package agent

// The full nft JSON view has a separate budget from native iptables-save and
// the direct nftables target-table netlink dump. Evidence stays in private root
// inspections and never enters public IPC responses or migration materials.
const nftRulesetReadBytes = 4 << 20

type nftReadbackScope struct {
	Bytes, NumberGrowth, Objects, Rules int
}

type nftReadbackBudget struct {
	Bytes, NumberGrowth, Objects, Schema int
	Scopes                               map[string]nftReadbackScope
}

func nftReadbackKey(family, table, chain string) string {
	return family + "\x00" + table + "\x00" + chain
}

func (v nftReadbackBudget) complete() bool {
	return v.Schema == 1 && v.Bytes > 0 && v.Bytes <= nftRulesetReadBytes && v.NumberGrowth >= 0 && v.Objects > 0 && v.Objects <= firewallObjectLimit && v.Scopes != nil
}

// Reserve every numeric token up to the maximum signed/unsigned 64-bit width.
// This also covers rules with several counters; object counts alone cannot
// bound counter growth. Quoted addresses, comments and names are not numbers.
func nftNumberGrowth(raw []byte) int {
	growth := 0
	for i := 0; i < len(raw); {
		if raw[i] == '"' {
			i++
			for i < len(raw) {
				if raw[i] == '\\' {
					i += 2
				} else if raw[i] == '"' {
					i++
					break
				} else {
					i++
				}
			}
			continue
		}
		if raw[i] != '-' && (raw[i] < '0' || raw[i] > '9') {
			i++
			continue
		}
		start := i
		for i < len(raw) && (raw[i] >= '0' && raw[i] <= '9' || raw[i] == '-' || raw[i] == '+' || raw[i] == '.' || raw[i] == 'e' || raw[i] == 'E') {
			i++
		}
		if size := i - start; size < 21 {
			growth += 21 - size
		}
	}
	return growth
}
