package agent

import "testing"

func TestFirewallLegacyPresenceWarning(t *testing.T) {
	// Captured from Ubuntu's official iptables 1.8.10: nft-save exits zero,
	// exports its own empty ruleset, and reports the separate legacy tables.
	const ipv4 = "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n"
	const ipv6 = "# Warning: ip6tables-legacy tables present, use ip6tables-legacy-save to see them\n"
	for _, test := range []struct {
		name, tool, action, diagnostic string
		allowed                        bool
	}{
		{"ipv4", "iptables-nft-save", "rules", ipv4, true},
		{"ipv6", "ip6tables-nft-save", "rules", ipv6, true},
		{"wrong-family-v4", "iptables-nft-save", "rules", ipv6, false},
		{"wrong-family-v6", "ip6tables-nft-save", "rules", ipv4, false},
		{"version", "iptables-nft-save", "version", ipv4, false},
		{"legacy", "iptables-legacy-save", "rules", ipv4, false},
		{"default-tool", "iptables-save", "rules", ipv4, false},
		{"nft", "nft", "rules", ipv4, false},
		{"extra-warning", "iptables-nft-save", "rules", ipv4 + "warning: truncated ruleset\n", false},
		{"duplicate", "iptables-nft-save", "rules", ipv4 + ipv4, false},
		{"prefix", "iptables-nft-save", "rules", "warning: failed\n" + ipv4, false},
		{"incompatible-table", "iptables-nft-save", "rules", "# Table `filter' is incompatible, use 'nft' tool.\n", false},
		{"missing-newline", "iptables-nft-save", "rules", ipv4[:len(ipv4)-1], false},
		{"empty", "iptables-nft-save", "rules", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := firewallReadWarningAllowed(test.tool, test.action, []byte(test.diagnostic)); got != test.allowed {
				t.Fatalf("allowed=%v, want %v", got, test.allowed)
			}
		})
	}
}
