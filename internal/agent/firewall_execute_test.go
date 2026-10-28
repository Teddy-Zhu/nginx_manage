package agent

import (
	"testing"

	"nginxpanel/internal/firewall"
)

func TestIndependentNFTTableCanCoexistWithLegacyRules(t *testing.T) {
	for _, backend := range []string{"unknown", "nftables", "legacy", "mixed"} {
		t.Run(backend, func(t *testing.T) {
			observed := firewall.Observation{Available: true, Manager: "direct-candidate", Backend: backend}
			for _, id := range []string{"nftables", "iptables-nft-ipv4", "iptables-nft-ipv6", "iptables-legacy-ipv4", "iptables-legacy-ipv6"} {
				observed.Rulesets = append(observed.Rulesets, firewall.Ruleset{ID: id, Available: true})
			}
			if err := checkFirewallManagers(observed); err != nil {
				t.Fatalf("independent fully observed rules must coexist: %v", err)
			}
			for _, manager := range []string{"firewalld", "ufw", "unknown", "conflict"} {
				other := observed
				other.Manager = manager
				if checkFirewallManagers(other) == nil {
					t.Fatalf("must reject manager %s", manager)
				}
			}
			observed.Available = false
			if checkFirewallManagers(observed) == nil {
				t.Fatal("must reject an unavailable observation")
			}
			observed.Available = true
			for i := range observed.Rulesets {
				observed.Rulesets[i].Available = false
				if checkFirewallManagers(observed) == nil {
					t.Fatalf("must reject an incomplete ruleset %s", observed.Rulesets[i].ID)
				}
				observed.Rulesets[i].Available = true
			}
		})
	}
}
