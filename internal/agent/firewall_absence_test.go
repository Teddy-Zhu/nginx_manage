package agent

import (
	"os"
	"path/filepath"
	"testing"

	"nginxpanel/internal/firewall"
)

func TestNFTAbsenceRequiresCompleteFamilyInventory(t *testing.T) {
	base := firewall.Ruleset{ID: "nftables", Backend: "nftables", Family: "all", Available: true, Tables: []firewall.Table{{Family: "inet", Name: "firewalld"}}}
	for _, test := range []struct {
		name, family string
		available    bool
		tables       []firewall.Table
		want         bool
	}{
		{"ipv4", "ipv4", true, base.Tables, true},
		{"ipv6", "ipv6", true, base.Tables, true},
		{"incomplete", "ipv4", false, nil, false},
		{"empty-ip-table", "ipv4", true, []firewall.Table{{Family: "ip", Name: "filter"}}, false},
		{"empty-ip6-table", "ipv6", true, []firewall.Table{{Family: "ip6", Name: "filter"}}, false},
		{"other-family", "ipv4", true, []firewall.Table{{Family: "ip6", Name: "filter"}}, true},
		{"unknown-family", "inet", true, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := base
			view.Available = test.available
			view.Tables = test.tables
			if got := nftFamilyAbsent(view, test.family); got != test.want {
				t.Fatalf("absent=%v want=%v", got, test.want)
			}
		})
	}
}

func TestXtablesAbsenceRejectsPartialAndBrokenInstallations(t *testing.T) {
	dir := t.TempDir()
	if !xtablesToolsAbsentAt("iptables-nft", dir) {
		t.Fatal("both applets are absent")
	}
	save := filepath.Join(dir, "iptables-nft-save")
	if err := os.WriteFile(save, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if xtablesToolsAbsentAt("iptables-nft", dir) {
		t.Fatal("existing untrusted save applet was treated as absent")
	}
	if err := os.Remove(save); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(dir, "iptables-nft")); err != nil {
		t.Fatal(err)
	}
	if xtablesToolsAbsentAt("iptables-nft", dir) {
		t.Fatal("dangling applet symlink was treated as absent")
	}
}

func TestLegacyAbsenceRequiresProcfs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ip_tables_names"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if legacyTablesAbsentAt(dir, "ipv4") {
		t.Fatal("empty ordinary file was accepted as kernel evidence")
	}
}
