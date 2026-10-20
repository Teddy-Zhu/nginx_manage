package agent

import (
	"slices"
	"strings"
	"testing"
)

func TestAgentUpgradeConfiguredEntry(t *testing.T) {
	const entry = "/opt/nginxpanel/current/nginxpanel agent --data-dir /srv/nginxpanel --allowed-uid 998 --nginx-binding --nginx-user nginxpanel-nginx --nginx-modules /etc/nginxpanel/nginx-modules.json --metrics-scope host --component-scope host --maintenance-scope host"
	for _, mode := range []string{"--nginx-binding", "--nginx-container"} {
		base := strings.Replace(entry, "--nginx-binding", mode, 1)
		selections := []string{"", " --dns-scope unconfirmed --dns-owner unconfirmed --firewall-scope unconfirmed --firewall-owner unconfirmed --firewall-ssh unconfirmed"}
		for _, owner := range []string{"regular-file", "networkmanager", "networkd", "netplan"} {
			selections = append(selections, " --dns-scope host --dns-owner "+owner)
		}
		for _, owner := range []string{"direct-nftables", "firewalld", "ufw", "iptables-nft", "iptables-legacy"} {
			selections = append(selections, " --firewall-owner "+owner+" --firewall-scope host --firewall-ssh openssh")
		}
		selections = append(selections, " --dns-scope host --dns-owner netplan --firewall-scope host --firewall-owner iptables-nft --firewall-ssh none")
		for _, selection := range selections {
			t.Run(mode+selection, func(t *testing.T) {
				actual := base + selection
				args, err := agentUpgradeArguments(actual, "/srv/nginxpanel", 998)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(args, strings.Split(actual, " ")) {
					t.Fatal("configured process arguments were changed")
				}
			})
		}
	}
	for name, actual := range map[string]string{
		"binary":           strings.Replace(entry, "/opt/nginxpanel/current/nginxpanel", "/tmp/nginxpanel", 1),
		"command":          strings.Replace(entry, " agent ", " serve ", 1),
		"data":             strings.Replace(entry, "/srv/nginxpanel", "/srv/other", 1),
		"uid":              strings.Replace(entry, "998", "0", 1),
		"binding":          strings.Replace(entry, "--nginx-binding", "--nginx-binary /usr/sbin/nginx", 1),
		"modules":          strings.Replace(entry, "/etc/nginxpanel/nginx-modules.json", "/tmp/modules.json", 1),
		"maintenance":      strings.Replace(entry, "--maintenance-scope host", "--maintenance-scope unconfirmed", 1),
		"duplicate-base":   entry + " --allowed-uid 0",
		"duplicate-owner":  entry + " --firewall-owner ufw --firewall-owner iptables-nft",
		"duplicate-scope":  entry + " --dns-scope host --dns-scope host",
		"unknown":          entry + " --release-trust /tmp/trust.json",
		"dev":              entry + " --dev true",
		"missing-value":    entry + " --firewall-owner",
		"unknown-owner":    entry + " --firewall-owner shell",
		"unknown-dns":      entry + " --dns-owner shell",
		"unknown-scope":    entry + " --firewall-scope container",
		"unknown-ssh":      entry + " --firewall-ssh auto",
		"quoted-value":     entry + " --firewall-owner \"ufw\"",
		"systemd-variable": entry + " --dns-owner ${OWNER}",
		"double-space":     entry + "  --firewall-owner ufw",
	} {
		t.Run(name, func(t *testing.T) {
			args, err := agentUpgradeArguments(actual, "/srv/nginxpanel", 998)
			if err == nil || args != nil {
				t.Fatal("unapproved entry accepted")
			}
		})
	}
}
