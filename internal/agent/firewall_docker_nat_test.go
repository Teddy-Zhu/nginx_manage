package agent

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"nginxpanel/internal/firewall"
)

func TestDockerDNATForwardableIPv6Sources(t *testing.T) {
	// Captured from Docker's ip6tables-nft NAT table on the ARM acceptance VM.
	const captured = "! -s fe80::/10 -d fd42:57::10/128 ! -i p5-docker -p tcp -m tcp --dport 18080 -j DNAT --to-destination [fd42:57:1::2]:8080"
	for _, tc := range []struct {
		name, source, predicate, target string
		sameInterface, unknown, want    bool
	}{
		{name: "default Docker rule", source: "::/0", want: true},
		{name: "explicit routed source", source: "fd42:57::/64", want: true},
		{name: "source spans link local", source: "fe00::/8", want: true},
		{name: "only link local", source: "fe80::/64"},
		{name: "other partial source exclusion", source: "::/0", predicate: "2001:db8::/32"},
		{name: "same interface redirect exception", source: "::/0", sameInterface: true},
		{name: "different container", source: "::/0", target: "[fd42:57:1::3]:8080"},
		{name: "unknown extension", source: "::/0", unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := captured
			if tc.predicate != "" {
				rule = strings.Replace(rule, "fe80::/10", tc.predicate, 1)
			}
			if tc.target != "" {
				rule = strings.Replace(rule, "[fd42:57:1::2]:8080", tc.target, 1)
			}
			if tc.unknown {
				rule += " -m mark --mark 0x1"
			}
			image := iptablesImage{Family: "ipv6", Tables: []iptablesImageTable{{Name: "nat", Chains: []iptablesImageChain{
				{Name: "PREROUTING", Policy: "ACCEPT", Rules: [][]string{strings.Fields("-m addrtype --dst-type LOCAL -j DOCKER")}},
				{Name: "DOCKER", Policy: "-", Rules: [][]string{strings.Fields(rule)}},
			}}}}
			resolved := firewall.DockerResolvedBinding{
				Binding:          firewall.DockerRuleBinding{Family: "ipv6", Protocol: "tcp", InputInterface: "p5-in", Destination: "fd42:57::10", HostPort: 18080, ContainerPort: 8080},
				ContainerAddress: "fd42:57:1::2", OutputInterface: "p5-docker",
			}
			if tc.sameInterface {
				resolved.OutputInterface = resolved.Binding.InputInterface
			}
			sources := []netip.Prefix{netip.MustParsePrefix(tc.source)}
			before := sources[0]
			budget := 16384
			digest, rules, err := proveDockerDNAT(context.Background(), image, resolved, sources, &budget)
			if tc.want {
				if err != nil || len(digest) != 64 || rules != 2 {
					t.Fatalf("valid Docker DNAT rejected: digest=%q rules=%d err=%v", digest, rules, err)
				}
			} else if err == nil || digest != "" {
				t.Fatalf("unproved mapping accepted: digest=%q rules=%d err=%v", digest, rules, err)
			}
			if sources[0] != before {
				t.Fatal("policy sources were mutated")
			}
		})
	}
	// Every sibling remains covered; no part of the excluded /10 can be used
	// to turn an otherwise partial source predicate into a false proof.
	sources := dockerIPv6ForwardSources([]netip.Prefix{netip.MustParsePrefix("::/0")})
	for _, address := range []string{"::", "8000::", "c000::", "e000::", "f000::", "f800::", "fc00::", "ff00::", "fe00::", "fec0::"} {
		covered := false
		for _, source := range sources {
			covered = covered || source.Contains(netip.MustParseAddr(address))
			if source.Overlaps(netip.MustParsePrefix("fe80::/10")) {
				t.Fatal("link-local source remains in the forwarding proof")
			}
		}
		if !covered {
			t.Fatalf("eligible source %s was omitted", address)
		}
	}
}
