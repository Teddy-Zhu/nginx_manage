package agent

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"nginxpanel/internal/firewall"
)

func TestIPTablesNFTSyntheticInputProjection(t *testing.T) {
	// Docker's actual nft filter table has FORWARD and DOCKER-USER, while
	// iptables-nft-save also exports a synthetic empty ACCEPT INPUT.
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, name := range []string{"synthetic", "existing", "missing native", "missing scope", "missing metadata", "drop policy", "populated", "scope drift", "metadata drift", "missing docker", "valid docker"} {
			t.Run(family+"/"+name, func(t *testing.T) {
				table := firewall.Table{Family: iptablesNFTFamily(family), Name: "filter", Chains: []firewall.Chain{{Name: "FORWARD"}}}
				image := iptablesImage{Family: family, Tables: []iptablesImageTable{{Name: "filter", Chains: []iptablesImageChain{{Name: "INPUT", Policy: "ACCEPT"}, {Name: "FORWARD", Policy: "DROP"}}}}}
				capacity := nftReadbackBudget{Scopes: map[string]nftReadbackScope{}}
				key := nftReadbackKey(table.Family, "filter", "INPUT")
				host := &firewall.IPTablesGeneration{Family: family}
				var docker *firewall.IPTablesGeneration
				want, materialized := true, true
				if slices.Contains([]string{"existing", "missing scope", "scope drift", "metadata drift"}, name) {
					table.Chains = append(table.Chains, firewall.Chain{Name: "INPUT"})
				}
				if slices.Contains([]string{"existing", "missing metadata", "scope drift", "metadata drift"}, name) {
					capacity.Scopes[key] = nftReadbackScope{Objects: 1}
				}
				switch name {
				case "existing":
					materialized = false
				case "missing native":
					image.Tables[0].Chains = image.Tables[0].Chains[1:]
					want = false
				case "missing scope", "missing metadata":
					want = false
				case "drop policy":
					image.Tables[0].Chains[0].Policy = "DROP"
					want = false
				case "populated":
					image.Tables[0].Chains[0].Rules = [][]string{{"-j", "ACCEPT"}}
					want = false
				case "scope drift":
					capacity.Scopes[key] = nftReadbackScope{Objects: 2}
					want = false
				case "metadata drift":
					table.Chains[1].Rules = 1
					want = false
				case "missing docker", "valid docker":
					docker = &firewall.IPTablesGeneration{Family: family}
					image.Tables[0].Chains = append(image.Tables[0].Chains, iptablesImageChain{Name: "DOCKER-USER", Policy: "-"})
					want = name == "valid docker"
					if want {
						table.Chains = append(table.Chains, firewall.Chain{Name: "DOCKER-USER"})
						capacity.Scopes[nftReadbackKey(table.Family, "filter", "DOCKER-USER")] = nftReadbackScope{Objects: 1}
					}
				}
				before := slices.Clone(table.Chains)
				_, projected, created, err := projectIPTablesReadbackTable([]firewall.Table{table}, capacity, image, host, docker, nil)
				if want {
					if err != nil || created != materialized {
						t.Fatalf("projection: created=%v err=%v", created, err)
					}
					ci := slices.IndexFunc(projected.Chains, func(c firewall.Chain) bool { return c.Name == "INPUT" })
					if ci < 0 || projected.Chains[ci].Rules != 1 {
						t.Fatal("projected INPUT does not include the entry rule")
					}
					chain := projected.Chains[ci]
					if created && (chain.Type != "filter" || chain.Hook != "input" || chain.Priority == nil || *chain.Priority != 0 || chain.Policy != "accept") {
						t.Fatalf("invalid materialized INPUT: %+v", chain)
					}
				} else if err == nil {
					t.Fatal("contradictory or unproved entry was accepted")
				}
				if !reflect.DeepEqual(before, table.Chains) {
					t.Fatal("observed metadata was mutated")
				}
			})
		}
	}
}

func TestIPTablesNFTSyntheticInputCapacity(t *testing.T) {
	policy := firewall.DefaultPolicy()
	policy.Backend = "iptables-nft"
	protections := []firewall.Protection{{Service: "ssh", Family: "ipv4", Port: 22, Sources: []string{"192.0.2.11/32"}}, {Service: "ssh", Family: "ipv6", Port: 22, Sources: []string{"fd42:57::11/128"}}}
	program, err := firewall.CompileIPTablesRuntime(policy, protections, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "apply")
	if err != nil || len(program.Families) != 2 {
		t.Fatalf("compile host program: %v", err)
	}
	reservedBytes, reservedObjects := 0, 0
	for _, generation := range program.Families {
		budget, err := iptablesNFTGenerationBudget(&generation, false)
		if err != nil {
			t.Fatal(err)
		}
		reservedBytes += budget.Bytes
		reservedObjects += budget.Objects
	}
	for _, name := range []string{"objects exceed", "objects fit", "bytes exceed", "bytes fit"} {
		t.Run(name, func(t *testing.T) {
			snapshot := iptablesRegistrationSnapshot{NFT: nftReadbackBudget{Schema: 1, Bytes: 1024, Objects: 4, Scopes: map[string]nftReadbackScope{}}}
			for _, family := range []string{"ipv4", "ipv6"} {
				snapshot.Images = append(snapshot.Images, iptablesImage{Family: family, Tables: []iptablesImageTable{{Name: "filter", Chains: []iptablesImageChain{{Name: "INPUT", Policy: "ACCEPT"}, {Name: "FORWARD", Policy: "ACCEPT"}, {Name: "OUTPUT", Policy: "ACCEPT"}}}}})
			}
			snapshot.Observed.Rulesets = []firewall.Ruleset{{ID: "nftables", Available: true, Tables: []firewall.Table{{Family: "ip", Name: "filter", Chains: []firewall.Chain{{Name: "FORWARD"}}}, {Family: "ip6", Name: "filter", Chains: []firewall.Chain{{Name: "FORWARD"}}}}}}
			if strings.HasPrefix(name, "objects") {
				// Opaque foreign objects already consume the remaining budget.
				snapshot.NFT.Objects = firewallObjectLimit - reservedObjects
				if name == "objects fit" {
					snapshot.NFT.Objects -= 2
				}
			} else {
				snapshot.NFT.Bytes = nftRulesetReadBytes - reservedBytes
				if name == "bytes fit" {
					snapshot.NFT.Bytes -= 2 * iptablesNFTInputChainBytes
				}
			}
			err := snapshot.admitCombinedReadback(iptablesProgramPair{Host: program}, iptablesProgramPair{})
			if strings.HasSuffix(name, "fit") {
				if err != nil {
					t.Fatalf("bounded projection refused: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "16384") {
				t.Fatalf("new INPUT header was not counted: %v", err)
			}
		})
	}
}
