package agent

import (
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/firewall"
)

func TestFirewallMaintenancePendingWhileLocked(t *testing.T) {
	var f hostFirewall
	f.mu.Lock()
	done := make(chan bool, 1)
	go func() { done <- f.pendingWithLock(false) }()
	select {
	case busy := <-done:
		f.mu.Unlock()
		if !busy {
			t.Fatal("locked firewall reported idle to maintenance")
		}
	case <-time.After(time.Second):
		f.mu.Unlock()
		<-done
		t.Fatal("maintenance waited for the firewall lock")
	}
}

func TestFirewallReadContentionFailsClosed(t *testing.T) {
	var f hostFirewall
	f.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		view := f.View()
		op, err := f.Operation("00000000-0000-4000-8000-000000000001")
		done <- !view.Available && !view.CanPlan && err != nil && op.ID == ""
	}()
	select {
	case closed := <-done:
		f.mu.Unlock()
		if !closed {
			t.Fatal("contended firewall read claimed availability or an operation")
		}
	case <-time.After(time.Second):
		f.mu.Unlock()
		<-done
		t.Fatal("firewall read waited for background recovery")
	}
}

func TestIPTablesLibraryOwnedJumps(t *testing.T) {
	const owner = "ca58fdb5-830d-414b-b502-0b9501f9ac92"
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, test := range []struct{ name, chain, policy, target, marker string }{
			{"input", "INPUT", "ACCEPT", firewall.IPTablesHostChain, "nginxpanel:host:hook:v1:" + owner},
			{"host-pointer", firewall.IPTablesHostChain, "-", firewall.IPTablesHostChain + "-c6b3f7704b53", "nginxpanel:host:generation:v1:" + owner},
			{"docker-pointer", firewall.IPTablesDockerChain, "-", firewall.IPTablesDockerChain + "-0123456789", "nginxpanel:docker:generation:v1:" + owner},
		} {
			t.Run(family+"/"+test.name, func(t *testing.T) {
				// Native -S replies include these custom jump targets. A terminal
				// verdict parser cannot authenticate their hook or pointer.
				args := []string{"-m", "comment", "--comment", test.marker, "-j", test.target}
				chain := iptablesImageChain{Name: test.chain, Policy: test.policy, Rules: [][]string{args}}
				image := iptablesImage{Family: family, Tables: []iptablesImageTable{{Name: "filter", Chains: []iptablesImageChain{chain}}}}
				declaration := "-N " + test.chain
				if test.chain == "INPUT" {
					declaration = "-P INPUT ACCEPT"
				}
				row := "-A " + test.chain + " -m comment --comment \"" + test.marker + "\" -j " + test.target
				if err := compareIPTablesLibraryChain(image, test.chain, []string{declaration, row}); err != nil {
					t.Fatalf("native owned jump rejected: %v", err)
				}
				for _, changed := range []string{
					strings.Replace(row, "-j "+test.target, "-j DROP", 1),
					strings.Replace(row, owner, "00000000-0000-4000-8000-000000000000", 1),
					row + " -m conntrack --ctstate NEW",
				} {
					if err := compareIPTablesLibraryChain(image, test.chain, []string{declaration, changed}); err == nil {
						t.Fatalf("changed owned jump accepted: %s", changed)
					}
				}
				if test.chain == "INPUT" {
					image.Tables[0].Chains[0].Rules = append(chain.Rules, []string{"-j", "P5-FOREIGN"})
					foreign := "-A INPUT -j P5-FOREIGN"
					if err := compareIPTablesLibraryChain(image, test.chain, []string{declaration, row, foreign}); err != nil {
						t.Fatalf("foreign rule after owned hook rejected: %v", err)
					}
					if err := compareIPTablesLibraryChain(image, test.chain, []string{declaration, foreign, row}); err == nil {
						t.Fatal("moved owned hook accepted")
					}
				}
			})
		}
	}
}
