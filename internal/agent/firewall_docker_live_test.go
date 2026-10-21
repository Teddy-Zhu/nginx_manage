package agent

import (
	"slices"
	"strings"
	"testing"

	"nginxpanel/internal/firewall"
)

func dockerRevalidationFixture(t *testing.T) (firewall.Policy, *dockerIPTablesPolicyRecord) {
	t.Helper()
	const ruleID = "00000000-0000-0000-0000-000000000064"
	policy := firewall.Policy{Backend: "iptables-nft", Rules: []firewall.Rule{{ID: ruleID, Name: "published", Enabled: true, Scope: "docker_published", Family: "ipv4", Protocol: "tcp", Ports: []firewall.PortRange{{From: 18080, To: 18080}}, Sources: []string{}, Action: "deny", Priority: 100, Interface: "p5-in"}}}
	binding := firewall.DockerRuleBinding{RuleID: ruleID, ContainerID: strings.Repeat("a", 64), NetworkID: strings.Repeat("b", 64), Family: "ipv4", Protocol: "tcp", HostIP: "192.0.2.10", HostPort: 18080, ContainerPort: 8080, Destination: "192.0.2.10", InputInterface: "p5-in"}
	record := &dockerIPTablesPolicyRecord{Targets: firewall.DockerTargets{EngineHash: strings.Repeat("c", 64), SnapshotHash: strings.Repeat("d", 64), Bindings: []firewall.DockerRuleBinding{binding}}, Bindings: []firewall.DockerResolvedBinding{{Binding: binding, ContainerAddress: "172.30.57.2", OutputInterface: "p5-docker", Path: firewall.DockerPathProof{DNATHash: strings.Repeat("e", 64), DNATRules: 2, RoutingHash: strings.Repeat("f", 64), OriginalRouteHash: strings.Repeat("1", 64), RouteHash: strings.Repeat("2", 64), RoutePrefix: "172.30.57.0/24", RouteTable: 254, OutputIndex: 6}}}}
	record.Registration.Owner = "00000000-0000-0000-0000-000000000001"
	program, err := firewall.CompileDockerIPTablesRuntime(policy, record.Targets, record.Bindings, record.Registration.Owner, "00000000-0000-0000-0000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	record.Program = program
	return policy, record
}

func TestDockerRevalidatedProgramPathLifecycle(t *testing.T) {
	policy, record := dockerRevalidationFixture(t)
	frozen := slices.Clone(record.Bindings)
	program := *record.Program
	fresh := slices.Clone(record.Bindings)
	fresh[0].Path = firewall.DockerPathProof{DNATHash: strings.Repeat("3", 64), DNATRules: 3, RoutingHash: strings.Repeat("4", 64), OriginalRouteHash: strings.Repeat("5", 64), RouteHash: strings.Repeat("6", 64), RoutePrefix: "172.30.57.0/25", RouteTable: 254, OutputIndex: 9}
	changed, err := firewall.CompileDockerIPTablesRuntime(policy, record.Targets, fresh, record.Registration.Owner, record.Program.PlanID)
	if err != nil || sameIPTablesValue(changed, record.Program) {
		t.Fatalf("fixture must produce a valid but different observation: %v", err)
	}
	before := slices.Clone(fresh)
	if err = verifyDockerRevalidatedProgram(policy, record, fresh); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fresh, before) || !slices.Equal(record.Bindings, frozen) || !sameIPTablesValue(record.Program, &program) {
		t.Fatal("revalidation mutated current evidence or frozen generation")
	}
}

func TestDockerRevalidatedProgramRetainsIdentity(t *testing.T) {
	changes := map[string]func(*firewall.DockerResolvedBinding){
		"container":             func(v *firewall.DockerResolvedBinding) { v.Binding.ContainerID = strings.Repeat("7", 64) },
		"network":               func(v *firewall.DockerResolvedBinding) { v.Binding.NetworkID = strings.Repeat("7", 64) },
		"published-port":        func(v *firewall.DockerResolvedBinding) { v.Binding.HostPort++ },
		"container-port":        func(v *firewall.DockerResolvedBinding) { v.Binding.ContainerPort++ },
		"destination":           func(v *firewall.DockerResolvedBinding) { v.Binding.Destination = "192.0.2.20" },
		"input-interface":       func(v *firewall.DockerResolvedBinding) { v.Binding.InputInterface = "other-in" },
		"endpoint":              func(v *firewall.DockerResolvedBinding) { v.ContainerAddress = "172.30.57.3" },
		"output-interface":      func(v *firewall.DockerResolvedBinding) { v.OutputInterface = "other-bridge" },
		"invalid-current-proof": func(v *firewall.DockerResolvedBinding) { v.Path.RouteHash = "" },
		"invalid-current-route": func(v *firewall.DockerResolvedBinding) { v.Path.RouteTable = 100 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			policy, record := dockerRevalidationFixture(t)
			fresh := slices.Clone(record.Bindings)
			change(&fresh[0])
			if verifyDockerRevalidatedProgram(policy, record, fresh) == nil {
				t.Fatal("changed identity or invalid proof accepted")
			}
		})
	}
	t.Run("frozen-program", func(t *testing.T) {
		policy, record := dockerRevalidationFixture(t)
		record.Program.Hash = strings.Repeat("8", 64)
		if verifyDockerRevalidatedProgram(policy, record, record.Bindings) == nil {
			t.Fatal("changed frozen generation accepted")
		}
	})
}
