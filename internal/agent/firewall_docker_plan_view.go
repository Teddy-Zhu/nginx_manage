package agent

import (
	"encoding/json"
	"slices"
	"strings"

	"nginxpanel/internal/firewall"
)

// Recompile the typed plan at the IPC boundary. The public summary never
// supplies commands or substitutes for the root executor's live admission.
func validDockerPlan(out firewall.Plan, input firewall.RuntimeInput) bool {
	value := out.Docker
	if value == nil {
		return input.DockerTargets == nil && !(input.Action == "apply" && input.PreparationID == "" && !input.CancelPreparation && firewall.HasDockerRules(input.Policy))
	}
	policy, err := input.Policy.Normalize()
	if err != nil || !firewall.HasDockerRules(policy) || input.Action != "apply" || input.PreparationID != "" || input.CancelPreparation || !validIPTablesBackend(policy.Backend) || out.Backend != policy.Backend || out.Action != "apply" || out.Preparation != nil || out.UFW != nil || out.Firewalld != nil || !validID(out.ID) || out.Version != input.Version || out.PolicyHash != policy.Hash() || out.ConfirmationSeconds != firewall.ConfirmationSeconds || out.ExpiresAt <= 0 || !firewalldDigest(value.EngineHash) || !firewalldDigest(value.SnapshotHash) || !firewalldDigest(value.ConfigurationHash) || value.ObservedAt <= 0 || !validDockerPublishedPorts(value.Ports, false, "inactive") || value.Truncated && len(value.Ports) != 128 || value.Addresses == nil || len(value.Addresses) > 512 || value.Bindings == nil || len(value.Bindings) > 128 || value.Entries == nil || value.Warnings == nil || len(value.Warnings) > 64 || !dockerFirewallText(value.Reason, 2048) {
		return false
	}
	seen := map[string]bool{}
	for _, address := range value.Addresses {
		key := address.Interface + ":" + address.Address
		if seen[key] || !firewall.DockerTargetInterface(address.Interface) || !firewall.DockerTargetAddress(address.Address, address.Family) {
			return false
		}
		seen[key] = true
	}
	for _, warning := range value.Warnings {
		if !dockerFirewallText(warning, 2048) {
			return false
		}
	}
	hostProgram, err := firewall.CompileIPTablesProtected(firewall.HostPolicy(policy), out.Protections)
	if err != nil || value.HostProgramHash != hostProgram.Hash || value.HostGeneratedRules != hostProgram.BaseRules+len(hostProgram.Entries) || out.GeneratedRules > firewall.MaxEntries {
		return false
	}
	if !value.Compiled {
		if out.CanApply || input.DockerTargets != nil || out.IPTables != nil || out.TransactionHash != "" || out.TransactionBytes != 0 || out.GeneratedRules != value.HostGeneratedRules || value.Transition != nil || len(value.Bindings) != 0 || value.BindingsHash != "" || value.ProgramHash != "" || value.ProgramBytes != 0 || value.GeneratedRules != 0 || len(value.Entries) != 0 || value.EntriesTruncated || out.ProgramHash != "" {
			return false
		}
	} else {
		if input.DockerTargets == nil || value.EngineHash != input.DockerTargets.EngineHash || value.SnapshotHash != input.DockerTargets.SnapshotHash {
			return false
		}
		for _, binding := range value.Bindings {
			if !slices.Contains(value.Addresses, firewall.DockerLocalAddress{Interface: binding.Binding.InputInterface, Family: binding.Binding.Family, Address: binding.Binding.Destination}) {
				return false
			}
		}
		program, err := firewall.CompileDockerIPTables(policy, *input.DockerTargets, value.Bindings)
		if err != nil || value.BindingsHash != program.BindingsHash || value.ProgramHash != program.Hash || value.ProgramBytes != program.Bytes || value.GeneratedRules != len(program.Entries) || len(value.Entries) != min(128, len(program.Entries)) || value.EntriesTruncated != (len(program.Entries) > len(value.Entries)) {
			return false
		}
		if !validDockerTransitionPlan(out, policy, *input.DockerTargets) {
			return false
		}
	}
	raw, err := json.Marshal(out)
	return err == nil && len(raw) <= 512<<10
}

func validDockerTransitionPlan(out firewall.Plan, policy firewall.Policy, targets firewall.DockerTargets) bool {
	v, host := out.Docker.Transition, out.IPTables
	if v == nil || host == nil || !validID(v.Owner) || !validID(v.HostOwner) || v.Owner == v.HostOwner || !validID(v.RegistrationOperationID) || !validID(v.ParentOperationID) || v.RegistrationOperationID == v.Owner || v.RegistrationOperationID == v.ParentOperationID || out.ID == v.RegistrationOperationID || out.ID == v.ParentOperationID || !firewalldDigest(v.RegistrationHash) || !firewalldDigest(v.ToolHash) || !firewalldDigest(v.ToolchainHash) || !firewalldDigest(v.DryRunHash) || v.DryRunCommands != 2*len(host.Families) || v.HookChain != "DOCKER-USER" || v.EntryChain != firewall.IPTablesDockerChain || !firewalldDigest(v.TransactionHash) || v.TransactionHash != out.TransactionHash || v.TransactionBytes != out.TransactionBytes || v.Families == nil {
		return false
	}
	hostProgram, err := firewall.CompileIPTablesRuntime(firewall.HostPolicy(policy), out.Protections, v.HostOwner, out.ID, "apply")
	if err != nil || hostProgram.Hash != v.HostRuntimeHash || hostProgram.Bytes != v.HostRuntimeBytes || host.RegistrationOperationID != v.ParentOperationID || !firewalldDigest(host.ConfigurationHash) || host.ToolHash != v.ToolHash || host.ToolchainHash != v.ToolchainHash || host.DryRunHash != v.DryRunHash || host.DryRunCommands != v.DryRunCommands || host.LogicalHash != hostProgram.LogicalHash || host.ProtectionRules != hostProgram.ProtectionRules || len(host.Families) == 0 || len(host.Families) > 2 || host.Warnings == nil || len(host.Warnings) > 64 || !dockerFirewallText(host.Reason, 2048) {
		return false
	}
	for _, warning := range host.Warnings {
		if !dockerFirewallText(warning, 2048) {
			return false
		}
	}
	program, err := firewall.CompileDockerIPTablesRuntime(policy, targets, out.Docker.Bindings, v.Owner, out.ID)
	if err != nil || v.RuntimeHash != program.Hash || v.RuntimeBytes != program.Bytes || v.GeneratedRules != program.GeneratedRules || len(v.Families) != len(program.Families) || !slices.Equal(out.Docker.Entries, program.Entries[:len(out.Docker.Entries)]) || out.ProgramHash != firewall.IPTablesCombinedProgramHash(hostProgram.Hash, program.Hash) {
		return false
	}
	batches := map[string]firewall.IPTablesFamilyPlan{}
	bytes, generated := 0, program.GeneratedRules
	last := ""
	for _, family := range host.Families {
		if !validDockerFamilyBatch(family, policy.Backend) || last >= family.Family {
			return false
		}
		last = family.Family
		next := iptablesGeneration(hostProgram, family.Family)
		if next != nil {
			if family.Chain != next.Chain || family.HookPosition != 1 || family.GeneratedRules != len(next.Rules)+2 {
				return false
			}
		} else if family.HookPosition != 0 || family.GeneratedRules != 0 || family.Chain != "" && (!strings.HasPrefix(family.Chain, firewall.IPTablesHostChain+"-") || len(family.Chain) != len(firewall.IPTablesHostChain)+13 || strings.Trim(strings.TrimPrefix(family.Chain, firewall.IPTablesHostChain+"-"), "0123456789abcdef") != "") {
			return false
		}
		batches[family.Family] = family
		bytes += family.CandidateBytes
		generated += family.GeneratedRules
	}
	for _, generation := range hostProgram.Families {
		if _, ok := batches[generation.Family]; !ok {
			return false
		}
	}
	for index, family := range v.Families {
		generation := program.Families[index]
		base, ok := batches[generation.Family]
		if !ok || family.Family != generation.Family || family.Binary != generation.Binary || family.Chain != generation.Chain || family.HookPosition != 1 || family.GeneratedRules != len(generation.Rules)+2 {
			return false
		}
		base.Chain, base.HookPosition, base.GeneratedRules = family.Chain, family.HookPosition, family.GeneratedRules
		if !sameIPTablesValue(base, family) {
			return false
		}
	}
	return v.TransactionBytes == bytes && out.GeneratedRules == generated && generated <= firewall.MaxEntries
}

func validDockerFamilyBatch(v firewall.IPTablesFamilyPlan, backend string) bool {
	binary := backend
	if v.Family == "ipv6" {
		binary = "ip6tables-" + strings.TrimPrefix(backend, "iptables-")
	} else if v.Family != "ipv4" {
		return false
	}
	return v.Binary == binary && v.PreservedRules >= 0 && v.PreservedRules <= firewallObjectLimit && firewalldDigest(v.BeforeHash) && firewalldDigest(v.AfterHash) && v.BeforeHash != v.AfterHash && firewalldDigest(v.CandidateHash) && firewalldDigest(v.PreviousHash) && v.CandidateBytes > 0 && v.CandidateBytes <= firewall.IPTablesProgramBytes && v.PreviousBytes > 0 && v.PreviousBytes <= firewall.IPTablesProgramBytes
}
