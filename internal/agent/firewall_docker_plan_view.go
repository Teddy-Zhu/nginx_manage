package agent

import (
	"encoding/json"
	"slices"

	"nginxpanel/internal/firewall"
)

// Recompile the typed preview at the IPC boundary. No public command text is
// trusted or later executed, and no view can upgrade this plan to writable.
func validDockerPlan(out firewall.Plan, input firewall.RuntimeInput) bool {
	value := out.Docker
	if value == nil {
		return input.DockerTargets == nil && !(input.Action == "apply" && input.PreparationID == "" && !input.CancelPreparation && firewall.HasDockerRules(input.Policy))
	}
	policy, err := input.Policy.Normalize()
	if err != nil || !firewall.HasDockerRules(policy) || input.Action != "apply" || input.PreparationID != "" || input.CancelPreparation || !validIPTablesBackend(policy.Backend) || out.Backend != policy.Backend || out.Action != "apply" || out.CanApply || out.Preparation != nil || out.IPTables != nil || out.UFW != nil || out.Firewalld != nil || !validID(out.ID) || out.Version != input.Version || out.PolicyHash != policy.Hash() || out.TransactionHash != "" || out.TransactionBytes != 0 || out.ConfirmationSeconds != firewall.ConfirmationSeconds || out.ExpiresAt <= 0 || !firewalldDigest(value.EngineHash) || !firewalldDigest(value.SnapshotHash) || !firewalldDigest(value.ConfigurationHash) || value.ObservedAt <= 0 || !validDockerPublishedPorts(value.Ports, false, "inactive") || value.Truncated && len(value.Ports) != 128 || value.Addresses == nil || len(value.Addresses) > 512 || value.Bindings == nil || len(value.Bindings) > 128 || value.Entries == nil || value.Warnings == nil || len(value.Warnings) > 64 || !dockerFirewallText(value.Reason, 2048) {
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
	if err != nil || value.HostProgramHash != hostProgram.Hash || value.HostGeneratedRules != hostProgram.BaseRules+len(hostProgram.Entries) || out.GeneratedRules != value.HostGeneratedRules+value.GeneratedRules || out.GeneratedRules > firewall.MaxEntries {
		return false
	}
	if !value.Compiled {
		if input.DockerTargets != nil || len(value.Bindings) != 0 || value.BindingsHash != "" || value.ProgramHash != "" || value.ProgramBytes != 0 || value.GeneratedRules != 0 || len(value.Entries) != 0 || value.EntriesTruncated || out.ProgramHash != "" {
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
		if err != nil || value.BindingsHash != program.BindingsHash || value.ProgramHash != program.Hash || value.ProgramBytes != program.Bytes || value.GeneratedRules != len(program.Entries) || len(value.Entries) != min(128, len(program.Entries)) || value.EntriesTruncated != (len(program.Entries) > len(value.Entries)) || !slices.Equal(value.Entries, program.Entries[:len(value.Entries)]) || out.ProgramHash != firewall.DockerPlanHash(policy, value) {
			return false
		}
	}
	raw, err := json.Marshal(out)
	return err == nil && len(raw) <= 512<<10
}
