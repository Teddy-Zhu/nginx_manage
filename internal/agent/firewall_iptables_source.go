package agent

import (
	"errors"

	"nginxpanel/internal/firewall"
)

// A bounded confirmation reference survives replacement of the latest business
// checkpoint. Its independent terminal receipt remains the source of authority.
type iptablesPolicySource struct {
	Owner, MachineHash, RegistrationOperationID, RegistrationRequestHash, ToolHash string
	Policy                                                                         firewallPolicyRecord
	Operation                                                                      firewall.Operation
	CheckpointHash                                                                 string
	Tools                                                                          iptablesToolBinding
	Docker                                                                         *dockerIPTablesPolicyRecord `json:",omitempty"`
}

func validateIPTablesSource(source *iptablesPolicySource) error {
	invalid := errors.New("iptables 原确认来源无效")
	if source == nil || !validID(source.Owner) || !validID(source.RegistrationOperationID) || !firewalldDigest(source.MachineHash) || !firewalldDigest(source.RegistrationRequestHash) || !firewalldDigest(source.ToolHash) || !firewalldDigest(source.CheckpointHash) || !source.Tools.valid() || source.Tools.Backend != source.Policy.Policy.Backend || source.Policy.Action != "apply" && source.Policy.Action != "remove" || source.Policy.Version < 1 || validateFirewallProtectionBasis(source.Policy.ProtectionBasis) != nil {
		return invalid
	}
	record, op := source.Policy, source.Operation
	stage := "confirmed"
	if record.Action == "remove" {
		stage = "rules_removed"
	}
	if !validID(record.OperationID) || !validID(record.PlanID) || record.OperationID == record.PlanID || record.OperationID == source.Owner || record.OperationID == source.RegistrationOperationID || op.ID != record.OperationID || op.PlanID != record.PlanID || op.Action != record.Action || op.Version != record.Version || op.PolicyHash != record.PolicyHash || op.ProgramHash != record.ProgramHash || op.State != "succeeded" || op.Stage != stage || op.Error != "" || op.Deadline <= 0 || op.UpdatedAt <= 0 || op.VerificationScope != "controlled-listener" || !validUFWConfirmationSource(op.ConfirmedSource) {
		return invalid
	}
	if err := validateDockerIPTablesPolicy(source.Docker, record, source.Owner, source.MachineHash, source.RegistrationOperationID, source.RegistrationRequestHash); err != nil {
		return err
	}
	program, err := firewall.CompileIPTablesRuntime(firewall.HostPolicy(record.Policy), record.Protections, source.Owner, record.PlanID, record.Action)
	hash, hashErr := firewall.PolicyDigest(record.Policy)
	if err != nil || hashErr != nil || hash != record.PolicyHash || iptablesTransitionProgramHash(&iptablesTransition{Program: program, Docker: source.Docker}) != record.ProgramHash || program.Marker != record.Marker {
		return invalid
	}
	return nil
}

func iptablesPolicySourceFor(v *iptablesChangeCheckpoint) *iptablesPolicySource {
	if v == nil || v.Confirmed == nil {
		return nil
	}
	if v.Operation.State != "succeeded" {
		return v.Transition.Previous
	}
	return &iptablesPolicySource{Owner: v.Transition.Owner, MachineHash: v.Transition.MachineHash, RegistrationOperationID: v.Transition.RegistrationOperationID, RegistrationRequestHash: v.Transition.RegistrationRequestHash, ToolHash: v.Transition.ToolHash, Policy: v.Policy, Operation: v.Operation, CheckpointHash: iptablesChangeHash(v), Tools: *v.Transition.Tools, Docker: v.Transition.Docker}
}

func iptablesPlanPrevious(v *iptablesChangeCheckpoint, owner, registrationID string) *iptablesPolicySource {
	source := iptablesPolicySourceFor(v)
	if source != nil && source.Policy.Action == "remove" && (source.Owner != owner || source.RegistrationOperationID != registrationID) {
		return nil // A released empty namespace grants no policy to a new registration.
	}
	return source
}

func verifyIPTablesSource(dataDir string, source *iptablesPolicySource) error {
	if err := validateIPTablesSource(source); err != nil {
		return err
	}
	if source.Docker != nil {
		grant := &source.Docker.Registration
		if grant.DataDir != dataDir {
			return errors.New("Docker 原确认来源不属于本机数据目录")
		}
		if err := dockerRegistrationReceipt(dataDir, grant); err != nil {
			return err
		}
	}
	r, err := loadIPTablesReceipt(dataDir, source.Policy.OperationID)
	if err != nil || r.Kind != firewallOperationKind || r.OperationID != source.Policy.OperationID || r.RequestHash != firewallRequestHash(source.Policy.PlanID, source.Policy.Action) || r.CandidateHash != source.CheckpointHash || r.State != source.Operation.State || r.Stage != source.Operation.Stage || r.Deadline != source.Operation.Deadline || r.Error != source.Operation.Error || r.Firewall == nil || !sameIPTablesValue(r.Firewall, source.Operation) {
		return errors.New("iptables 原确认来源与独立终态回执不一致")
	}
	return nil
}

func iptablesPreviousProgram(transition *iptablesTransition) *firewall.IPTablesRuntimeProgram {
	if transition == nil || transition.Previous == nil {
		return nil
	}
	record := transition.Previous.Policy
	program, _ := firewall.CompileIPTablesRuntime(firewall.HostPolicy(record.Policy), record.Protections, transition.Previous.Owner, record.PlanID, record.Action)
	return program // Callers validate the immutable source before inspecting it.
}

func iptablesTransitionFamilies(transition *iptablesTransition) []string {
	out := []string{}
	previous := iptablesPreviousProgram(transition)
	for _, family := range []string{"ipv4", "ipv6"} {
		if iptablesGeneration(transition.Program, family) != nil || iptablesGeneration(previous, family) != nil || dockerIPTablesGeneration(transition.Docker, family) != nil || dockerIPTablesGeneration(iptablesPreviousDocker(transition), family) != nil {
			out = append(out, family)
		}
	}
	return out
}
