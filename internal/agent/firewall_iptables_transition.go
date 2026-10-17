package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const iptablesChangeBytes = 32 << 20
const iptablesRestoreAttempts = 8

type iptablesChangeStep struct{ ID, Family, Target string }

// Large original images stay outside the small operation journal. The journal
// binds their digest; neither these images nor grants belong in migration data.
type iptablesChangeCheckpoint struct {
	Schema      int                       `json:"schema"`
	RequestHash string                    `json:"request_hash"`
	Policy      firewallPolicyRecord      `json:"policy"`
	Operation   firewall.Operation        `json:"operation"`
	Transition  iptablesInitialTransition `json:"transition"`
	Steps       []iptablesChangeStep      `json:"steps"`
	Rollback    bool                      `json:"rollback"`
}

func iptablesChangePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "iptables-change.json")
}

func iptablesChangeHash(v *iptablesChangeCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("iptables:change:v1:\x00"), raw...))
}

func iptablesChangeIntentHash(v *iptablesChangeCheckpoint) string {
	copy := *v
	copy.Operation.State, copy.Operation.Stage, copy.Operation.Error, copy.Operation.ConfirmedSource = "", "", "", ""
	copy.Operation.UpdatedAt, copy.Rollback = 0, false
	return iptablesChangeHash(&copy)
}

func sameIPTablesValue(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

func validateIPTablesTransition(v *iptablesInitialTransition, policy firewallPolicyRecord) error {
	invalid := errors.New("iptables 原业务转换材料无效")
	if v == nil || !validID(v.Owner) || !validID(v.RegistrationOperationID) || !firewalldDigest(v.MachineHash) || !firewalldDigest(v.RegistrationRequestHash) || !firewalldDigest(v.ConfigurationHash) || !firewalldDigest(v.ToolHash) || !validID(policy.PlanID) || policy.Action != "apply" || policy.Version < 1 || validateFirewallProtectionBasis(policy.ProtectionBasis) != nil || !v.Tools.valid() || v.Tools.Backend != policy.Policy.Backend {
		return invalid
	}
	hash, err := firewall.PolicyDigest(policy.Policy)
	program, compileErr := firewall.CompileIPTablesRuntime(policy.Policy, policy.Protections, v.Owner, policy.PlanID)
	if err != nil || compileErr != nil || hash != policy.PolicyHash || program.Hash != policy.ProgramHash || program.Marker != policy.Marker || !sameIPTablesValue(program, v.Program) || len(v.Materials) != len(program.Families) || len(v.Materials) == 0 || len(v.Materials) > 2 {
		return invalid
	}
	proof := &iptablesDryRunProof{ToolchainHash: v.Tools.Hash, ConfigurationHash: v.ConfigurationHash, ProgramHash: program.Hash, Calls: []iptablesDryRunCall{}}
	for index, generation := range program.Families {
		material := v.Materials[index]
		expected, err := initialIPTablesMaterial(material.Before, generation)
		if err != nil || !sameIPTablesValue(expected, material) {
			return invalid
		}
		roundTrip, err := iptablesRoundTrip(material)
		if err != nil {
			return err
		}
		for _, call := range []struct {
			mode  string
			input []byte
		}{{"candidate", material.Candidate}, {"round_trip", roundTrip}} {
			proof.Calls = append(proof.Calls, iptablesDryRunCall{Family: generation.Family, Mode: call.mode, Tool: generation.Binary + "-restore", InputHash: secure.Hash(call.input), InputBytes: len(call.input), OutputHash: secure.Hash(nil), DiagnosticHash: secure.Hash(nil)})
		}
	}
	raw, _ := json.Marshal(proof)
	proof.Hash = secure.Hash(append([]byte("iptables:dry-run:v1:\x00"), raw...))
	if !sameIPTablesValue(proof, v.DryRun) {
		return invalid
	}
	return nil
}

func iptablesChangeTerminal(v *iptablesChangeCheckpoint) bool {
	return v != nil && slices.Contains([]string{"rolled_back", "failed"}, v.Operation.State)
}

func validateIPTablesChange(v *iptablesChangeCheckpoint) error {
	invalid := errors.New("iptables 原业务恢复快照无效")
	if v == nil || v.Schema != 1 || !validID(v.Operation.ID) || v.Policy.OperationID != v.Operation.ID || v.RequestHash != firewallRequestHash(v.Policy.PlanID, v.Policy.Action) || v.Operation.PlanID != v.Policy.PlanID || v.Operation.Action != v.Policy.Action || v.Operation.Version != v.Policy.Version || v.Operation.PolicyHash != v.Policy.PolicyHash || v.Operation.ProgramHash != v.Policy.ProgramHash || v.Operation.Deadline <= 0 || v.Operation.UpdatedAt <= 0 || len(v.Operation.Error) > 512 || v.Operation.ConfirmedSource != "" || !slices.Contains([]string{"running", "waiting_confirmation", "compensating", "recovery_required", "rolled_back", "failed"}, v.Operation.State) {
		return invalid
	}
	if err := validateIPTablesTransition(&v.Transition, v.Policy); err != nil {
		return err
	}
	if v.Operation.ID == v.Policy.PlanID || v.Operation.ID == v.Transition.Owner || v.Operation.ID == v.Transition.RegistrationOperationID || len(v.Operation.Stage) == 0 || len(v.Operation.Stage) > 128 || v.Operation.VerificationScope != "controlled-listener" || v.Rollback != slices.Contains([]string{"compensating", "recovery_required", "rolled_back"}, v.Operation.State) {
		return invalid
	}
	if len(v.Steps) != len(v.Transition.Materials)*(1+iptablesRestoreAttempts) {
		return invalid
	}
	ids := map[string]bool{v.Operation.ID: true, v.Policy.PlanID: true, v.Transition.Owner: true, v.Transition.RegistrationOperationID: true}
	for index, step := range v.Steps {
		material := v.Transition.Materials[index/(1+iptablesRestoreAttempts)]
		target := "previous"
		if index%(1+iptablesRestoreAttempts) == 0 {
			target = "candidate"
		}
		if !validID(step.ID) || ids[step.ID] || step.Family != material.Family || step.Target != target {
			return invalid
		}
		ids[step.ID] = true
	}
	if (v.Operation.State == "compensating" || v.Operation.State == "rolled_back") && !v.Rollback {
		return invalid
	}
	return nil
}

func loadIPTablesChange(dataDir string) (*iptablesChangeCheckpoint, error) {
	raw, err := listenerRead(iptablesChangePath(dataDir), iptablesChangeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v iptablesChangeCheckpoint
	if err = ufwToolJSON(raw, &v); err != nil {
		return nil, err
	}
	if err = validateIPTablesChange(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func iptablesChangeReceiptMatches(r Record, v *iptablesChangeCheckpoint) bool {
	return r.Kind == firewallOperationKind && r.OperationID == v.Operation.ID && r.RequestHash == v.RequestHash && r.CandidateHash == iptablesChangeHash(v) && r.State == v.Operation.State && r.Stage == v.Operation.Stage && r.Deadline == v.Operation.Deadline && r.Error == v.Operation.Error && r.Firewall != nil && sameIPTablesValue(r.Firewall, v.Operation)
}

func saveIPTablesChange(dataDir string, v *iptablesChangeCheckpoint) error {
	if err := validateIPTablesChange(v); err != nil {
		return err
	}
	old, err := loadIPTablesChange(dataDir)
	if err != nil {
		return err
	}
	if old != nil {
		if old.Operation.ID == v.Operation.ID {
			if iptablesChangeIntentHash(old) != iptablesChangeIntentHash(v) || old.Rollback && !v.Rollback || iptablesChangeTerminal(old) && !sameIPTablesValue(old, v) {
				return errors.New("iptables 原意图或终态已变化，禁止覆盖")
			}
		} else if !iptablesChangeTerminal(old) {
			return errors.New("iptables 原业务尚未结束")
		}
	}
	if r, err := loadIPTablesReceipt(dataDir, v.Operation.ID); err == nil {
		if r.Kind != firewallOperationKind || r.OperationID != v.Operation.ID || r.RequestHash != v.RequestHash || r.Firewall == nil || r.Firewall.ID != v.Operation.ID || r.Firewall.PlanID != v.Policy.PlanID || r.Firewall.Action != v.Policy.Action || r.Firewall.Version != v.Policy.Version || r.Firewall.PolicyHash != v.Policy.PolicyHash || r.Firewall.ProgramHash != v.Policy.ProgramHash || r.State != r.Firewall.State || r.Stage != r.Firewall.Stage || r.Deadline != r.Firewall.Deadline || r.Error != r.Firewall.Error || r.Firewall.Deadline != v.Operation.Deadline || !firewalldDigest(r.CandidateHash) || slices.Contains([]string{"succeeded", "rolled_back", "failed"}, r.State) && !iptablesChangeReceiptMatches(r, v) {
			return errors.New("iptables 原业务独立回执冲突")
		}
		if old != nil && old.Operation.ID == v.Operation.ID && (r.Firewall.UpdatedAt > old.Operation.UpdatedAt || slices.Contains([]string{"compensating", "recovery_required"}, r.State) && !old.Rollback) {
			return errors.New("iptables 独立回执晚于原检查点，禁止倒退恢复方向")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = secure.RootDirectory(filepath.Dir(iptablesChangePath(dataDir)), 0700); err != nil {
		return err
	}
	if err = rootJSONWrite(iptablesChangePath(dataDir), v, iptablesChangeBytes); err != nil {
		return err
	}
	op := &v.Operation
	journal := iptablesRegistrationJournal(dataDir)
	if err = secure.RootDirectory(journal.Dir, 0700); err != nil {
		return err
	}
	return journal.Put(Record{OperationID: op.ID, RequestHash: v.RequestHash, Kind: firewallOperationKind, State: op.State, Stage: op.Stage, Deadline: op.Deadline, Error: op.Error, Firewall: op, CandidateHash: iptablesChangeHash(v)})
}

func iptablesBusinessPending(dataDir string) bool {
	v, err := loadIPTablesChange(dataDir)
	if err != nil || iptablesRestorePending(dataDir) {
		return true
	}
	if v == nil {
		return false
	}
	r, err := loadIPTablesReceipt(dataDir, v.Operation.ID)
	return err != nil || !iptablesChangeReceiptMatches(r, v) || !iptablesChangeTerminal(v)
}

func iptablesChangeAuthority(dataDir string, v *iptablesChangeCheckpoint) error {
	registered, err := iptablesRegistrationAuthority(dataDir)
	if err != nil {
		return err
	}
	if registered.NextClaim.Owner != v.Transition.Owner || registered.NextClaim.MachineHash != v.Transition.MachineHash || registered.NextClaim.OperationID != v.Transition.RegistrationOperationID || registered.RequestHash != v.Transition.RegistrationRequestHash || registered.NextClaim.Backend != v.Policy.Policy.Backend {
		return errors.New("iptables 原业务与本机原授权不一致")
	}
	return nil
}

// Caller owns iptables-business.lock. Public admission remains disabled until
// normal confirmation and confirmed-policy repair are fully connected.
func acceptIPTablesChangeLocked(ctx context.Context, dataDir, id string, plan firewallPrivatePlan) (*iptablesChangeCheckpoint, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || (&HostDNS{Scope: "host"}).hostScopeReason() != "" || !validID(id) || !plan.view.CanApply || plan.record == nil || plan.iptables == nil || plan.view.IPTables == nil || plan.view.ID != plan.record.PlanID || plan.view.Action != plan.record.Action || plan.view.Version != plan.record.Version || plan.view.PolicyHash != plan.record.PolicyHash || plan.view.ProgramHash != plan.record.ProgramHash || plan.view.Backend != plan.record.Policy.Backend || time.Now().Unix() >= plan.view.ExpiresAt {
		return nil, errors.New("iptables 业务操作尚不具备完整受理条件")
	}
	if err := validateIPTablesTransition(plan.iptables, *plan.record); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(plan.iptables)
	if len(raw) > 16<<20 || plan.view.TransactionHash != secure.Hash(append([]byte("iptables:initial-plan:v1:\x00"), raw...)) || plan.view.IPTables.ToolchainHash != plan.iptables.Tools.Hash || plan.view.IPTables.DryRunHash != plan.iptables.DryRun.Hash {
		return nil, errors.New("iptables 私有计划摘要不一致")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if iptablesBusinessPending(dataDir) {
		return nil, errors.New("iptables 原业务或子进程尚未完成核对")
	}
	if _, err = loadIPTablesReceipt(dataDir, id); !os.IsNotExist(err) {
		return nil, errors.New("iptables 业务操作标识已使用或无法核对")
	}
	policy := *plan.record
	policy.OperationID = id
	now := time.Now().Unix()
	v := &iptablesChangeCheckpoint{Schema: 1, RequestHash: firewallRequestHash(policy.PlanID, policy.Action), Policy: policy, Transition: *plan.iptables, Operation: firewall.Operation{ID: id, PlanID: policy.PlanID, Action: policy.Action, Version: policy.Version, PolicyHash: policy.PolicyHash, ProgramHash: policy.ProgramHash, State: "running", Stage: "submitting_runtime", Deadline: now + firewall.ConfirmationSeconds, UpdatedAt: now, VerificationScope: "controlled-listener"}}
	for _, material := range v.Transition.Materials {
		v.Steps = append(v.Steps, iptablesChangeStep{ID: secure.ID(), Family: material.Family, Target: "candidate"})
		for range iptablesRestoreAttempts {
			v.Steps = append(v.Steps, iptablesChangeStep{ID: secure.ID(), Family: material.Family, Target: "previous"})
		}
	}
	if err = iptablesChangeAuthority(dataDir, v); err != nil {
		return nil, err
	}
	if err = v.Transition.Tools.verify(ctx); err != nil {
		return nil, err
	}
	baseline, err := inspectIPTablesRegistration(ctx, dataDir, policy.Policy.Backend, true)
	if err != nil || baseline.Hash != v.Transition.ConfigurationHash {
		return nil, errors.New("iptables 原完整环境或规则已变化")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = saveIPTablesChange(dataDir, v); err != nil {
		return nil, err
	}
	return v, nil
}
