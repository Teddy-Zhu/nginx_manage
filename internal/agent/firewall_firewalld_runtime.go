package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const firewalldCheckpointBytes = 2 << 20

// Each call is durable before dispatch. A timeout cannot cancel a handler in
// firewalld; compensation must wait for its reply or original process exit.
type firewalldMutation struct {
	Plane    string          `json:"plane"`
	Target   string          `json:"target"`
	BusID    string          `json:"bus_id"`
	BusOwner string          `json:"bus_owner"`
	Peer     networkdProcess `json:"peer"`
	Ended    bool            `json:"ended"`
}
type firewalldCheckpoint struct {
	Schema                  int                   `json:"schema"`
	Owner                   string                `json:"owner"`
	MachineHash             string                `json:"machine_hash"`
	RegistrationOperationID string                `json:"registration_operation_id"`
	RuntimeHash             string                `json:"runtime_hash"`
	PermanentHash           string                `json:"permanent_hash"`
	Confirmed               *firewallPolicyRecord `json:"confirmed"`
	Candidate               *firewallPolicyRecord `json:"candidate"`
	Operation               *firewall.Operation   `json:"operation"`
	RequestHash             string                `json:"request_hash"`
	Rollback                bool                  `json:"rollback"`
	Call                    *firewalldMutation    `json:"call"`
	LastRescue              string                `json:"last_rescue"`
}

func firewalldStatePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "firewalld-runtime.json")
}
func firewalldProgram(record *firewallPolicyRecord) (*firewall.FirewalldProgram, error) {
	if record == nil {
		return firewall.CompileFirewalld(firewall.Policy{Backend: "firewalld", Rules: []firewall.Rule{}})
	}
	p, err := firewall.CompileFirewalldRuntime(record.Policy, record.Protections, record.Action)
	if err == nil && p.Hash != record.ProgramHash {
		err = errors.New("firewalld 独立程序摘要变化")
	}
	return p, err
}
func loadFirewalldState(dataDir string) (*firewalldCheckpoint, error) {
	raw, err := listenerRead(firewalldStatePath(dataDir), firewalldCheckpointBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v firewalldCheckpoint
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&v); err != nil {
		return nil, err
	}
	invalid := errors.New("firewalld 独立恢复记录无效")
	if d.Decode(new(any)) != io.EOF || v.Schema != 1 || !validID(v.Owner) || !firewalldDigest(v.MachineHash) || !validID(v.RegistrationOperationID) || !firewalldDigest(v.RuntimeHash) || !firewalldDigest(v.PermanentHash) || v.LastRescue != "" && !validID(v.LastRescue) {
		return nil, invalid
	}
	for _, r := range []*firewallPolicyRecord{v.Confirmed, v.Candidate} {
		if r == nil {
			continue
		}
		hash, err := firewall.PolicyDigest(r.Policy)
		if err != nil || hash != r.PolicyHash || r.Policy.Backend != "firewalld" || !validID(r.OperationID) || !validID(r.PlanID) || r.Version < 1 || r.Marker != "nginxpanel:firewalld:v1:"+v.Owner || validateFirewallProtectionBasis(r.ProtectionBasis) != nil {
			return nil, invalid
		}
		if _, err = firewalldProgram(r); err != nil {
			return nil, err
		}
	}
	if v.Operation == nil {
		return nil, invalid
	}
	op := v.Operation
	if !validID(op.ID) || !validID(op.PlanID) || op.Version < 1 || !firewalldDigest(op.PolicyHash) || !firewalldDigest(op.ProgramHash) || op.Action != "apply" && op.Action != "remove" || op.UpdatedAt <= 0 || op.Deadline <= 0 || v.RequestHash != firewallRequestHash(op.PlanID, op.Action) {
		return nil, invalid
	}
	active := slices.Contains([]string{"running", "waiting_confirmation", "compensating", "recovery_required"}, op.State)
	if !active && !slices.Contains([]string{"succeeded", "rolled_back", "failed"}, op.State) || active != (v.Candidate != nil) {
		return nil, invalid
	}
	match := func(r *firewallPolicyRecord) bool {
		return r != nil && op.ID == r.OperationID && op.PlanID == r.PlanID && op.Version == r.Version && op.PolicyHash == r.PolicyHash && op.ProgramHash == r.ProgramHash && op.Action == r.Action
	}
	if active && !match(v.Candidate) || op.State == "succeeded" && !match(v.Confirmed) || !active && v.Rollback {
		return nil, invalid
	}
	if c := v.Call; c != nil {
		if !slices.Contains([]string{"runtime", "permanent"}, c.Plane) || !slices.Contains([]string{"candidate", "confirmed"}, c.Target) || !validFirewalldBusID(c.BusID) || !validFirewalldBusOwner(c.BusOwner) || !validDNSProcess(c.Peer) || c.Target == "candidate" && v.Candidate == nil {
			return nil, invalid
		}
	}
	return &v, nil
}
func firewalldStateHash(v *firewalldCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("nginxpanel:firewalld-runtime:v1:\x00"), raw...))
}
func firewalldStateReceipt(dataDir string, v *firewalldCheckpoint) error {
	r, err := firewalldRegistrationJournal(dataDir).Get(v.Operation.ID)
	if err != nil {
		return err
	}
	if r.Kind != firewallOperationKind || r.RequestHash != v.RequestHash || r.CandidateHash != firewalldStateHash(v) || r.State != v.Operation.State || r.Stage != v.Operation.Stage || r.Firewall == nil {
		return errors.New("firewalld 独立回执不一致")
	}
	actual, _ := json.Marshal(r.Firewall)
	expected, _ := json.Marshal(v.Operation)
	if string(actual) != string(expected) {
		return errors.New("firewalld 独立操作内容不一致")
	}
	return nil
}
func (f *hostFirewall) persistFirewalld() (bool, error) {
	v := f.firewalldState
	if err := rootJSONWrite(firewalldStatePath(f.dataDir), v, firewalldCheckpointBytes); err != nil {
		f.problem = "firewalld 独立恢复记录无法保存"
		return false, err
	}
	op := v.Operation
	if op == nil {
		return true, nil
	}
	if old, err := f.journal.Get(op.ID); err == nil {
		if old.Kind != firewallOperationKind || old.RequestHash != v.RequestHash {
			f.problem = "firewalld 操作身份冲突"
			return true, errors.New(f.problem)
		}
	} else if !os.IsNotExist(err) {
		f.problem = "firewalld 独立回执无法读取"
		return true, err
	}
	err := f.journal.Put(Record{OperationID: op.ID, RequestHash: v.RequestHash, Kind: firewallOperationKind, State: op.State, Stage: op.Stage, Deadline: op.Deadline, Error: op.Error, Firewall: op, CandidateHash: firewalldStateHash(v)})
	if err != nil {
		f.problem = "firewalld 独立操作回执无法保存"
	}
	return true, err
}
func (f *hostFirewall) saveFirewalld() error { _, err := f.persistFirewalld(); return err }

// Match every official setting, including empty flags/tuples not exposed in
// the public summary. Only the compiler's exact, ordered rich rules may vary.
func firewalldSettingsMatch(settings map[string]dbus.Variant, owner string, p *firewall.FirewalldProgram) bool {
	values, ok := firewalldOwnedRules(settings, owner)
	return ok && slices.Equal(values, p.Settings.RichRules)
}
func firewalldOwnedRules(settings map[string]dbus.Variant, owner string) ([]string, bool) {
	if settings == nil {
		return nil, false
	}
	empty := make(map[string]dbus.Variant, len(settings))
	for k, v := range settings {
		if k != "rich_rules" {
			empty[k] = v
		}
	}
	if !firewalldEmptyMatches(empty, owner) {
		return nil, false
	}
	value, exists := settings["rich_rules"]
	if !exists {
		return []string{}, true
	}
	rules, ok := value.Value().([]string)
	if !ok || value.Signature().String() != "as" || len(rules) > firewall.MaxEntries {
		return nil, false
	}
	return rules, true
}
func firewalldActive(s firewalldRegistrationSnapshot) bool {
	return s.Policy.Runtime != nil && s.Policy.Permanent != nil && s.Policy.Active && slices.Equal(s.Policy.ActiveIngressZones, []string{"ANY"}) && slices.Equal(s.Policy.ActiveEgressZones, []string{"HOST"})
}
func (f *hostFirewall) firewalldSnapshot(ctx context.Context) (firewalldRegistrationSnapshot, error) {
	var out firewalldRegistrationSnapshot
	b, err := openFirewalldBus(ctx)
	if err != nil {
		return out, err
	}
	defer b.close()
	out, err = b.registrationSnapshot()
	if err == nil && !firewalldActive(out) {
		err = errors.New("firewalld 原运行/永久 policy 或活动绑定缺失")
	}
	return out, err
}
func (f *hostFirewall) firewalldConfirmedSnapshot(ctx context.Context) (firewalldRegistrationSnapshot, error) {
	out, err := f.firewalldSnapshot(ctx)
	if err != nil {
		return out, err
	}
	p, err := firewalldProgram(f.firewalldState.Confirmed)
	if err != nil {
		return out, err
	}
	if !firewalldSettingsMatch(out.Runtime, f.firewalldState.Owner, p) || !firewalldSettingsMatch(out.Permanent, f.firewalldState.Owner, p) {
		return out, errors.New("firewalld 已确认完整配置发生变化")
	}
	return out, nil
}
func (f *hostFirewall) firewalldFailure(reason string) error {
	v := f.firewalldState
	if v.Operation != nil && v.Candidate != nil {
		v.Operation.State, v.Operation.Stage, v.Operation.Error, v.Operation.UpdatedAt = "recovery_required", "restore_unproven", reason, time.Now().Unix()
	}
	f.problem, f.retryAt = reason, time.Now().Add(10*time.Second)
	if v.Operation != nil {
		if err := f.saveFirewalld(); err != nil {
			return err
		}
	}
	return fault.Unavailable(reason)
}

func (f *hostFirewall) firewalldViewLocked() firewall.RuntimeView {
	v := f.firewalldState
	out := firewall.RuntimeView{Backend: "firewalld", Available: f.available && f.problem == "" && v.Candidate == nil && v.Call == nil, Reason: f.problem, Kernel: firewall.KernelView{Reason: "firewalld 通过运行/永久配置核对，不提供直接 nftables 内核事务证明"}, Protections: []firewall.Protection{}, ConfirmedAction: "none"}
	if out.Reason == "" && (v.Candidate != nil || v.Call != nil) {
		out.Reason = "存在待确认或待恢复的 firewalld 操作"
	}
	if out.Reason == "" && !f.available {
		out.Reason = "本机 root 尚未授权 firewalld 新操作；独立恢复继续运行"
	}
	if r := v.Confirmed; r != nil {
		out.ConfirmedAction, out.ConfirmedPlanID, out.ConfirmedOperationID = r.Action, r.PlanID, r.OperationID
		out.ConfirmedVersion, out.ConfirmedPolicyHash = r.Version, r.PolicyHash
		if r.Action == "apply" {
			out.Protections = append(out.Protections, r.Protections...)
		}
	}
	if v.Operation != nil {
		op := *v.Operation
		out.Operation = &op
	}
	out.CanPlan, out.ProtectionObservation = out.Available, f.protectionObservationLocked()
	return out
}
