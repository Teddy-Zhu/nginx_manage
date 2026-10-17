package agent

import (
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

const iptablesRepairKind = "firewall.iptables.repair"

type iptablesRepairSource struct {
	Owner, MachineHash, RegistrationOperationID, RegistrationRequestHash, ToolHash string
	Policy                                                                         firewallPolicyRecord
	Tools                                                                          iptablesToolBinding
}

type iptablesRepairStatus struct {
	ID, OperationID, PlanID, State, Error, IntentHash string
	UpdatedAt                                         int64
}

type iptablesRepairCheckpoint struct {
	Schema            int
	Status            iptablesRepairStatus
	Source            iptablesRepairSource
	ConfigurationHash string
	Materials         []iptablesRepairMaterial
	Steps             []iptablesChangeStep
}

func iptablesRepairPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "iptables-repair.json")
}

func iptablesRepairIntentHash(v *iptablesRepairCheckpoint) string {
	copy := *v
	copy.Status.State, copy.Status.Error, copy.Status.IntentHash, copy.Status.UpdatedAt = "", "", "", 0
	raw, _ := json.Marshal(copy)
	return secure.Hash(append([]byte("iptables:repair-intent:v1:\x00"), raw...))
}

func iptablesRepairHash(v *iptablesRepairCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("iptables:repair:v1:\x00"), raw...))
}

func iptablesRepairTerminal(v *iptablesRepairCheckpoint) bool {
	return v != nil && slices.Contains([]string{"succeeded", "superseded"}, v.Status.State)
}

func validateIPTablesRepair(v *iptablesRepairCheckpoint) error {
	invalid := errors.New("iptables 已确认策略修复检查点无效")
	if v == nil || v.Schema != 1 || !validID(v.Status.ID) || v.Status.OperationID != v.Source.Policy.OperationID || v.Status.PlanID != v.Source.Policy.PlanID || !validID(v.Status.OperationID) || !validID(v.Status.PlanID) || v.Status.ID == v.Status.OperationID || v.Status.ID == v.Status.PlanID || v.Status.IntentHash != iptablesRepairIntentHash(v) || len(v.Status.Error) > 512 || v.Status.UpdatedAt <= 0 || !slices.Contains([]string{"running", "recovery_required", "succeeded", "superseded"}, v.Status.State) || !validID(v.Source.Owner) || !validID(v.Source.RegistrationOperationID) || !firewalldDigest(v.Source.MachineHash) || !firewalldDigest(v.Source.RegistrationRequestHash) || !firewalldDigest(v.Source.ToolHash) || !firewalldDigest(v.ConfigurationHash) || !v.Source.Tools.valid() || v.Source.Tools.Backend != v.Source.Policy.Policy.Backend || v.Source.Policy.Action != "apply" || v.Source.Policy.Version < 1 || validateFirewallProtectionBasis(v.Source.Policy.ProtectionBasis) != nil {
		return invalid
	}
	program, err := firewall.CompileIPTablesRuntime(v.Source.Policy.Policy, v.Source.Policy.Protections, v.Source.Owner, v.Source.Policy.PlanID)
	hash, hashErr := firewall.PolicyDigest(v.Source.Policy.Policy)
	if err != nil || hashErr != nil || hash != v.Source.Policy.PolicyHash || program.Hash != v.Source.Policy.ProgramHash || program.Marker != v.Source.Policy.Marker || len(v.Materials) != len(program.Families) || len(v.Materials) == 0 || len(v.Materials) > 2 || len(v.Steps) != 3*len(v.Materials) {
		return invalid
	}
	ids := map[string]bool{v.Status.ID: true, v.Status.OperationID: true, v.Status.PlanID: true, v.Source.Owner: true, v.Source.RegistrationOperationID: true}
	for index, material := range v.Materials {
		expected, err := repairIPTablesMaterial(material.Before, program.Families[index])
		if err != nil || !sameIPTablesValue(expected, material) {
			return invalid
		}
	}
	for index, step := range v.Steps {
		if !validID(step.ID) || ids[step.ID] || step.Target != "repair" || step.Family != v.Materials[index/3].Family {
			return invalid
		}
		ids[step.ID] = true
	}
	return nil
}

func loadIPTablesRepair(dataDir string) (*iptablesRepairCheckpoint, error) {
	raw, err := listenerRead(iptablesRepairPath(dataDir), iptablesChangeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v iptablesRepairCheckpoint
	if err = ufwToolJSON(raw, &v); err != nil {
		return nil, err
	}
	if err = validateIPTablesRepair(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func iptablesRepairReceiptMatches(r Record, v *iptablesRepairCheckpoint) bool {
	return r.Kind == iptablesRepairKind && r.OperationID == v.Status.ID && r.RelatedOperationID == v.Status.OperationID && r.RequestHash == v.Status.IntentHash && r.State == v.Status.State && r.Error == v.Status.Error && r.CandidateHash == iptablesRepairHash(v) && r.IPTablesRepair != nil && sameIPTablesValue(r.IPTablesRepair, v.Status)
}

func saveIPTablesRepair(dataDir string, v *iptablesRepairCheckpoint) error {
	if err := validateIPTablesRepair(v); err != nil {
		return err
	}
	old, err := loadIPTablesRepair(dataDir)
	if err != nil {
		return err
	}
	if old != nil {
		if old.Status.ID == v.Status.ID {
			if old.Status.IntentHash != v.Status.IntentHash || iptablesRepairTerminal(old) && !sameIPTablesValue(old, v) {
				return errors.New("iptables 原修复意图或终态变化")
			}
		} else {
			receipt, err := loadIPTablesReceipt(dataDir, old.Status.ID)
			if !iptablesRepairTerminal(old) || err != nil || !iptablesRepairReceiptMatches(receipt, old) {
				return errors.New("iptables 原修复尚未完成核对")
			}
		}
	}
	if r, err := loadIPTablesReceipt(dataDir, v.Status.ID); err == nil {
		if r.Kind != iptablesRepairKind || r.RequestHash != v.Status.IntentHash || r.IPTablesRepair == nil || r.RelatedOperationID != v.Status.OperationID || r.IPTablesRepair.ID != v.Status.ID || r.IPTablesRepair.IntentHash != v.Status.IntentHash || slices.Contains([]string{"succeeded", "superseded"}, r.State) && !iptablesRepairReceiptMatches(r, v) {
			return errors.New("iptables 原修复独立回执冲突")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = secure.RootDirectory(filepath.Dir(iptablesRepairPath(dataDir)), 0700); err != nil {
		return err
	}
	if err = rootJSONWrite(iptablesRepairPath(dataDir), v, iptablesChangeBytes); err != nil {
		return err
	}
	journal := iptablesRegistrationJournal(dataDir)
	if err = secure.RootDirectory(journal.Dir, 0700); err != nil {
		return err
	}
	status := v.Status
	return journal.Put(Record{OperationID: status.ID, RelatedOperationID: status.OperationID, Kind: iptablesRepairKind, RequestHash: status.IntentHash, State: status.State, Stage: "confirmed_runtime_repair", Error: status.Error, IPTablesRepair: &status, CandidateHash: iptablesRepairHash(v)})
}

func iptablesRepairPending(dataDir string) bool {
	v, err := loadIPTablesRepair(dataDir)
	if err != nil {
		return true
	}
	if v == nil {
		return false
	}
	r, err := loadIPTablesReceipt(dataDir, v.Status.ID)
	return err != nil || !iptablesRepairReceiptMatches(r, v) || !iptablesRepairTerminal(v)
}

func iptablesRepairSourceFor(v *iptablesChangeCheckpoint) iptablesRepairSource {
	return iptablesRepairSource{Owner: v.Transition.Owner, MachineHash: v.Transition.MachineHash, RegistrationOperationID: v.Transition.RegistrationOperationID, RegistrationRequestHash: v.Transition.RegistrationRequestHash, ToolHash: v.Transition.ToolHash, Policy: v.Policy, Tools: *v.Transition.Tools}
}

func iptablesRepairSourceMatches(repair *iptablesRepairCheckpoint, v *iptablesChangeCheckpoint) bool {
	return v != nil && v.Operation.State == "succeeded" && v.Confirmed != nil && sameIPTablesValue(repair.Source, iptablesRepairSourceFor(v))
}

func iptablesRestoreMatchesRepair(r *iptablesRestoreReceipt, v *iptablesRepairCheckpoint) bool {
	if !validIPTablesRestore(r) || v == nil || r.Target != "repair" || r.RepairID != v.Status.ID || r.ParentIntentHash != v.Status.IntentHash || r.OperationID != v.Status.OperationID || r.Owner != v.Source.Owner || r.MachineHash != v.Source.MachineHash || r.RegistrationOperationID != v.Source.RegistrationOperationID || r.ProgramHash != v.Source.Policy.ProgramHash || r.ToolchainHash != v.Source.Tools.Hash || !sameIPTablesValue(r.Helper, v.Source.Tools.Helper) {
		return false
	}
	allowed := false
	for _, step := range v.Steps {
		if step.ID == r.ID && step.Family == r.Family {
			allowed = true
		}
	}
	if !allowed {
		return false
	}
	for _, material := range v.Materials {
		if material.Family != r.Family {
			continue
		}
		restore, err := v.Source.Tools.tool(material.Binary + "-restore")
		if err != nil {
			return false
		}
		blocker, err := v.Source.Tools.tool("false")
		return err == nil && r.InputBytes == len(material.Input) && r.InputHash == material.InputHash && sameIPTablesValue(r.Restore, restore) && sameIPTablesValue(r.Blocker, blocker)
	}
	return false
}

// Same closed child transport, with a different durable parent intent. Never
// mutates or reopens the original successful business operation.
func runIPTablesRepairRestore(ctx context.Context, dataDir string, request iptablesRestoreRequest) (*iptablesRestoreReceipt, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, errors.New("iptables 修复须由本机 root 执行")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	processUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-process.lock")
	if err != nil {
		return nil, err
	}
	defer processUnlock()
	v, err := loadIPTablesChange(dataDir)
	if err != nil {
		return nil, err
	}
	repair, err := loadIPTablesRepair(dataDir)
	if err != nil || repair == nil || iptablesRepairTerminal(repair) || !iptablesRepairSourceMatches(repair, v) || request.OperationID != v.Operation.ID {
		return nil, errors.New("iptables 修复缺少原已确认业务及独立意图")
	}
	parent, err := loadIPTablesReceipt(dataDir, v.Operation.ID)
	if err != nil || !iptablesChangeReceiptMatches(parent, v) {
		return nil, errors.New("iptables 已确认业务回执尚未核对")
	}
	root, err := loadIPTablesReceipt(dataDir, repair.Status.ID)
	if err != nil || !iptablesRepairReceiptMatches(root, repair) {
		return nil, errors.New("iptables 独立修复回执尚未核对")
	}
	var material *iptablesRepairMaterial
	for _, step := range repair.Steps {
		if step.ID == request.ID {
			for index := range repair.Materials {
				if repair.Materials[index].Family == step.Family {
					material = &repair.Materials[index]
				}
			}
		}
	}
	if material == nil || len(material.Input) == 0 {
		return nil, errors.New("iptables 修复许可或批次缺失")
	}
	if old, err := loadIPTablesReceipt(dataDir, request.ID); err == nil {
		if !iptablesRestoreRecordMatches(old, old.IPTablesRestore) || !iptablesRestoreMatchesRepair(old.IPTablesRestore, repair) {
			return nil, errors.New("iptables 原修复调用身份冲突")
		}
		return old.IPTablesRestore, iptablesRestoreResult(old.IPTablesRestore)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if iptablesRestorePending(dataDir) {
		return nil, errors.New("iptables 原执行子进程尚未结束")
	}
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	current, err := inspectIPTablesChangeScope(ctx, dataDir, v, true)
	if err != nil || current.Hash != repair.ConfigurationHash {
		return nil, errors.New("iptables 原修复基线已变化")
	}
	if err = checkIPTablesInterfaces(v.Policy.Policy, current.Observed); err != nil {
		return nil, err
	}
	matched := false
	for _, image := range current.Images {
		if image.Family == material.Family {
			matched = image.hash() == material.BeforeHash
		}
	}
	if !matched {
		return nil, errors.New("iptables 原修复完整地址族已变化")
	}
	blocker, err := repair.Source.Tools.tool("false")
	if err != nil {
		return nil, err
	}
	restore, err := repair.Source.Tools.tool(material.Binary + "-restore")
	if err != nil {
		return nil, err
	}
	r := &iptablesRestoreReceipt{Schema: 2, ID: request.ID, OperationID: request.OperationID, RepairID: repair.Status.ID, Owner: repair.Source.Owner, MachineHash: repair.Source.MachineHash, RegistrationOperationID: repair.Source.RegistrationOperationID, ParentIntentHash: repair.Status.IntentHash, ProgramHash: repair.Source.Policy.ProgramHash, ToolchainHash: repair.Source.Tools.Hash, Target: "repair", Family: material.Family, InputHash: material.InputHash, InputBytes: len(material.Input), Helper: repair.Source.Tools.Helper, Restore: restore, Blocker: blocker, GuardVersion: 1, Phase: "prepared"}
	r.RequestHash = iptablesRestoreRequestHash(*r)
	if err = saveIPTablesRestore(dataDir, r); err != nil {
		return nil, err
	}
	return launchIPTablesRestore(ctx, dataDir, r, material.Input, guard)
}

// Caller owns the business lock; the source is the original root confirmation.
func reconcileIPTablesConfirmedLocked(ctx context.Context, dataDir string, v *iptablesChangeCheckpoint) error {
	if v == nil || v.Confirmed == nil {
		if iptablesRepairPending(dataDir) {
			return errors.New("iptables 修复缺少原确认策略")
		}
		return nil
	}
	if v.Operation.State != "succeeded" {
		return errors.New("iptables 已确认策略对应的业务终态无效")
	}
	parent, err := loadIPTablesReceipt(dataDir, v.Operation.ID)
	if err != nil || !iptablesChangeReceiptMatches(parent, v) {
		return errors.New("iptables 原确认回执尚未完成")
	}
	if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
		return err
	}
	for _, generation := range v.Transition.Program.Families {
		if err = iptablesCandidateReceipt(dataDir, v, generation.Family); err != nil {
			return err
		}
	}
	current, err := inspectIPTablesChangeScope(ctx, dataDir, v, true)
	if err != nil {
		return err
	}
	repair, err := loadIPTablesRepair(dataDir)
	if err != nil {
		return err
	}
	if repair != nil {
		if err = saveIPTablesRepair(dataDir, repair); err != nil {
			return err
		}
		if !iptablesRepairTerminal(repair) && !iptablesRepairSourceMatches(repair, v) {
			return errors.New("iptables 原修复对应其他确认来源")
		}
	}
	complete := true
	for _, state := range current.States {
		complete = complete && state != "missing"
	}
	if complete {
		if repair != nil && !iptablesRepairTerminal(repair) {
			return finishIPTablesRepair(ctx, dataDir, v, repair)
		}
		return nil
	}
	// A changed complete foreign baseline is never replayed. End all original
	// children first, then preserve the old intent and prepare from current state.
	if repair != nil && !iptablesRepairTerminal(repair) {
		changed := current.Hash != repair.ConfigurationHash
		for _, material := range repair.Materials {
			for _, image := range current.Images {
				if image.Family == material.Family && current.States[image.Family] == "missing" && image.hash() != material.BeforeHash {
					changed = true
				}
			}
		}
		if changed {
			repair.Status.State, repair.Status.Error, repair.Status.UpdatedAt = "superseded", "当前完整基线变化，原进程已结束；依据当前已确认规则另建修复", time.Now().Unix()
			if err = saveIPTablesRepair(dataDir, repair); err != nil {
				return err
			}
		}
	}
	if repair == nil || iptablesRepairTerminal(repair) {
		repair = &iptablesRepairCheckpoint{Schema: 1, Status: iptablesRepairStatus{ID: secure.ID(), OperationID: v.Operation.ID, PlanID: v.Policy.PlanID, State: "running", UpdatedAt: time.Now().Unix()}, Source: iptablesRepairSourceFor(v), ConfigurationHash: current.Hash, Materials: []iptablesRepairMaterial{}, Steps: []iptablesChangeStep{}}
		for _, generation := range v.Transition.Program.Families {
			for _, image := range current.Images {
				if image.Family != generation.Family {
					continue
				}
				material, err := repairIPTablesMaterial(image, generation)
				if err != nil {
					return err
				}
				if len(material.Input) != 0 {
					restore, err := repair.Source.Tools.tool(material.Binary + "-restore")
					if err != nil {
						return err
					}
					blocker, err := repair.Source.Tools.tool("false")
					if err != nil {
						return err
					}
					if _, err = runIPTablesBound(ctx, restore, blocker, "test", material.Input); err != nil {
						return err
					}
				}
				repair.Materials = append(repair.Materials, material)
				for range 3 {
					repair.Steps = append(repair.Steps, iptablesChangeStep{ID: secure.ID(), Family: image.Family, Target: "repair"})
				}
			}
		}
		repair.Status.IntentHash = iptablesRepairIntentHash(repair)
		if err = saveIPTablesRepair(dataDir, repair); err != nil {
			return err
		}
	}
	fail := func(reason string) error {
		repair.Status.State, repair.Status.Error, repair.Status.UpdatedAt = "recovery_required", reason, time.Now().Unix()
		return errors.Join(errors.New(reason), saveIPTablesRepair(dataDir, repair))
	}
	for _, material := range repair.Materials {
		current, err = inspectIPTablesChangeScope(ctx, dataDir, v, true)
		if err != nil {
			return fail("iptables 已确认规则的当前完整状态无法核对")
		}
		if current.States[material.Family] != "missing" {
			continue
		}
		var next *iptablesChangeStep
		for index := range repair.Steps {
			step := &repair.Steps[index]
			if step.Family != material.Family {
				continue
			}
			r, err := loadIPTablesReceipt(dataDir, step.ID)
			if os.IsNotExist(err) {
				next = step
				break
			}
			if err != nil || !iptablesRestoreRecordMatches(r, r.IPTablesRestore) || !iptablesRestoreMatchesRepair(r.IPTablesRestore, repair) || r.IPTablesRestore.Phase != "ended" {
				return fail("iptables 原修复调用回执无法核对")
			}
			if r.IPTablesRestore.Outcome != "unknown" {
				return fail("iptables 原修复调用已有明确结果，禁止重复提交")
			}
		}
		if next == nil {
			return fail("iptables 原修复调用许可已耗尽，请本机核对")
		}
		_, submitErr := runIPTablesRestore(ctx, dataDir, iptablesRestoreRequest{ID: next.ID, OperationID: v.Operation.ID, Target: "repair"})
		if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
			return fail("iptables 原修复进程尚未结束")
		}
		after, err := inspectIPTablesChangeScope(ctx, dataDir, v, true)
		if err != nil || after.States[material.Family] != "candidate" {
			if submitErr != nil {
				return fail("iptables 原修复未核对完成")
			}
			return fail("iptables 修复后完整代际无法核对")
		}
	}
	if err = finishIPTablesRepair(ctx, dataDir, v, repair); err != nil {
		if stored, readErr := loadIPTablesRepair(dataDir); readErr == nil && stored != nil && stored.Status.ID == repair.Status.ID && iptablesRepairTerminal(stored) {
			return err
		}
		return fail("iptables 最终修复规则或回执无法核对")
	}
	return nil
}

func finishIPTablesRepair(ctx context.Context, dataDir string, v *iptablesChangeCheckpoint, repair *iptablesRepairCheckpoint) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer unlock()
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return err
	}
	defer guard.Close()
	current, err := inspectIPTablesChange(ctx, dataDir, v)
	if err != nil || iptablesRestorePending(dataDir) {
		return errors.New("iptables 最终修复规则或回执无法核对")
	}
	for _, generation := range v.Transition.Program.Families {
		if current.States[generation.Family] != "candidate" {
			return errors.New("iptables 已确认地址族仍缺少完整代际")
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	repair.Status.State, repair.Status.Error, repair.Status.UpdatedAt = "succeeded", "", time.Now().Unix()
	return saveIPTablesRepair(dataDir, repair)
}

func reconcileIPTablesConfirmed(ctx context.Context, dataDir string) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	v, err := loadIPTablesChange(dataDir)
	if err != nil {
		return err
	}
	return reconcileIPTablesConfirmedLocked(ctx, dataDir, v)
}
