package agent

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"nginxpanel/internal/secure"
)

func ufwRepairChild(source *ufwChangeCheckpoint, v *ufwRepairCheckpoint, family ufwRepairFamily, id string) (*ufwRestoreReceipt, []byte, error) {
	if !slices.Contains(family.CallIDs, id) {
		return nil, nil, errors.New("UFW 修复调用不属于原预分配许可")
	}
	program, err := ufwPolicyProgram(&v.Policy, v.Owner)
	if err != nil {
		return nil, nil, err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return nil, nil, err
	}
	_, payload, err := ufwRepairProjection(family.Raw, family.Family, family.Before, owned)
	if err != nil || len(payload) == 0 {
		return nil, nil, errors.Join(err, errors.New("UFW 修复调用没有固定的缺失规则"))
	}
	role := "iptables-restore"
	if family.Family == "ipv6" {
		role = "ip6tables-restore"
	}
	python, pythonErr := source.Transition.Tools.tool("python")
	restore, restoreErr := source.Transition.Tools.tool(role)
	blocker, blockerErr := source.Transition.Tools.tool("false")
	if err = errors.Join(pythonErr, restoreErr, blockerErr); err != nil {
		return nil, nil, err
	}
	r := &ufwRestoreReceipt{Schema: 2, ID: id, OperationID: v.Status.ID, Owner: v.Owner, MachineHash: source.Transition.MachineHash, RegistrationOperationID: source.Transition.RegistrationOperationID, BatchHash: v.Status.IntentHash, ProgramHash: v.Policy.ProgramHash, ToolchainHash: v.ToolchainHash, Target: "repair", Family: family.Family, InputHash: secure.Hash(payload), InputBytes: len(payload), Python: python, Restore: restore, Blocker: blocker, GuardHash: secure.Hash([]byte(ufwRestoreGate)), Phase: "prepared", ExitCode: -1, UpdatedAt: time.Now().Unix()}
	r.RequestHash = ufwRestoreRequestHash(*r)
	if !validUFWRestoreReceipt(r) {
		return nil, nil, errors.New("UFW 修复子进程许可无效")
	}
	return r, payload, nil
}

// An ended unknown/not-started attempt may consume a different preallocated
// ID, after a fresh complete before-image proof. A known exit that left the
// before-image is not retried. The same child ID is never executed twice.
func nextUFWRepairCall(dataDir string, source *ufwChangeCheckpoint, v *ufwRepairCheckpoint, family ufwRepairFamily) (string, error) {
	for _, id := range family.CallIDs {
		expected, _, err := ufwRepairChild(source, v, family, id)
		if err != nil {
			return "", err
		}
		old, err := loadUFWReceipt(dataDir, id)
		if os.IsNotExist(err) {
			return id, nil
		}
		if err != nil || !ufwRestoreRecordMatches(old, old.UFWRestore) || old.RequestHash != expected.RequestHash || old.UFWRestore.Phase != "ended" {
			return "", errors.New("UFW 原修复调用尚未完成或独立回执不匹配")
		}
		if old.UFWRestore.Outcome == "exit" {
			return "", errors.New("UFW 原修复进程已返回但缺失规则未恢复，须检查原失败，不自动重复提交")
		}
	}
	return "", errors.New("UFW 原修复的三次预分配许可已用尽，须本机检查")
}

// Every family must still be its frozen before/after image. A different current
// configuration can retire an old intent only through a new full observation;
// it cannot grant the old process permission to use stale positions or packets.
func ufwRepairFrozen(v *ufwRepairCheckpoint, observed ufwConfirmedObservation) (bool, []int, error) {
	if observed.Configuration.Hash != v.ConfigurationHash || len(observed.Families) != len(v.Families) {
		return false, nil, nil
	}
	program, err := ufwPolicyProgram(&v.Policy, v.Owner)
	if err != nil {
		return false, nil, err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return false, nil, err
	}
	missing := []int{}
	for index, family := range v.Families {
		current := observed.Families[index]
		after, payload, err := ufwRepairProjection(family.Raw, family.Family, family.Before, owned)
		if err != nil {
			return false, nil, err
		}
		if current.Family != family.Family {
			return false, nil, errors.New("UFW 修复地址族顺序变化")
		}
		if sameUFWReloadImage(current.Before, after) {
			continue
		}
		if !sameUFWReloadImage(current.Before, family.Before) || len(payload) == 0 {
			return false, nil, nil
		}
		missing = append(missing, index)
	}
	return true, missing, nil
}

func runUFWRepairFamily(ctx context.Context, dataDir string, v *ufwRepairCheckpoint, family ufwRepairFamily, id string) (*ufwRestoreReceipt, error) {
	source, err := checkUFWRepairAnchor(dataDir, v)
	if err != nil {
		return nil, err
	}
	r, payload, err := ufwRepairChild(source, v, family, id)
	if err != nil {
		return nil, err
	}
	err = withUFWConfirmedObservation(ctx, dataDir, source, true, func(observed ufwConfirmedObservation, manager *os.File) error {
		current, err := loadUFWRepair(dataDir)
		if err != nil || current == nil || ufwRepairHash(current) != ufwRepairHash(v) || ufwRepairTerminal(current) {
			return errors.New("UFW 原修复意图已变化或结束")
		}
		parent, err := loadUFWReceipt(dataDir, v.Status.ID)
		if err != nil || !ufwRepairReceiptMatches(parent, &v.Status) || parent.CandidateHash != ufwRepairHash(v) {
			return errors.New("UFW 原修复父回执尚未完整发布")
		}
		if old, err := loadUFWReceipt(dataDir, id); err == nil {
			if !ufwRestoreRecordMatches(old, old.UFWRestore) || old.RequestHash != r.RequestHash {
				return errors.New("UFW 修复调用 ID 与原回执冲突")
			}
			r = old.UFWRestore
			return ufwRestoreResult(r)
		} else if !os.IsNotExist(err) {
			return err
		}
		previous, err := loadUFWRestore(dataDir)
		if err != nil || previous != nil && previous.OperationID != v.Status.ID && ufwRestoreParentPending(dataDir, previous) {
			return errors.New("UFW 其他原业务尚未完成核对，禁止修复")
		}
		frozen, missing, err := ufwRepairFrozen(v, observed)
		selected := false
		for _, index := range missing {
			selected = selected || v.Families[index].Family == family.Family
		}
		if err != nil || !frozen || !selected {
			return errors.New("UFW 修复前置内核或配置已变化，禁止使用原插入位置")
		}
		next, err := nextUFWRepairCall(dataDir, source, v, family)
		if err != nil || next != id {
			return errors.Join(err, errors.New("UFW 修复未选中原下一次许可"))
		}
		if err = saveUFWRestore(dataDir, r); err != nil {
			return err
		}
		r, err = executeUFWRestore(ctx, dataDir, r, payload, manager)
		return err
	})
	return r, err
}

// Caller holds the host-wide business lock. Repair never reopens or mutates the
// succeeded policy operation, and never compensates a confirmed policy away.
func recoverUFWRepairLocked(ctx context.Context, dataDir string) (resultErr error) {
	v, err := loadUFWRepair(dataDir)
	if err != nil || v == nil {
		return err
	}
	if ufwRepairTerminal(v) {
		if ufwRepairPending(dataDir) {
			return saveUFWRepair(dataDir, v)
		}
		return nil
	}
	source, err := checkUFWRepairAnchor(dataDir, v)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr == nil {
			return
		}
		// Publication can fail after the terminal checkpoint reached disk.
		// Read the durable direction before recording a failure.
		current, err := loadUFWRepair(dataDir)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
		} else if current == nil || current.Status.ID != v.Status.ID {
			resultErr = errors.Join(resultErr, errors.New("UFW 原修复检查点丢失或身份已变化"))
		} else if !ufwRepairTerminal(current) {
			current.Status.State, current.Status.Error = "recovery_required", "原确认规则修复尚未完成；请核对本机配置、运行状态及独立回执"
			resultErr = errors.Join(resultErr, saveUFWRepair(dataDir, current))
		}
	}()
	// End the original exact PID before any observation or new grant. This
	// also repairs a child checkpoint/journal publication gap without replay.
	if err = recoverUFWRestore(ctx, dataDir); err != nil {
		return err
	}
	if err = saveUFWRepair(dataDir, v); err != nil {
		return err
	}
	for step := 0; step <= 3*len(v.Families); step++ {
		var family ufwRepairFamily
		var callID string
		finished := false
		err = withUFWConfirmedObservation(ctx, dataDir, source, false, func(observed ufwConfirmedObservation, _ *os.File) error {
			frozen, missing, err := ufwRepairFrozen(v, observed)
			if err != nil {
				return err
			}
			if !frozen {
				// The fresh projection has proved every current foreign rule
				// and native owned block. Retain the old audit as superseded;
				// the ordinary reconciler may then create a fresh repair.
				v.Status.State, v.Status.Error, v.Status.ResolutionHash = "superseded", "当前配置或运行基线已变化；旧修复未重放，已按当前原生规则重新核对", observed.Hash
				finished = true
				return saveUFWRepair(dataDir, v)
			}
			if len(missing) == 0 {
				v.Status.State, v.Status.Error, v.Status.ResolutionHash = "succeeded", "", observed.Hash
				finished = true
				return saveUFWRepair(dataDir, v)
			}
			family = v.Families[missing[0]]
			callID, err = nextUFWRepairCall(dataDir, source, v, family)
			return err
		})
		if err != nil || finished {
			return err
		}
		r, runErr := runUFWRepairFamily(ctx, dataDir, v, family, callID)
		if runErr != nil && (r == nil || r.Phase != "ended" || ufwRestoreProcessPending(dataDir)) {
			return runErr
		}
		// An ended child, including an unknown result, is resolved by the
		// next complete observation. An exit code is never a kernel proof.
	}
	return errors.New("UFW 修复预分配许可耗尽，原意图保留")
}
