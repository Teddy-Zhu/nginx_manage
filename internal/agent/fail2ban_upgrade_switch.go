package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

// The stopped branch never starts an engine or opens its SQLite database.
// Running upgrades must separately coordinate stop, recovery and action proof.
func SwitchFail2banUpgrade(ctx context.Context, in Fail2banUpgradeSwitchOptions) (Fail2banUpgradeSwitchStatus, error) {
	if !validID(in.PreparationID) || !validID(in.SnapshotID) || !fail2banDigest.MatchString(in.Target) {
		return Fail2banUpgradeSwitchStatus{}, errors.New("停止实例切换须提供准备 UUID、原状态快照 UUID 和准备材料摘要")
	}
	return operateFail2banUpgradeSwitch(ctx, in, "switch")
}

func ResumeFail2banUpgradeSwitch(ctx context.Context, data, scope, id string) (Fail2banUpgradeSwitchStatus, error) {
	return operateFail2banUpgradeSwitch(ctx, Fail2banUpgradeSwitchOptions{DataDir: data, Scope: scope, OperationID: id}, "resume")
}

func RevertFail2banUpgradeSwitch(ctx context.Context, data, scope, id string) (Fail2banUpgradeSwitchStatus, error) {
	return operateFail2banUpgradeSwitch(ctx, Fail2banUpgradeSwitchOptions{DataDir: data, Scope: scope, OperationID: id}, "revert")
}

func fail2banUpgradeSwitchAdmission(data, allowed string) error {
	records, err := fail2banStateRestoreRawRecords(data)
	if err != nil {
		return err
	}
	pending, err := fail2banStateRestoreRecords(data, records, "")
	if err != nil {
		return err
	}
	if pending != "" {
		return ErrBusy
	}
	pending, err = fail2banUpgradeSwitchRecords(data, records, allowed)
	if err != nil {
		return err
	}
	if pending != "" && pending != allowed {
		return ErrBusy
	}
	for _, r := range records {
		if pendingNginxRecord(r) && r.OperationID != allowed || r.Kind == "maintenance.lock" && r.State != "succeeded" {
			return ErrBusy
		}
	}
	if err = fail2banHostBootRecoveryIdle(data); err != nil {
		return err
	}
	retirement, err := loadFail2banHostRetirement(data)
	if err != nil {
		return err
	}
	if retirement != nil {
		r, err := retirement.record(data)
		if err != nil {
			return err
		}
		if r.State != "succeeded" {
			return ErrBusy
		}
	}
	return nil
}

func (i fail2banUpgradeSwitch) original(ctx context.Context) error {
	p, receipt, err := readFail2banUpgradePreparation(i.Request.DataDir, i.Request.PreparationID, i.Prepared.dir())
	if err != nil {
		return err
	}
	if p.hash() != i.Prepared.hash() {
		return ErrExternalChange
	}
	status, err := fail2banUpgradePreparationStatus(ctx, p, receipt)
	if err != nil {
		return err
	}
	if status.State != "prepared" || status.ScopeCurrent == nil || !*status.ScopeCurrent || status.CheckpointCurrent == nil || !*status.CheckpointCurrent {
		return errors.New("原升级准备尚未确认，或原范围/检查点已经变化")
	}
	if err = verifyFail2banManaged(ctx, &p.Basis.Current, true); err != nil {
		return err
	}
	if err = verifyFail2banManaged(ctx, &p.Basis.Candidate, false); err != nil {
		return err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return err
	}
	return i.observe(ctx, nil)
}

func (i fail2banUpgradeSwitch) snapshot(ctx context.Context) error {
	dir := filepath.Join(fail2banStateDir(i.Request.DataDir), i.Request.SnapshotID)
	r, m, err := readFail2banStateArchive(ctx, i.Request.DataDir, i.Request.SnapshotID, dir, nil)
	if err != nil {
		return err
	}
	if !fail2banUpgradeOneOf(r, i.Snapshot) || !fail2banUpgradeOneOf(m, i.Manifest) {
		return errors.New("原升级快照及清单已变化")
	}
	return verifyFail2banStatePrepared(ctx, filepath.Join(dir, "prepared"), r, m)
}

func beginFail2banUpgradeSwitch(ctx context.Context, in Fail2banUpgradeSwitchOptions, j *Journal) (fail2banUpgradeSwitch, error) {
	var i fail2banUpgradeSwitch
	if err := fail2banUpgradeIdle(j); err != nil {
		return i, err
	}
	if _, err := j.Get(in.OperationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("切换 UUID 已被其他审计占用或无法核对"), err)
	}
	p, _, err := readFail2banUpgradePreparation(in.DataDir, in.PreparationID, filepath.Join(fail2banUpgradePreparations(in.DataDir), in.PreparationID))
	if err != nil {
		return i, err
	}
	if p.hash() != in.Target {
		return i, errors.New("切换须使用准备材料 intent_sha256，不能使用原候选预览摘要")
	}
	original, err := fail2banJailConfig(&p.Basis.Current, p.Basis.Bundle)
	if err != nil {
		return i, err
	}
	candidate, err := fail2banJailConfig(&p.Basis.Candidate, p.Material.Bundle)
	if err != nil {
		return i, err
	}
	if !fail2banUpgradeOneOf(original, candidate) {
		return i, errors.New("此停止实例切换不接受同时改变物理 jail 配置")
	}
	dir := filepath.Join(fail2banStateDir(in.DataDir), in.SnapshotID)
	snapshot, manifest, err := readFail2banStateArchive(ctx, in.DataDir, in.SnapshotID, dir, nil)
	if err != nil {
		return i, err
	}
	if err = verifyFail2banStatePrepared(ctx, filepath.Join(dir, "prepared"), snapshot, manifest); err != nil {
		return i, err
	}
	directory, _, err := observeFail2banStateDirectory(ctx, filepath.Join(p.Basis.Current.work(), "state"))
	if err != nil {
		return i, err
	}
	i = fail2banUpgradeSwitch{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, Prepared: p, Snapshot: snapshot, Manifest: manifest, Directory: directory}
	i.After = fail2banUpgradeManagedEvent(p.Basis.Candidate, secure.ID(), p.Basis.Current.EventID, p.Material.IDs.Jails, "upgrade", i.CreatedAt)
	i.After.Start, i.After.Enable = p.Basis.Current.Start, p.Basis.Current.Enable
	if root := p.Basis.HostRegistration; root != nil && root.State == "registered" {
		program, _ := fail2banUpgradeOriginalHostProgram(p)
		i.Kernel, err = program.snapshot(ctx)
		if err != nil {
			return i, err
		}
	}
	if err = i.validate(in.DataDir, in.OperationID); err != nil {
		return i, err
	}
	if err = i.original(ctx); err != nil {
		return i, err
	}
	if err = i.grantEvents(nil); err != nil {
		return i, err
	}
	if err = reserveFail2banUpgradeSwitch(i); err != nil {
		return i, err
	}
	return i, nil
}

func operateFail2banUpgradeSwitch(parent context.Context, in Fail2banUpgradeSwitchOptions, action string) (out Fail2banUpgradeSwitchStatus, resultErr error) {
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	i, err := readFail2banUpgradeSwitch(in.DataDir, in.OperationID)
	if os.IsNotExist(err) && action == "switch" {
		i, err = beginFail2banUpgradeSwitch(ctx, in, j)
	}
	if err != nil {
		return out, err
	}
	if action == "switch" && i.Request != in {
		return out, errors.New("相同切换 UUID 已绑定其他准备、快照或摘要")
	}
	u, err := i.undo()
	if err != nil {
		return out, err
	}
	receipt, err := i.receipt()
	if err != nil {
		return out, err
	}
	if err = ensureFail2banUpgradeSwitchJournal(ctx, i, j, u, receipt); err != nil {
		return out, err
	}
	if receipt != nil {
		actual, err := j.Get(in.OperationID)
		if err != nil {
			return out, err
		}
		if action == "revert" && receipt.Outcome == "selected" {
			out = i.status(actual, receipt)
			if !sameFail2banUpgradePreparationRecord(actual, i.record(receipt, u)) {
				out.State, out.Stage = "recovery_required", "completion_unacknowledged"
			}
			return out, errors.New("停止实例切换已完成，不能用旧撤回授权覆盖后续启动或状态")
		}
		if !sameFail2banUpgradePreparationRecord(actual, i.record(receipt, u)) {
			if err = j.Put(i.record(receipt, u)); err != nil {
				return out, err
			}
		}
		return i.status(i.record(receipt, u), receipt), nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		actual, err := j.Get(i.Request.OperationID)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		if !pendingFail2banUpgradeSwitchRecord(actual, i.record(nil, u)) {
			if !pendingFail2banUpgradeSwitchRecord(actual, i.record(nil, nil)) {
				return
			}
			actual = i.record(nil, u)
		}
		message := []rune(resultErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		actual.State, actual.Error = "recovery_required", string(message)
		resultErr = errors.Join(resultErr, j.Put(actual))
		out = i.status(actual, nil)
	}()
	if err = fail2banUpgradeSwitchAdmission(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	if err = fail2banUpgradeSwitchQuota(fail2banUpgradeSwitches(in.DataDir), false); err != nil {
		return out, err
	}
	if err = i.snapshot(ctx); err != nil {
		return out, err
	}
	if action == "revert" && u == nil {
		if err = i.observe(ctx, nil); err != nil {
			return out, err
		}
		undo, err := i.newUndo()
		if err != nil {
			return out, err
		}
		if err = i.grantEvents(&undo); err != nil {
			return out, err
		}
		if err = writeFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "undo.json"), undo); err != nil {
			return out, err
		}
		u = &undo
	}
	// An immutable undo intent makes every subsequent resume compensating.
	if err = j.Put(i.record(nil, u)); err != nil {
		return out, err
	}
	if err = i.execute(ctx, u); err != nil {
		return out, err
	}
	receipt, err = i.receipt()
	if err != nil {
		return out, err
	}
	if receipt == nil {
		return out, errors.New("切换执行返回但缺少完成证明")
	}
	return i.status(i.record(receipt, u), receipt), nil
}
