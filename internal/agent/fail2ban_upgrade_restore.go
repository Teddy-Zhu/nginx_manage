package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

func RestoreFail2banUpgrade(ctx context.Context, in Fail2banUpgradeRestoreOptions) (Fail2banUpgradeRestore, error) {
	if !validID(in.ActivationID) {
		return Fail2banUpgradeRestore{}, errors.New("升级恢复须指定原候选启动 UUID")
	}
	return operateFail2banUpgradeRestore(ctx, in, "restore")
}

func ResumeFail2banUpgradeRestore(ctx context.Context, data, scope, id string) (Fail2banUpgradeRestore, error) {
	return operateFail2banUpgradeRestore(ctx, Fail2banUpgradeRestoreOptions{DataDir: data, Scope: scope, OperationID: id}, "resume")
}

func CancelFail2banUpgradeRestore(ctx context.Context, data, scope, id string) (Fail2banUpgradeRestore, error) {
	return operateFail2banUpgradeRestore(ctx, Fail2banUpgradeRestoreOptions{DataDir: data, Scope: scope, OperationID: id}, "cancel")
}

func beginFail2banUpgradeRestore(ctx context.Context, in Fail2banUpgradeRestoreOptions, j *Journal) (fail2banUpgradeRestoreIntent, error) {
	var i fail2banUpgradeRestoreIntent
	if err := fail2banUpgradeIdleFor(j, in.OperationID); err != nil {
		return i, err
	}
	if _, err := j.Get(in.OperationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("升级恢复 UUID 已有审计或无法核对"), err)
	}
	a, s, f, err := readFail2banUpgradeRestoreSource(in.DataDir, in.ActivationID)
	if err != nil {
		return i, err
	}
	if err = a.engine(ctx, false); err != nil {
		return i, err
	}
	before, err := readFail2banStateBasis(ctx, in.DataDir)
	if err != nil {
		return i, err
	}
	directory, files, err := observeFail2banStateDirectory(ctx, filepath.Join(s.After.work(), "state"))
	if err != nil {
		return i, err
	}
	b := fail2banUpgradeRestoreCandidateBasis(s)
	_, blockers, err := readFail2banUpgradeHostCheckpoint(in.DataDir, b)
	if err != nil {
		return i, err
	}
	if len(blockers) != 0 {
		return i, errors.New("升级恢复前须完成当前宿主机动作事务及其原审计")
	}
	recovery, err := readFail2banUpgradeHostRecovery(in.DataDir, b)
	if err != nil {
		return i, err
	}
	ids := fail2banUpgradeUndoIDs{Managed: secure.ID()}
	if s.Prepared.Material.Nginx != nil {
		ids.Nginx = secure.ID()
	}
	if s.Prepared.Material.Sources != nil {
		ids.Sources = secure.ID()
	}
	if s.Prepared.Material.Sync != nil {
		ids.Sync = secure.ID()
	}
	i = fail2banUpgradeRestoreIntent{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, ActivationSHA256: a.hash(), ActivationReceiptSHA256: fail2banUpgradeGrantHash("activation-receipt", f.Receipt), Before: before, Recovery: recovery}
	i.Undo, err = fail2banUpgradeRestoreUndo(s, recovery, ids, i.CreatedAt)
	if err != nil {
		return i, err
	}
	basis := s.Manifest.Basis
	basis.Managed, basis.Service, basis.Invocation = i.Undo.Managed, before.Service, before.Invocation
	basis.Configuration, err = fail2banJailConfig(&i.Undo.Managed, basis.Bundle)
	if err != nil {
		return i, err
	}
	basis.Configuration["service.unit"] = i.Undo.Managed.unit()
	target := fail2banStateRestoreTarget{Snapshot: s.Snapshot, Basis: basis, Before: files, Directory: directory}
	i.State = fail2banStateRestoreIntent{Schema: 1, ID: in.OperationID, DataDir: in.DataDir, CreatedAt: i.CreatedAt, Target: target.hash(), Input: target, After: s.Manifest.Files}
	if root := b.HostRegistration; root != nil && root.State == "registered" {
		program := i.program(s)
		i.Kernel, err = program.snapshot(ctx)
		if err != nil {
			return i, err
		}
	}
	p := s.Prepared
	p.Basis = b
	i.Nginx, err = readFail2banUpgradeQuiesceNginx(in.DataDir, p)
	if err != nil {
		return i, err
	}
	if err = i.validate(in.DataDir, in.OperationID, a, s, f); err != nil {
		return i, err
	}
	if err = i.snapshot(ctx, s); err != nil {
		return i, err
	}
	if err = i.observe(ctx, s); err != nil {
		return i, err
	}
	if err = i.unexecuted(); err != nil {
		return i, err
	}
	if _, err = os.Lstat(i.stateRestore().dir()); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("升级恢复的状态交换路径已被使用或无法确认"), err)
	}
	if err = i.reserve(j); err != nil {
		return i, err
	}
	if err = reserveFail2banUpgradeRestore(i); err != nil {
		return i, err
	}
	return i, nil
}

func (i fail2banUpgradeRestoreIntent) snapshot(ctx context.Context, s fail2banUpgradeSwitch) error {
	r, m, err := readFail2banStateArchive(ctx, i.Request.DataDir, s.Request.SnapshotID, filepath.Join(fail2banStateDir(i.Request.DataDir), s.Request.SnapshotID), nil)
	if err != nil {
		return err
	}
	if r != s.Snapshot || !fail2banUpgradeOneOf(m, s.Manifest) {
		return errors.New("升级恢复原加密快照或完整清单变化")
	}
	return verifyFail2banStatePrepared(ctx, filepath.Join(fail2banStateDir(i.Request.DataDir), s.Request.SnapshotID, "prepared"), r, m)
}

func (i fail2banUpgradeRestoreIntent) reserve(j *Journal) error {
	records, err := j.List()
	if err != nil {
		return err
	}
	reserve := 1
	if i.Undo.Sync != nil {
		reserve++
	}
	for _, r := range records {
		if r.OperationID == i.Request.OperationID || i.Undo.Sync != nil && r.OperationID == i.Undo.Sync.ID {
			reserve--
		}
	}
	if len(records)+reserve > 2048 {
		return errors.New("升级恢复须保留父操作及新持续会话的审计容量")
	}
	if err = checkFail2banUpgradeGrantEvents(i.Request.DataDir, i.Undo.Nginx, i.Undo.Sources, i.Undo.Sync, false); err != nil {
		return err
	}
	return i.reserveState()
}

func ensureFail2banUpgradeRestoreJournal(ctx context.Context, i fail2banUpgradeRestoreIntent, s fail2banUpgradeSwitch, f fail2banUpgradeRestoreFacts, j *Journal, cancel bool) error {
	audit, err := j.Get(i.Request.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && f.Receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return nil
	}
	active, _, e := pendingFail2banUpgradeRestore(i.Request.DataDir)
	if e != nil {
		return e
	}
	if active == nil || active.hash() != i.hash() {
		if active != nil {
			return ErrBusy
		}
		if err == nil || f.Execution || f.State != nil || f.Receipt != nil {
			return errors.New("升级恢复隔离变化，不重新生成执行授权")
		}
		if e = fail2banUpgradeIdleFor(j, i.Request.OperationID); e != nil {
			return e
		}
		if !cancel {
			if e = i.observe(ctx, s); e != nil {
				return e
			}
		}
		if e = rootJSONWrite(filepath.Join(fail2banUpgradeRestores(i.Request.DataDir), "current.json"), i.marker(), 4096); e != nil {
			return e
		}
	}
	if os.IsNotExist(err) {
		if f.Execution || f.State != nil || f.Receipt != nil {
			return errors.New("升级恢复已有执行材料但原审计丢失，不重建授权")
		}
		if !cancel {
			if e = i.observe(ctx, s); e != nil {
				return e
			}
		}
		return j.Put(i.record(nil))
	}
	if !pendingFail2banUpgradeRestoreRecord(audit, i.record(nil)) {
		return errors.New("升级恢复原审计与意图冲突")
	}
	return nil
}

func acknowledgeFail2banUpgradeRestore(i fail2banUpgradeRestoreIntent, f fail2banUpgradeRestoreFacts, j *Journal) error {
	if f.Receipt == nil {
		return errors.New("升级恢复尚无完成回执")
	}
	audit, err := j.Get(i.Request.OperationID)
	if err != nil {
		return err
	}
	if sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return nil
	}
	if !pendingFail2banUpgradeRestoreRecord(audit, i.record(nil)) {
		return errors.New("升级恢复不能覆盖变化的原始完成审计")
	}
	return j.Put(i.record(f.Receipt))
}

func operateFail2banUpgradeRestore(parent context.Context, in Fail2banUpgradeRestoreOptions, action string) (out Fail2banUpgradeRestore, resultErr error) {
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	_, statErr := os.Lstat(filepath.Join(fail2banUpgradeRestores(in.DataDir), in.OperationID))
	if os.IsNotExist(statErr) && action == "restore" {
		if _, err = beginFail2banUpgradeRestore(ctx, in, j); err != nil {
			return out, err
		}
	} else if statErr != nil {
		return out, statErr
	}
	i, s, err := readFail2banUpgradeRestore(in.DataDir, in.OperationID)
	if err != nil {
		return out, err
	}
	if action == "restore" && i.Request != in {
		return out, errors.New("相同升级恢复 UUID 已绑定其他失败候选")
	}
	f, err := i.facts()
	if err != nil {
		return out, err
	}
	out = i.result(f, false)
	if err = ensureFail2banUpgradeRestoreJournal(ctx, i, s, f, j, action == "cancel"); err != nil {
		return out, err
	}
	defer func() {
		if resultErr == nil {
			return
		}
		r, e := j.Get(in.OperationID)
		if e != nil || !pendingFail2banUpgradeRestoreRecord(r, i.record(nil)) {
			return
		}
		message := []rune(resultErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		r.State, r.Error = "recovery_required", string(message)
		resultErr = errors.Join(resultErr, j.Put(r))
		out.State, out.Reason = r.State, r.Error
	}()
	if f.Receipt != nil {
		if err = acknowledgeFail2banUpgradeRestore(i, f, j); err != nil {
			return out, err
		}
		out = i.result(f, true)
		if action == "cancel" && f.Receipt.Outcome != "cancelled" {
			return out, errors.New("升级恢复已完成，不能使用旧取消授权覆盖后续状态")
		}
		return out, nil
	}
	if err = fail2banUpgradeIdleFor(j, in.OperationID); err != nil {
		return out, err
	}
	if action == "cancel" {
		if f.Execution {
			return out, errors.New("升级恢复已进入执行，只能沿原 UUID 续办")
		}
		receipt := fail2banUpgradeRestoreReceipt{fail2banUpgradeActivationMarker: i.marker(), Outcome: "cancelled", CompletedAt: time.Now().Unix()}
		if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), receipt); err != nil {
			return out, err
		}
	} else {
		if !f.Execution && time.Now().Unix() > i.CreatedAt+int64(fail2banUpgradeActivationWindow/time.Second) {
			return out, errors.New("升级恢复首次执行许可已过期，可取消后重新申请")
		}
		if err = i.execute(ctx, s, j, f); err != nil {
			return out, err
		}
	}
	f, err = i.facts()
	if err != nil {
		return out, err
	}
	if err = acknowledgeFail2banUpgradeRestore(i, f, j); err != nil {
		return out, err
	}
	return i.result(f, true), nil
}

func (i fail2banUpgradeRestoreIntent) execute(ctx context.Context, s fail2banUpgradeSwitch, j *Journal, f fail2banUpgradeRestoreFacts) error {
	if err := i.observe(ctx, s); err != nil {
		return err
	}
	if err := i.snapshot(ctx, s); err != nil {
		return err
	}
	if err := fail2banUpgradeSwitchQuota(fail2banUpgradeRestores(i.Request.DataDir), false); err != nil {
		return err
	}
	if err := i.reserve(j); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), i.marker()); err != nil {
		return err
	}
	u := i.Undo
	if err := replaceFail2banUpgradeUnit(i.Request.OperationID, s.After.unit(), u.Managed.unit(), u.Managed); err != nil {
		return err
	}
	current, err := loadFail2banManaged(i.Request.DataDir)
	if err != nil {
		return err
	}
	if current.EventID != u.Managed.EventID {
		if err = publishFail2banManagedRecord(i.Request.DataDir, u.Managed.PreviousEvent, u.Managed); err != nil {
			return err
		}
	}
	if err = i.applyGrants(j); err != nil {
		return err
	}
	if err = fail2banManagedSystemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err = verifyFail2banManaged(ctx, &u.Managed, true); err != nil {
		return err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return err
	}
	if err = i.observe(ctx, s); err != nil {
		return err
	}
	if err = i.selected(ctx); err != nil {
		return err
	}
	state := i.stateRestore()
	if err = fail2banStatePrivateDir(state.dir(), true); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(state.dir())); err != nil {
		return err
	}
	if f.State == nil {
		if _, err = advanceFail2banStateRestore(ctx, state, false); err != nil {
			return err
		}
	}
	if err = i.observe(ctx, s); err != nil {
		return err
	}
	if err = i.selected(ctx); err != nil {
		return err
	}
	proof, err := state.receipt()
	if err != nil {
		return err
	}
	if proof == nil || proof.Outcome != "restored" {
		return errors.New("升级恢复缺少原数据库交换完成证明")
	}
	receipt := fail2banUpgradeRestoreReceipt{fail2banUpgradeActivationMarker: i.marker(), Outcome: "restored", StateReceiptSHA256: fail2banUpgradeGrantHash("upgrade-restore-state", proof), CompletedAt: time.Now().Unix()}
	return writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), receipt)
}
