package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func fail2banStateRestoreAdmission(data, allowed string) error {
	if err := fail2banUpgradeQuiesceIdle(data, ""); err != nil {
		return err
	}
	if err := fail2banUpgradeActivationIdle(data, ""); err != nil {
		return err
	}
	if err := fail2banHostRetirementIdle(data); err != nil {
		return err
	}
	records, err := fail2banStateRestoreRawRecords(data)
	if err != nil {
		return err
	}
	pending, err := fail2banStateRestoreRecords(data, records, allowed)
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
	return nil
}

func planFail2banStateRestore(ctx context.Context, data, snapshot string) (fail2banStateRestoreTarget, fail2banStateManifest, error) {
	var t fail2banStateRestoreTarget
	var m fail2banStateManifest
	if !validID(snapshot) {
		return t, m, errors.New("须提供原本机状态快照 UUID")
	}
	if err := fail2banStateRestoreAdmission(data, ""); err != nil {
		return t, m, err
	}
	r, m, err := readFail2banStateArchive(ctx, data, snapshot, filepath.Join(fail2banStateDir(data), snapshot), nil)
	if err != nil {
		return t, m, err
	}
	if err = verifyFail2banStatePrepared(ctx, filepath.Join(fail2banStateDir(data), snapshot, "prepared"), r, m); err != nil {
		return t, m, errors.Join(errors.New("须先完整准备原快照的恢复暂存"), err)
	}
	basis, err := readFail2banStateBasis(ctx, data)
	if err != nil {
		return t, m, err
	}
	if !compatibleFail2banStateSnapshot(basis, m.Basis) {
		return t, m, errors.New("须先恢复原签名代码、解释器、管理程序及完整 jail 配置，不能跨版本安装状态库")
	}
	directory, before, err := observeFail2banStateDirectory(ctx, filepath.Join(basis.Managed.work(), "state"))
	if err != nil {
		return t, m, err
	}
	observed := m
	observed.Basis, observed.Files = basis, before
	if err = observed.validate(data, snapshot); err != nil {
		return t, m, err
	}
	after, err := readFail2banStateBasis(ctx, data)
	x, _ := json.Marshal(basis)
	y, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(x, y) {
		return t, m, errors.Join(errors.New("Fail2ban 状态恢复预览期间实例或配置变化"), err)
	}
	t = fail2banStateRestoreTarget{Snapshot: r, Basis: basis, Before: before, Directory: directory}
	return t, m, ctx.Err()
}

func PlanFail2banStateRestore(parent context.Context, in Fail2banStateRestoreOptions) (Fail2banStateRestorePlan, error) {
	var out Fail2banStateRestorePlan
	unlock, err := fail2banStateSnapshotAccess(Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: in.SnapshotID})
	if err != nil {
		return out, err
	}
	defer unlock()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	access, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer access()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	t, m, err := planFail2banStateRestore(ctx, in.DataDir, in.SnapshotID)
	if err != nil {
		return out, err
	}
	return Fail2banStateRestorePlan{At: time.Now().Unix(), SnapshotID: in.SnapshotID, InstallationID: t.Basis.Managed.OperationID, Target: t.hash(), Component: t.Snapshot.Component, Before: t.Before, After: m.Files, Impacts: []string{"只替换已停止独立实例的完整状态目录；同一文件系统原子交换并保留原目录", "恢复未完成时禁止启动及冲突维护；中断后须沿原操作继续或撤回", "不修改代码、jail 配置、动作授权、模块开关或服务启停；实际封禁恢复须在后续授权启动后核对"}}, nil
}

func RestoreFail2banState(ctx context.Context, in Fail2banStateRestoreOptions) (Fail2banStateRestoreStatus, error) {
	if !validID(in.SnapshotID) || !fail2banDigest.MatchString(in.Target) {
		return Fail2banStateRestoreStatus{}, errors.New("状态恢复须提供原快照和精确预览摘要")
	}
	return operateFail2banStateRestore(ctx, in, false)
}

func RevertFail2banStateRestore(ctx context.Context, in Fail2banStateRestoreOptions) (Fail2banStateRestoreStatus, error) {
	return operateFail2banStateRestore(ctx, in, true)
}

func operateFail2banStateRestore(parent context.Context, in Fail2banStateRestoreOptions, revert bool) (out Fail2banStateRestoreStatus, resultErr error) {
	unlock, err := fail2banStateSnapshotAccess(Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: in.OperationID})
	if err != nil {
		return out, err
	}
	defer unlock()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	access, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer access()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	i, err := readFail2banStateRestore(in.DataDir, in.OperationID)
	if os.IsNotExist(err) && !revert {
		i, err = beginFail2banStateRestore(ctx, in, j)
	}
	if err != nil {
		return out, err
	}
	if !revert && (i.Target != in.Target || i.Input.Snapshot.OperationID != in.SnapshotID) {
		return out, errors.New("状态恢复 UUID 已绑定其他快照或预览，不覆盖原意图")
	}
	if err = ensureFail2banStateRestoreJournal(i, j); err != nil {
		return out, err
	}
	defer func() {
		if resultErr == nil {
			return
		}
		r, e := j.Get(i.ID)
		if e != nil || !samePendingFail2banStateRestoreRecord(r, i.record(nil)) {
			return
		}
		message := []rune(resultErr.Error())
		if len(message) > 256 {
			message = message[:256]
		}
		r.Error = string(message)
		if e = j.Put(r); e != nil {
			resultErr = errors.Join(resultErr, e)
		}
		out = i.status(r, nil)
	}()
	receipt, err := i.receipt()
	if err != nil {
		return out, err
	}
	if receipt != nil {
		if revert && receipt.Outcome == "restored" {
			return out, errors.New("原状态恢复已完成，不能用旧撤回授权覆盖后续状态")
		}
		if err = acknowledgeFail2banStateRestore(i, j, receipt); err != nil {
			return out, err
		}
		return i.status(i.record(receipt), receipt), nil
	}
	if err = fail2banStateRestoreAdmission(in.DataDir, i.ID); err != nil {
		return out, err
	}
	if revert {
		raw, e := fail2banStateJSON(i.marker())
		if e != nil {
			return out, e
		}
		if e = writeFail2banJailImmutable(filepath.Join(i.dir(), "revert.json"), raw, 4096); e != nil {
			return out, e
		}
	}
	reverting, err := i.reverting()
	if err != nil {
		return out, err
	}
	if reverting && !revert {
		return out, errors.New("原状态恢复已授权撤回，须使用撤回命令沿原 UUID 续办")
	}
	receipt, err = advanceFail2banStateRestore(ctx, i, reverting)
	if err != nil {
		return out, err
	}
	if err = acknowledgeFail2banStateRestore(i, j, receipt); err != nil {
		return out, err
	}
	return i.status(i.record(receipt), receipt), nil
}

func advanceFail2banStateRestore(ctx context.Context, i fail2banStateRestoreIntent, revert bool) (*fail2banStateRestoreReceipt, error) {
	basis, err := readFail2banStateBasis(ctx, i.DataDir)
	if err != nil || !sameFail2banStateRestoreControl(basis, i.Input.Basis) {
		return nil, errors.Join(errors.New("原安装事件、配置或停止状态已变化，保留恢复现场"), err)
	}
	ready, err := i.ready()
	if err != nil {
		return nil, err
	}
	if revert && ready == nil {
		identity, files, e := observeFail2banStateDirectory(ctx, filepath.Join(i.Input.Basis.Managed.work(), "state"))
		if e != nil || identity != i.Input.Directory {
			return nil, errors.Join(errors.New("交换前取消须核对未被替换的原状态目录"), e)
		}
		receipt := &fail2banStateRestoreReceipt{fail2banStateRestoreMarker: i.marker(), Outcome: "cancelled", CompletedAt: time.Now().Unix(), Directory: identity, FilesSHA256: fail2banStateFilesHash(files)}
		if e = writeFail2banStateRestoreReceipt(i, receipt); e != nil {
			return nil, e
		}
		return receipt, nil
	}
	if !revert {
		r, m, e := readFail2banStateArchive(ctx, i.DataDir, i.Input.Snapshot.OperationID, filepath.Join(fail2banStateDir(i.DataDir), i.Input.Snapshot.OperationID), nil)
		if e != nil || r != i.Input.Snapshot || fail2banStateFilesHash(m.Files) != fail2banStateFilesHash(i.After) || !compatibleFail2banStateSnapshot(basis, m.Basis) {
			return nil, errors.Join(errors.New("原状态快照或其匹配配置无法重新认证"), e)
		}
		if ready == nil {
			ready, err = i.stage(ctx, r, m)
			if err != nil {
				return nil, err
			}
		}
	}
	// The retained original must survive a crash, including an engine that
	// exited without flushing its final database/sidecar pages. Hash both
	// directories after flushing and before authorizing the exchange.
	state := filepath.Join(i.Input.Basis.Managed.work(), "state")
	directories := []string{state, filepath.Join(i.dir(), "exchange")}
	if revert {
		identity, e := fail2banStateDirectoryIdentity(state)
		if e != nil {
			return nil, e
		}
		if identity == i.Input.Directory {
			// No exchange back is needed when the original is already live.
			// Its full inventory is still checked below; unrelated scratch
			// damage cannot force replacement of that original directory.
			directories = []string{state}
		}
	}
	for _, dir := range directories {
		if err = syncFail2banRestoreDirectory(ctx, dir); err != nil {
			return nil, err
		}
	}
	swapped, err := i.observeForRestore(ctx, ready, revert)
	if err != nil {
		return nil, err
	}
	basis, err = readFail2banStateBasis(ctx, i.DataDir)
	if err != nil || !sameFail2banStateRestoreControl(basis, i.Input.Basis) {
		return nil, errors.Join(errors.New("交换前原安装或停止状态变化，保留恢复现场"), err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if swapped == revert {
		if err = unix.Renameat2(unix.AT_FDCWD, state, unix.AT_FDCWD, filepath.Join(i.dir(), "exchange"), unix.RENAME_EXCHANGE); err != nil {
			return nil, err
		}
	}
	if err = syncDir(filepath.Dir(state)); err != nil {
		return nil, err
	}
	if err = syncDir(i.dir()); err != nil {
		return nil, err
	}
	swapped, err = i.observeForRestore(ctx, ready, revert)
	if err != nil || swapped == revert {
		return nil, errors.Join(errors.New("Fail2ban 状态目录未匹配恢复结果"), err)
	}
	basis, err = readFail2banStateBasis(ctx, i.DataDir)
	if err != nil || !sameFail2banStateRestoreControl(basis, i.Input.Basis) {
		return nil, errors.Join(errors.New("恢复后原安装或停止状态未确认"), err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	receipt := &fail2banStateRestoreReceipt{fail2banStateRestoreMarker: i.marker(), CompletedAt: time.Now().Unix()}
	if revert {
		receipt.Outcome, receipt.Directory, receipt.FilesSHA256 = "reverted", i.Input.Directory, fail2banStateFilesHash(i.Input.Before)
	} else {
		receipt.Outcome, receipt.Directory, receipt.FilesSHA256 = "restored", ready.Directory, fail2banStateFilesHash(i.After)
	}
	if err = writeFail2banStateRestoreReceipt(i, receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

func writeFail2banStateRestoreReceipt(i fail2banStateRestoreIntent, receipt *fail2banStateRestoreReceipt) error {
	raw, err := fail2banStateJSON(receipt)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(filepath.Join(i.dir(), "receipt.json"), raw, 4096)
}

func (i fail2banStateRestoreIntent) observeForRestore(ctx context.Context, ready *fail2banStateRestoreReady, revert bool) (bool, error) {
	if revert {
		identity, files, err := observeFail2banStateDirectory(ctx, filepath.Join(i.Input.Basis.Managed.work(), "state"))
		if err != nil {
			return false, err
		}
		if identity == i.Input.Directory && fail2banStateFilesHash(files) == fail2banStateFilesHash(i.Input.Before) {
			return false, nil
		}
	}
	return i.observe(ctx, ready)
}
