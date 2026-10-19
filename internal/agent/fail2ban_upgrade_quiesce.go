package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

func QuiesceFail2banUpgrade(ctx context.Context, in Fail2banUpgradeQuiesceOptions) (Fail2banUpgradeQuiesce, error) {
	if !validID(in.PreparationID) || !fail2banDigest.MatchString(in.Target) {
		return Fail2banUpgradeQuiesce{}, errors.New("升级停止须指定运行准备 UUID 及其 intent_sha256")
	}
	return operateFail2banUpgradeQuiesce(ctx, in, "quiesce")
}
func ResumeFail2banUpgradeQuiesce(ctx context.Context, data, scope, id string) (Fail2banUpgradeQuiesce, error) {
	return operateFail2banUpgradeQuiesce(ctx, Fail2banUpgradeQuiesceOptions{DataDir: data, Scope: scope, OperationID: id}, "resume")
}
func CancelFail2banUpgradeQuiesce(ctx context.Context, data, scope, id string) (Fail2banUpgradeQuiesce, error) {
	return operateFail2banUpgradeQuiesce(ctx, Fail2banUpgradeQuiesceOptions{DataDir: data, Scope: scope, OperationID: id}, "cancel")
}

func beginFail2banUpgradeQuiesce(ctx context.Context, in Fail2banUpgradeQuiesceOptions, j *Journal) (fail2banUpgradeQuiesceIntent, error) {
	var i fail2banUpgradeQuiesceIntent
	if err := fail2banUpgradeIdleFor(j, in.OperationID); err != nil {
		return i, err
	}
	if _, err := j.Get(in.OperationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("升级停止 UUID 已有审计或无法核对"), err)
	}
	p, receipt, err := readFail2banUpgradePreparation(in.DataDir, in.PreparationID, filepath.Join(fail2banUpgradePreparations(in.DataDir), in.PreparationID))
	if err != nil {
		return i, err
	}
	if p.hash() != in.Target {
		return i, errors.New("运行准备摘要已变化")
	}
	audit, err := j.Get(in.PreparationID)
	if err != nil || !sameFail2banUpgradePreparationRecord(audit, p.record(receipt)) {
		return i, errors.Join(errors.New("升级停止前须确认原准备审计"), err)
	}
	b, err := readFail2banUpgradeBasis(ctx, in.DataDir, &p.Basis.Candidate)
	if err != nil {
		return i, err
	}
	if b.hash() != p.Basis.hash() || b.Service.Active != "active" {
		return i, errors.New("升级停止须仍选择原运行准备的实例、配置和批准")
	}
	grants, err := planFail2banUpgradeGrants(in.DataDir, b)
	if err != nil {
		return i, err
	}
	if !grants.ScopeVerified || grants.ScopeSHA256 != p.Grants.ScopeSHA256 {
		return i, errors.New("升级停止的原动作批准或恢复检查点不可核对")
	}
	recovery, err := readFail2banUpgradeHostRecovery(in.DataDir, b)
	if err != nil {
		return i, err
	}
	live, err := readFail2banLiveService(ctx, b.Current.binding())
	if err != nil {
		return i, err
	}
	bans, err := readFail2banJailRuntime(ctx, &b.Current, b.Bundle)
	if err != nil {
		return i, err
	}
	after, err := readFail2banLiveService(ctx, b.Current.binding())
	if err != nil || !sameFail2banLive(live, after) {
		return i, errors.Join(errors.New("升级停止准备期间原实例运行代次变化"), err)
	}
	i = fail2banUpgradeQuiesceIntent{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, PreparationReceiptSHA256: fail2banUpgradeGrantHash("preparation-receipt", receipt), SnapshotID: secure.ID(), StoppedPreparationID: secure.ID(), Invocation: live.invocation, SocketInode: live.inode, PID: *live.view.MainPID, Bans: bans, Recovery: recovery}
	i.MachineID, i.BootID, err = hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return i, err
	}
	i.Directory, err = fail2banStateDirectoryIdentity(filepath.Join(b.Current.work(), "state"))
	if err != nil {
		return i, err
	}
	if root := b.HostRegistration; root != nil && root.State == "registered" {
		copy := p
		copy.Recovery = recovery
		program, _ := fail2banUpgradeOriginalHostProgram(copy)
		i.Kernel, err = program.snapshot(ctx)
		if err != nil {
			return i, err
		}
	}
	i.Nginx, err = readFail2banUpgradeQuiesceNginx(in.DataDir, p)
	if err != nil {
		return i, err
	}
	if err = i.validate(in.DataDir, in.OperationID, p, receipt); err != nil {
		return i, err
	}
	if _, err = i.observe(ctx, p); err != nil {
		return i, err
	}
	if err = i.reserveChildren(p, j); err != nil {
		return i, err
	}
	if err = reserveFail2banUpgradeQuiesce(i); err != nil {
		return i, err
	}
	return i, nil
}

func ensureFail2banUpgradeQuiesceJournal(ctx context.Context, i fail2banUpgradeQuiesceIntent, p fail2banUpgradePreparation, f fail2banUpgradeQuiesceFacts, j *Journal, cancel bool) error {
	audit, err := j.Get(i.Request.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && f.Receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return nil
	}
	active, _, e := pendingFail2banUpgradeQuiesce(i.Request.DataDir)
	if e != nil {
		return e
	}
	if active == nil || active.hash() != i.hash() {
		if active != nil {
			return ErrBusy
		}
		if err == nil || f.Execution || f.Stopped != nil || f.Receipt != nil {
			return errors.New("升级停止隔离变化，不重新取得执行授权")
		}
		if e = fail2banUpgradeIdleFor(j, i.Request.OperationID); e != nil {
			return e
		}
		if !cancel {
			if e = i.running(ctx, p); e != nil {
				return e
			}
		}
		if e = rootJSONWrite(filepath.Join(fail2banUpgradeQuiescences(i.Request.DataDir), "current.json"), i.marker(), 4096); e != nil {
			return e
		}
	}
	if os.IsNotExist(err) {
		if f.Execution || f.Stopped != nil || f.Receipt != nil {
			return errors.New("升级停止已执行但原审计丢失，不重建授权")
		}
		if !cancel {
			if e = i.running(ctx, p); e != nil {
				return e
			}
		}
		return j.Put(i.record(nil))
	}
	if !pendingFail2banUpgradeQuiesceRecord(audit, i.record(nil)) {
		return errors.New("升级停止审计与原意图冲突")
	}
	return nil
}

func operateFail2banUpgradeQuiesce(parent context.Context, in Fail2banUpgradeQuiesceOptions, action string) (out Fail2banUpgradeQuiesce, resultErr error) {
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	_, statErr := os.Lstat(filepath.Join(fail2banUpgradeQuiescences(in.DataDir), in.OperationID))
	if os.IsNotExist(statErr) && action == "quiesce" {
		if _, err = beginFail2banUpgradeQuiesce(ctx, in, j); err != nil {
			return out, err
		}
	} else if statErr != nil {
		return out, statErr
	}
	i, p, err := readFail2banUpgradeQuiesce(in.DataDir, in.OperationID)
	if err != nil {
		return out, err
	}
	if action == "quiesce" && i.Request != in {
		return out, errors.New("相同升级停止 UUID 已绑定其他准备或摘要")
	}
	f, err := i.facts(p)
	if err != nil {
		return out, err
	}
	out = i.result(f, false)
	if err = ensureFail2banUpgradeQuiesceJournal(ctx, i, p, f, j, action == "cancel"); err != nil {
		return out, err
	}
	if f.Receipt != nil {
		audit, e := j.Get(in.OperationID)
		if e != nil {
			return out, e
		}
		if action == "cancel" && f.Receipt.Outcome != "cancelled" {
			return i.result(f, sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt))), errors.New("升级停止已完成，不得以旧取消授权影响后续运行")
		}
		if !sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
			if err = j.Put(i.record(f.Receipt)); err != nil {
				return out, err
			}
		}
		return i.result(f, true), nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		audit, e := j.Get(in.OperationID)
		if e != nil {
			resultErr = errors.Join(resultErr, e)
			return
		}
		if !pendingFail2banUpgradeQuiesceRecord(audit, i.record(nil)) {
			return
		}
		message := []rune(resultErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		audit.State, audit.Error = "recovery_required", string(message)
		resultErr = errors.Join(resultErr, j.Put(audit))
		out.State, out.Reason = "recovery_required", audit.Error
	}()
	if err = fail2banUpgradeIdleFor(j, in.OperationID); err != nil {
		return out, err
	}
	if err = fail2banUpgradeSwitchQuota(fail2banUpgradeQuiescences(in.DataDir), false); err != nil {
		return out, err
	}
	if action == "cancel" {
		if f.Execution || f.Stopped != nil {
			return out, errors.New("已进入原实例停止执行，不能按未执行取消；须续办原捕获")
		}
		return finishFail2banUpgradeQuiesce(i, f, fail2banUpgradeQuiesceReceipt{fail2banUpgradeActivationMarker: i.marker(), CompletedAt: time.Now().Unix(), Outcome: "cancelled"}, j)
	}
	if !f.Execution {
		if time.Now().Unix() > i.CreatedAt+300 {
			return out, errors.New("原升级停止授权已过期且尚未执行，可取消后重新准备")
		}
		if err = i.running(ctx, p); err != nil {
			return out, err
		}
		if err = i.reserveChildren(p, j); err != nil {
			return out, err
		}
		if err = ctx.Err(); err != nil {
			return out, err
		}
		if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), i.marker()); err != nil {
			return out, err
		}
		f.Execution = true
	}
	out = i.result(f, false)
	if f.Stopped == nil {
		stopped, e := i.stop(ctx, p)
		if e != nil {
			return out, e
		}
		if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "stopped.json"), stopped); err != nil {
			return out, err
		}
		f.Stopped = &stopped
	}
	out = i.result(f, false)
	basis, err := i.stopped(ctx, p, *f.Stopped)
	if err != nil {
		return out, err
	}
	snapshot := Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: "host", OperationID: i.SnapshotID}
	snapshotDir := filepath.Join(fail2banStateDir(in.DataDir), i.SnapshotID)
	if _, err = os.Lstat(snapshotDir); os.IsNotExist(err) {
		if _, err = captureFail2banStateFor(ctx, snapshot, j, in.OperationID); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	}
	r, m, err := readFail2banStateArchive(ctx, in.DataDir, i.SnapshotID, snapshotDir, nil)
	if err != nil {
		return out, err
	}
	if !fail2banUpgradeOneOf(m.Basis.Managed, p.Basis.Current) || !fail2banUpgradeOneOf(m.Basis.Bundle, p.Basis.Bundle) || !fail2banUpgradeOneOf(m.Basis.Service, f.Stopped.Service) || m.Basis.Invocation != f.Stopped.Invocation || m.Basis.MachineID != i.MachineID || m.Basis.BootID != i.BootID || m.Basis.StateLabel != i.Directory.SELinux || fail2banStateFilesHash(m.Files) != f.Stopped.FilesSHA256 || r.CreatedAt < f.Stopped.At {
		return out, errors.New("升级捕获快照与原停止、目录或配置不匹配")
	}
	if _, err = prepareFail2banState(ctx, snapshot); err != nil {
		return out, err
	}
	summary, err := i.snapshotBans(ctx, r, m)
	if err != nil {
		return out, err
	}
	grants, err := planFail2banUpgradeGrants(in.DataDir, basis)
	if err != nil {
		return out, err
	}
	if !grants.ScopeVerified || grants.ScopeSHA256 != p.Grants.ScopeSHA256 {
		return out, errors.New("停止态准备的动作范围已变化")
	}
	next := p.Request
	next.OperationID, next.Target = i.StoppedPreparationID, basis.hash()
	prepared, err := prepareFail2banUpgradeLocked(ctx, next, Fail2banUpgradePlan{Target: next.Target, Grants: grants}, basis, in.OperationID)
	if err != nil {
		return out, err
	}
	if prepared.State != "prepared" {
		return out, errors.New("停止态升级准备尚未审计确认")
	}
	if _, err = i.stopped(ctx, p, *f.Stopped); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	receipt := fail2banUpgradeQuiesceReceipt{fail2banUpgradeActivationMarker: i.marker(), CompletedAt: time.Now().Unix(), Outcome: "prepared", SnapshotReceiptSHA256: fail2banUpgradeGrantHash("quiesce-snapshot", r), PreparationSHA256: prepared.IntentSHA256, Bans: &summary}
	return finishFail2banUpgradeQuiesce(i, f, receipt, j)
}

func finishFail2banUpgradeQuiesce(i fail2banUpgradeQuiesceIntent, f fail2banUpgradeQuiesceFacts, receipt fail2banUpgradeQuiesceReceipt, j *Journal) (Fail2banUpgradeQuiesce, error) {
	out := i.result(f, false)
	if err := writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), receipt); err != nil {
		out.State, out.Stage = "recovery_required", "completion_unknown"
		return out, err
	}
	f.Receipt = &receipt
	out = i.result(f, false)
	if err := j.Put(i.record(&receipt)); err != nil {
		return out, err
	}
	return i.result(f, true), nil
}

func ReadFail2banUpgradeQuiesce(ctx context.Context, data, scope, id string) (Fail2banUpgradeQuiesce, error) {
	var out Fail2banUpgradeQuiesce
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	i, p, err := readFail2banUpgradeQuiesce(data, id)
	if err != nil {
		return out, err
	}
	f, err := i.facts(p)
	if err != nil {
		return out, err
	}
	out = i.result(f, false)
	audit, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if os.IsNotExist(err) {
		out.State, out.Stage = "recovery_required", "journal_missing"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if f.Receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return i.result(f, true), nil
	}
	if !pendingFail2banUpgradeQuiesceRecord(audit, i.record(nil)) {
		return out, errors.New("升级停止原审计与持久材料冲突")
	}
	if audit.State == "recovery_required" {
		out.State, out.Reason = audit.State, audit.Error
	}
	return out, nil
}
