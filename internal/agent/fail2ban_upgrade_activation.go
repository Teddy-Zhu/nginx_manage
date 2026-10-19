package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

func ActivateFail2banUpgrade(ctx context.Context, in Fail2banUpgradeActivationOptions) (Fail2banUpgradeActivation, error) {
	if !validID(in.SwitchID) {
		return Fail2banUpgradeActivation{}, errors.New("升级启动须指定已完成的切换 UUID")
	}
	return operateFail2banUpgradeActivation(ctx, in, "activate")
}

func ResumeFail2banUpgradeActivation(ctx context.Context, data, scope, id string) (Fail2banUpgradeActivation, error) {
	return operateFail2banUpgradeActivation(ctx, Fail2banUpgradeActivationOptions{DataDir: data, Scope: scope, OperationID: id}, "resume")
}

func StopFail2banUpgradeActivation(ctx context.Context, data, scope, id string) (Fail2banUpgradeActivation, error) {
	return operateFail2banUpgradeActivation(ctx, Fail2banUpgradeActivationOptions{DataDir: data, Scope: scope, OperationID: id}, "stop")
}

func beginFail2banUpgradeActivation(ctx context.Context, in Fail2banUpgradeActivationOptions, j *Journal) (fail2banUpgradeActivationIntent, error) {
	var i fail2banUpgradeActivationIntent
	if err := fail2banUpgradeIdle(j); err != nil {
		return i, err
	}
	if _, err := j.Get(in.OperationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("升级启动 UUID 已存在审计或无法核对"), err)
	}
	s, receipt, err := readFail2banUpgradeVerificationSwitch(in.DataDir, in.SwitchID)
	if err != nil {
		return i, err
	}
	i = fail2banUpgradeActivationIntent{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, VerificationID: secure.ID(), SelectedEvent: s.After.EventID, SwitchSHA256: s.hash(), SwitchReceiptSHA256: fail2banUpgradeGrantHash("switch-receipt", receipt)}
	if fail2banJailNeedsNginx(s.Prepared.Material.Bundle) {
		n, _, runtimeHash, err := fail2banUpgradeNginxObserver(i.verification())
		if err != nil {
			return i, err
		}
		dir, m, err := n.active()
		if err != nil {
			return i, err
		}
		if dir != s.Prepared.Material.Bundle.NginxDir || manifestHash(m) != s.Prepared.Material.Bundle.NginxHash {
			return i, errors.New("升级启动须保持原活动 Nginx 修订")
		}
		if err = n.observe(ctx, m); err != nil {
			return i, err
		}
		i.NginxRuntimeSHA256 = runtimeHash
	}
	if err = i.validate(in.DataDir, in.OperationID, s, receipt); err != nil {
		return i, err
	}
	if err = i.beforeStart(ctx, s); err != nil {
		return i, err
	}
	if err = reserveFail2banUpgradeVerification(in.DataDir); err != nil {
		return i, err
	}
	if _, err = j.Get(i.VerificationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("升级保护证明 UUID 冲突"), err)
	}
	if err = reserveFail2banUpgradeActivation(i); err != nil {
		return i, err
	}
	return i, nil
}

func (i fail2banUpgradeActivationIntent) beforeStart(ctx context.Context, s fail2banUpgradeSwitch) error {
	if _, err := i.selection(ctx); err != nil {
		return err
	}
	if err := s.snapshot(ctx); err != nil {
		return err
	}
	return s.observe(ctx, nil)
}

func ensureFail2banUpgradeActivationJournal(ctx context.Context, i fail2banUpgradeActivationIntent, s fail2banUpgradeSwitch, f fail2banUpgradeActivationFacts, j *Journal) error {
	audit, err := j.Get(i.Request.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && f.Receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return nil
	}
	active, _, e := pendingFail2banUpgradeActivation(i.Request.DataDir)
	if e != nil {
		return e
	}
	if active == nil || active.hash() != i.hash() {
		if active != nil {
			return ErrBusy
		}
		if err == nil || f.Execution || f.Claim != nil || f.Started != nil || f.Stop != nil || f.Receipt != nil {
			return errors.New("升级启动隔离变化，不重新取得执行授权")
		}
		if e = fail2banUpgradeIdle(j); e != nil {
			return e
		}
		if e = i.beforeStart(ctx, s); e != nil {
			return e
		}
		if e = rootJSONWrite(filepath.Join(fail2banUpgradeActivations(i.Request.DataDir), "current.json"), i.marker(), 4096); e != nil {
			return e
		}
	}
	if os.IsNotExist(err) {
		if f.Execution || f.Claim != nil || f.Started != nil || f.Stop != nil || f.Receipt != nil {
			return errors.New("升级启动已有执行材料但原审计丢失，不重建授权")
		}
		if e = i.beforeStart(ctx, s); e != nil {
			return e
		}
		return j.Put(i.record(nil))
	}
	if !pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
		return errors.New("升级启动审计与原授权不匹配")
	}
	return nil
}

func operateFail2banUpgradeActivation(parent context.Context, in Fail2banUpgradeActivationOptions, action string) (out Fail2banUpgradeActivation, resultErr error) {
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	dir := filepath.Join(fail2banUpgradeActivations(in.DataDir), in.OperationID)
	_, statErr := os.Lstat(dir)
	if os.IsNotExist(statErr) && action == "activate" {
		if _, err = beginFail2banUpgradeActivation(ctx, in, j); err != nil {
			return out, err
		}
	} else if statErr != nil {
		return out, statErr
	}
	i, s, err := readFail2banUpgradeActivation(in.DataDir, in.OperationID)
	if err != nil {
		return out, err
	}
	if action == "activate" && i.Request != in {
		return out, errors.New("相同升级启动 UUID 已绑定其他请求")
	}
	f, err := i.facts()
	if err != nil {
		return out, err
	}
	out = i.result(f, false)
	if err = ensureFail2banUpgradeActivationJournal(ctx, i, s, f, j); err != nil {
		return out, err
	}
	if f.Receipt != nil {
		if action == "stop" && f.Receipt.Outcome == "verified" {
			return i.result(f, true), errors.New("升级启动已完成，不得用旧停止授权覆盖后续运行")
		}
		audit, e := j.Get(i.Request.OperationID)
		if e != nil {
			return out, e
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
		audit, e := j.Get(i.Request.OperationID)
		if e != nil {
			resultErr = errors.Join(resultErr, e)
			return
		}
		if !pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
			return
		}
		audit.State = "recovery_required"
		message := []rune(resultErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		audit.Error = string(message)
		resultErr = errors.Join(resultErr, j.Put(audit))
	}()
	if err = fail2banUpgradeIdleFor(j, i.Request.OperationID); err != nil {
		return out, err
	}
	if err = fail2banUpgradeActivationQuota(fail2banUpgradeActivations(in.DataDir), false); err != nil {
		return out, err
	}
	if action == "stop" || f.Stop != nil {
		reason := "cancelled"
		if f.Stop != nil {
			reason = f.Stop.Reason
		}
		return stopFail2banUpgradeActivation(i, s, f, j, reason)
	}
	if f.Started == nil {
		if time.Now().Unix() > i.deadline() {
			return stopFail2banUpgradeActivation(i, s, f, j, "protection_timeout")
		}
		if !f.Execution {
			if err = i.beforeStart(ctx, s); err != nil {
				return out, err
			}
			if err = ctx.Err(); err != nil {
				return out, err
			}
			closeStart, err := armFail2banUpgradeStart(ctx, i)
			if err != nil {
				return out, err
			}
			defer closeStart()
			if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), i.marker()); err != nil {
				return out, err
			}
			f.Execution = true
			if err = fail2banManagedSystemctl(ctx, "start", fail2banManagedService); err != nil {
				closeStart()
				return stopFailedFail2banUpgradeActivation(i, s, f, j, "start_failed", err)
			}
			if err = waitFail2banManagedLive(ctx, &s.After); err != nil {
				closeStart()
				return stopFailedFail2banUpgradeActivation(i, s, f, j, "start_failed", err)
			}
			closeStart()
		}
		// A restart observes the one claimed invocation; it never resends start.
		f, err = i.facts()
		if err != nil {
			return out, err
		}
		live, e := readFail2banLiveService(ctx, s.After.binding())
		if e != nil || f.Claim == nil || live.invocation != f.Claim.Invocation {
			return stopFailedFail2banUpgradeActivation(i, s, f, j, "start_unconfirmed", errors.Join(errors.New("无法确认原启动许可的服务代次"), e))
		}
		if _, err = i.selection(ctx); err != nil {
			return out, err
		}
		if time.Now().Unix() > i.deadline() {
			return stopFail2banUpgradeActivation(i, s, f, j, "protection_timeout")
		}
		started := fail2banUpgradeActivationStarted{fail2banUpgradeActivationMarker: i.marker(), At: time.Now().Unix(), Invocation: live.invocation, SocketInode: live.inode, PID: *live.view.MainPID}
		if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "started.json"), started); err != nil {
			return out, err
		}
		f.Started = &started
		return i.result(f, false), nil
	}
	// A saved proof completed its observation before interruption. Acknowledging
	// it cannot restart the engine or resample mutable protection/database state.
	v, _, err := readFail2banUpgradeVerification(in.DataDir, i.VerificationID)
	if err == nil {
		return finishFail2banUpgradeActivation(i, f, v, j)
	}
	if !errors.Is(err, errFail2banUpgradeVerificationAbsent) {
		return out, err
	}
	if time.Now().Unix() > i.deadline() {
		return stopFail2banUpgradeActivation(i, s, f, j, "protection_timeout")
	}
	if _, err = i.selection(ctx); err != nil {
		return out, err
	}
	live, err := readFail2banLiveService(ctx, s.After.binding())
	if err != nil {
		return out, err
	}
	if err = f.Started.matches(live); err != nil {
		return out, err
	}
	proofCtx, proofCancel := context.WithDeadline(ctx, time.Unix(i.deadline(), 0))
	_, err = verifyFail2banUpgradeLocked(proofCtx, i.verification(), i.Request.OperationID)
	proofCancel()
	if err != nil {
		if time.Now().Unix() >= i.deadline() {
			return stopFailedFail2banUpgradeActivation(i, s, f, j, "protection_timeout", err)
		}
		out = i.result(f, false)
		out.Reason = "protection_pending"
		return out, err
	}
	v, _, err = readFail2banUpgradeVerification(in.DataDir, i.VerificationID)
	if err != nil {
		return out, err
	}
	return finishFail2banUpgradeActivation(i, f, v, j)
}

func finishFail2banUpgradeActivation(i fail2banUpgradeActivationIntent, f fail2banUpgradeActivationFacts, v fail2banUpgradeVerification, j *Journal) (Fail2banUpgradeActivation, error) {
	out := i.result(f, false)
	if f.Started == nil || f.Stop != nil {
		return out, errors.New("升级启动尚无运行回执或已进入停止")
	}
	if err := i.checkProof(v, *f.Started); err != nil {
		return out, err
	}
	if err := acknowledgeFail2banUpgradeVerification(v, j); err != nil {
		return out, err
	}
	receipt := fail2banUpgradeActivationReceipt{fail2banUpgradeActivationMarker: i.marker(), CompletedAt: v.CreatedAt, Outcome: "verified", VerificationSHA256: v.hash()}
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

func stopFailedFail2banUpgradeActivation(i fail2banUpgradeActivationIntent, s fail2banUpgradeSwitch, f fail2banUpgradeActivationFacts, j *Journal, reason string, cause error) (Fail2banUpgradeActivation, error) {
	out, err := stopFail2banUpgradeActivation(i, s, f, j, reason)
	return out, errors.Join(cause, err)
}

func stopFail2banUpgradeActivation(i fail2banUpgradeActivationIntent, s fail2banUpgradeSwitch, f fail2banUpgradeActivationFacts, j *Journal, reason string) (Fail2banUpgradeActivation, error) {
	// Cancellation cannot strand an already sent start solely because its caller left.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	current, err := i.facts()
	if err != nil {
		return i.result(f, false), err
	}
	f = current
	if f.Receipt != nil {
		return i.result(f, false), errors.New("升级启动已存在完成证明，不覆盖既有结果")
	}
	if f.Stop == nil {
		stop := fail2banUpgradeActivationStop{fail2banUpgradeActivationMarker: i.marker(), At: time.Now().Unix(), Reason: reason}
		if err := writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "stop.json"), stop); err != nil {
			return i.result(f, false), err
		}
		f.Stop = &stop
	}
	out := i.result(f, false)
	// Stopping never changes an unrelated service generation or mutable DB bytes.
	if err := i.engine(ctx, false); err != nil {
		return out, err
	}
	service, invocation, err := lifecycleService(ctx)
	if err != nil {
		return out, err
	}
	if service.MainPID == nil {
		return out, errors.New("候选服务状态未知，不能确认停止")
	}
	if *service.MainPID != 0 || service.Active == "activating" || service.Active == "deactivating" {
		if f.Claim == nil || invocation != f.Claim.Invocation {
			return out, errors.New("候选运行代次超出原启动许可，不停止其他实例")
		}
		if err = fail2banManagedSystemctl(ctx, "stop", fail2banManagedService); err != nil {
			return out, err
		}
	}
	service, _, err = lifecycleService(ctx)
	if err != nil {
		return out, err
	}
	if err = fail2banExistingStopped(s.After.binding(), service); err != nil {
		return out, err
	}
	receipt := fail2banUpgradeActivationReceipt{fail2banUpgradeActivationMarker: i.marker(), CompletedAt: time.Now().Unix(), Outcome: "stopped"}
	if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), receipt); err != nil {
		return out, err
	}
	f.Receipt = &receipt
	out = i.result(f, false)
	if err = j.Put(i.record(&receipt)); err != nil {
		return out, err
	}
	return i.result(f, true), nil
}

func ReadFail2banUpgradeActivation(parent context.Context, data, scope, id string) (Fail2banUpgradeActivation, error) {
	var out Fail2banUpgradeActivation
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = parent.Err(); err != nil {
		return out, err
	}
	i, _, err := readFail2banUpgradeActivation(data, id)
	if err != nil {
		return out, err
	}
	f, err := i.facts()
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
	if !pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
		return out, errors.New("升级启动原审计与持久材料冲突")
	}
	if audit.State == "recovery_required" {
		out.State, out.Reason = audit.State, audit.Error
	}
	return out, nil
}
