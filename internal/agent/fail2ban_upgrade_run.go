package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"nginxpanel/internal/secure"
)

func RunFail2banUpgrade(ctx context.Context, in Fail2banUpgradeRunOptions) (Fail2banUpgradeRun, error) {
	if !validID(in.PreparationID) || !fail2banDigest.MatchString(in.Target) {
		return Fail2banUpgradeRun{}, errors.New("整体升级须提供运行准备 UUID 及其 intent_sha256")
	}
	return operateFail2banUpgradeRun(ctx, in, "run")
}
func ResumeFail2banUpgradeRun(ctx context.Context, data, scope, id string) (Fail2banUpgradeRun, error) {
	return operateFail2banUpgradeRun(ctx, Fail2banUpgradeRunOptions{DataDir: data, Scope: scope, OperationID: id}, "resume")
}
func CancelFail2banUpgradeRun(ctx context.Context, data, scope, id string) (Fail2banUpgradeRun, error) {
	return operateFail2banUpgradeRun(ctx, Fail2banUpgradeRunOptions{DataDir: data, Scope: scope, OperationID: id}, "cancel")
}

func beginFail2banUpgradeRun(ctx context.Context, in Fail2banUpgradeRunOptions, j *Journal) (fail2banUpgradeRunIntent, error) {
	var i fail2banUpgradeRunIntent
	if err := fail2banUpgradeIdle(j); err != nil {
		return i, err
	}
	if _, err := j.Get(in.OperationID); !os.IsNotExist(err) {
		return i, errors.Join(errors.New("整体升级 UUID 已有审计或无法核对"), err)
	}
	p, r, err := readFail2banUpgradePreparation(in.DataDir, in.PreparationID, filepath.Join(fail2banUpgradePreparations(in.DataDir), in.PreparationID))
	if err != nil {
		return i, err
	}
	i = fail2banUpgradeRunIntent{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, PreparationReceiptSHA256: fail2banUpgradeGrantHash("preparation-receipt", r), QuiesceID: secure.ID(), SwitchID: secure.ID(), ActivationID: secure.ID(), RestoreID: secure.ID(), RecoveryActivationID: secure.ID()}
	if fail2banJailNeedsNginx(p.Basis.Bundle) {
		_, _, i.NginxRuntimeSHA256, err = i.nginxObserver()
		if err != nil {
			return i, err
		}
	}
	if err = i.validate(in.DataDir, in.OperationID, p, r); err != nil {
		return i, err
	}
	if err = i.beforeExecution(ctx); err != nil {
		return i, err
	}
	for step := 1; step <= 5; step++ {
		id := i.child(step)
		if _, err = j.Get(id); !os.IsNotExist(err) {
			return i, errors.Join(errors.New("整体升级子任务 UUID 已被审计占用"), err)
		}
		store := []string{"", fail2banUpgradeQuiescences(in.DataDir), fail2banUpgradeSwitches(in.DataDir), fail2banUpgradeActivations(in.DataDir), fail2banUpgradeRestores(in.DataDir), fail2banUpgradeActivations(in.DataDir)}[step]
		if _, err = os.Lstat(filepath.Join(store, id)); !os.IsNotExist(err) {
			return i, errors.Join(errors.New("整体升级子任务 UUID 已有私有材料"), err)
		}
	}
	if err = reserveFail2banUpgradeRun(i); err != nil {
		return i, err
	}
	return i, nil
}

func (i fail2banUpgradeRunIntent) activation(restored bool) Fail2banUpgradeActivationOptions {
	r := i.Request
	out := Fail2banUpgradeActivationOptions{DataDir: r.DataDir, Scope: r.Scope, OperationID: i.ActivationID, SwitchID: i.SwitchID, NginxBinary: r.NginxBinary, NginxWorker: r.NginxWorker, NginxContainer: r.NginxContainer}
	if restored {
		out.OperationID, out.SwitchID, out.RestoreID = i.RecoveryActivationID, "", i.RestoreID
	}
	return out
}

func (i fail2banUpgradeRunIntent) nginxObserver() (*Nginx, string, string, error) {
	r := i.Request
	return fail2banUpgradeNginxObserver(Fail2banUpgradeVerificationOptions{DataDir: r.DataDir, NginxBinary: r.NginxBinary, NginxWorker: r.NginxWorker, NginxContainer: r.NginxContainer})
}

func (i fail2banUpgradeRunIntent) beforeExecution(ctx context.Context) error {
	p, r, err := readFail2banUpgradePreparation(i.Request.DataDir, i.Request.PreparationID, filepath.Join(fail2banUpgradePreparations(i.Request.DataDir), i.Request.PreparationID))
	if err != nil {
		return err
	}
	if p.hash() != i.Request.Target {
		return ErrExternalChange
	}
	status, err := fail2banUpgradePreparationStatus(ctx, p, r)
	if err != nil {
		return err
	}
	if status.State != "prepared" || status.ScopeCurrent == nil || !*status.ScopeCurrent || status.CheckpointCurrent == nil || !*status.CheckpointCurrent {
		return errors.New("整体升级的原运行准备或动作检查点已变化")
	}
	if err = verifyFail2banManaged(ctx, &p.Basis.Current, true); err != nil {
		return err
	}
	if err = verifyFail2banManaged(ctx, &p.Basis.Candidate, false); err != nil {
		return err
	}
	if err = i.reserveChildren(p); err != nil {
		return err
	}
	if i.NginxRuntimeSHA256 != "" {
		n, _, hash, e := i.nginxObserver()
		if e != nil {
			return e
		}
		if hash != i.NginxRuntimeSHA256 {
			return ErrExternalChange
		}
		dir, m, e := n.active()
		if e != nil {
			return e
		}
		if dir != p.Basis.Bundle.NginxDir || manifestHash(m) != p.Basis.Bundle.NginxHash {
			return ErrExternalChange
		}
		if e = n.observe(ctx, m); e != nil {
			return e
		}
	}
	return ctx.Err()
}

func ensureFail2banUpgradeRunJournal(i fail2banUpgradeRunIntent, f fail2banUpgradeRunFacts, j *Journal) error {
	a, err := j.Get(i.Request.OperationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && f.Receipt != nil && sameFail2banUpgradePreparationRecord(a, i.record(f.Receipt)) {
		return nil
	}
	active, _, e := pendingFail2banUpgradeRun(i.Request.DataDir)
	if e != nil {
		return e
	}
	if active == nil {
		if err == nil || f.Execution || f.Receipt != nil {
			return errors.New("整体升级隔离变化，不重建原授权")
		}
		if e = fail2banUpgradeIdle(j); e != nil {
			return e
		}
		if e = rootJSONWrite(filepath.Join(fail2banUpgradeRuns(i.Request.DataDir), "current.json"), i.marker(), 4096); e != nil {
			return e
		}
	} else if active.hash() != i.hash() {
		return ErrBusy
	}
	if os.IsNotExist(err) {
		if f.Execution || f.Receipt != nil {
			return errors.New("整体升级已执行但原审计丢失，不重建授权")
		}
		return j.Put(i.record(nil))
	}
	if !pendingFail2banUpgradeRunRecord(a, i.record(nil)) {
		return errors.New("整体升级原审计与意图冲突")
	}
	return nil
}

func operateFail2banUpgradeRun(parent context.Context, in Fail2banUpgradeRunOptions, action string) (out Fail2banUpgradeRun, resultErr error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	i, err := readFail2banUpgradeRun(in.DataDir, in.OperationID)
	if os.IsNotExist(err) && action == "run" {
		if _, e := os.Lstat(filepath.Join(fail2banUpgradeRuns(in.DataDir), in.OperationID)); os.IsNotExist(e) {
			i, err = beginFail2banUpgradeRun(ctx, in, &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")})
		}
	}
	if err != nil {
		unlock()
		return out, err
	}
	if action == "run" && i.Request != in {
		unlock()
		return out, errors.New("同一整体升级 UUID 已绑定其他请求")
	}
	f, err := i.facts()
	if err != nil {
		unlock()
		return out, err
	}
	out = i.result(f, false)
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	if err = ensureFail2banUpgradeRunJournal(i, f, j); err != nil {
		unlock()
		return out, err
	}
	if f.Receipt != nil {
		if action == "cancel" && f.Receipt.Outcome != "cancelled" {
			unlock()
			return out, errors.New("整体升级已完成，不能用旧取消授权影响后续实例")
		}
		err = acknowledgeFail2banUpgradeRun(i, f.Receipt, j)
		unlock()
		return i.result(f, err == nil), err
	}
	if err = fail2banUpgradeRunIdle(in.DataDir, in.OperationID); err != nil {
		unlock()
		return out, err
	}
	if err = fail2banUpgradeActivationQuota(fail2banUpgradeRuns(in.DataDir), false); err != nil {
		unlock()
		return out, err
	}
	if action == "cancel" {
		if f.Execution {
			unlock()
			return out, errors.New("整体升级已进入执行，须沿原父任务续办；不能按未执行取消")
		}
		out, err = finishFail2banUpgradeRun(i, f, "cancelled", j)
		unlock()
		return out, err
	}
	if !f.Execution {
		if time.Now().Unix() > i.CreatedAt+300 {
			unlock()
			return out, errors.New("整体升级授权已过期且尚未执行，可取消后重新准备")
		}
		if err = i.beforeExecution(ctx); err != nil {
			unlock()
			return out, err
		}
		if err = fail2banUpgradeIdleFor(j, in.OperationID); err != nil {
			unlock()
			return out, err
		}
		if err = ctx.Err(); err != nil {
			unlock()
			return out, err
		}
		if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), i.marker()); err != nil {
			unlock()
			return out, err
		}
		f.Execution = true
	}
	step := f.Step
	unlock()
	// Child executors acquire their own host/binding/maintenance locks. Keep
	// the durable parent fence while releasing those locks between stages.
	childErr := i.executeChild(ctx, step)
	unlock, err = fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, errors.Join(childErr, err)
	}
	defer unlock()
	current, err := readFail2banUpgradeRun(in.DataDir, in.OperationID)
	if err != nil || current.hash() != i.hash() {
		return out, errors.Join(ErrExternalChange, childErr, err)
	}
	f, err = i.facts()
	if err != nil {
		return out, errors.Join(childErr, err)
	}
	if err = ensureFail2banUpgradeRunJournal(i, f, j); err != nil {
		return out, errors.Join(childErr, err)
	}
	out = i.result(f, false)
	if f.Receipt != nil {
		if err = acknowledgeFail2banUpgradeRun(i, f.Receipt, j); err != nil {
			return out, err
		}
		return i.result(f, true), nil
	}
	if f.Step != step {
		return out, nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		a, e := j.Get(in.OperationID)
		if e != nil {
			resultErr = errors.Join(resultErr, e)
			return
		}
		if !pendingFail2banUpgradeRunRecord(a, i.record(nil)) {
			return
		}
		message := []rune(resultErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		a.State, a.Error = "recovery_required", string(message)
		resultErr = errors.Join(resultErr, j.Put(a))
		out.State, out.Reason = "recovery_required", a.Error
	}()
	if step == 3 || step == 5 {
		_, af, e := i.activated(step == 5)
		if errors.Is(e, errFail2banUpgradeRunChildPending) {
			if childErr == nil {
				audit, readErr := j.Get(in.OperationID)
				if readErr != nil {
					return out, readErr
				}
				if audit.State == "recovery_required" {
					return out, j.Put(i.record(nil))
				}
			}
			return out, childErr
		}
		if e != nil {
			return out, errors.Join(childErr, e)
		}
		if af.Receipt.Outcome == "verified" {
			outcome := "upgraded"
			if step == 5 {
				outcome = "restored"
			}
			return finishFail2banUpgradeRun(i, f, outcome, j)
		}
		if step == 5 {
			return out, errors.New("原版本恢复启动已停止，保护未恢复；保留现场与整体升级隔离")
		}
	}
	source, err := i.stageSource(step + 1)
	if err != nil {
		if childErr != nil {
			return out, childErr
		}
		return out, err
	}
	stage := fail2banUpgradeRunStage{fail2banUpgradeActivationMarker: i.marker(), Step: step + 1, At: time.Now().Unix(), SourceSHA256: source}
	if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "stage-"+strconv.Itoa(step+1)+".json"), stage); err != nil {
		return out, err
	}
	f.Step++
	if err = j.Put(i.record(nil)); err != nil {
		return i.result(f, false), err
	}
	return i.result(f, false), nil
}

func (i fail2banUpgradeRunIntent) executeChild(ctx context.Context, step int) error {
	in := i.Request
	switch step {
	case 1:
		_, err := QuiesceFail2banUpgrade(ctx, Fail2banUpgradeQuiesceOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.QuiesceID, PreparationID: in.PreparationID, Target: in.Target})
		return err
	case 2:
		q, r, err := i.quiescence()
		if err != nil {
			return err
		}
		_, err = SwitchFail2banUpgrade(ctx, Fail2banUpgradeSwitchOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.SwitchID, PreparationID: q.StoppedPreparationID, SnapshotID: q.SnapshotID, Target: r.PreparationSHA256})
		return err
	case 3, 5:
		_, err := ActivateFail2banUpgrade(ctx, i.activation(step == 5))
		return err
	case 4:
		_, err := RestoreFail2banUpgrade(ctx, Fail2banUpgradeRestoreOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.RestoreID, ActivationID: i.ActivationID})
		return err
	}
	return errors.New("整体升级执行阶段无效")
}

func finishFail2banUpgradeRun(i fail2banUpgradeRunIntent, f fail2banUpgradeRunFacts, outcome string, j *Journal) (Fail2banUpgradeRun, error) {
	r := fail2banUpgradeRunReceipt{fail2banUpgradeActivationMarker: i.marker(), Outcome: outcome, CompletedAt: time.Now().Unix()}
	var err error
	if outcome != "cancelled" {
		r.SourceSHA256, err = i.completionSource(outcome == "restored")
		if err != nil {
			return i.result(f, false), err
		}
	}
	if err = writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), r); err != nil {
		return i.result(f, false), err
	}
	f.Receipt = &r
	if err = acknowledgeFail2banUpgradeRun(i, &r, j); err != nil {
		return i.result(f, false), err
	}
	return i.result(f, true), nil
}

func acknowledgeFail2banUpgradeRun(i fail2banUpgradeRunIntent, receipt *fail2banUpgradeRunReceipt, j *Journal) error {
	audit, err := j.Get(i.Request.OperationID)
	if err != nil {
		return err
	}
	expected := i.record(receipt)
	if sameFail2banUpgradePreparationRecord(audit, expected) {
		return nil
	}
	if !pendingFail2banUpgradeRunRecord(audit, i.record(nil)) {
		return errors.New("整体升级终态审计与原授权冲突")
	}
	return j.Put(expected)
}

func ReadFail2banUpgradeRun(ctx context.Context, data, scope, id string) (Fail2banUpgradeRun, error) {
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return Fail2banUpgradeRun{}, err
	}
	defer unlock()
	i, err := readFail2banUpgradeRun(data, id)
	if err != nil {
		return Fail2banUpgradeRun{}, err
	}
	f, err := i.facts()
	if err != nil {
		return Fail2banUpgradeRun{}, err
	}
	out := i.result(f, false)
	a, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if err != nil {
		return out, err
	}
	if f.Receipt != nil && sameFail2banUpgradePreparationRecord(a, i.record(f.Receipt)) {
		return i.result(f, true), ctx.Err()
	}
	if !pendingFail2banUpgradeRunRecord(a, i.record(nil)) {
		return out, errors.New("整体升级原审计不匹配")
	}
	active, _, err := pendingFail2banUpgradeRun(data)
	if err != nil || active == nil || active.hash() != i.hash() {
		return out, errors.Join(errors.New("整体升级缺少原隔离"), err)
	}
	if a.State == "recovery_required" {
		out.State, out.Reason = a.State, a.Error
	}
	return out, ctx.Err()
}
