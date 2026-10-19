package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func readFail2banUpgradeRun(data, id string) (fail2banUpgradeRunIntent, error) {
	var i fail2banUpgradeRunIntent
	if !validID(id) {
		return i, errors.New("整体升级 UUID 无效")
	}
	dir := filepath.Join(fail2banUpgradeRuns(data), id)
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, err
	}
	if err := readFail2banUpgradeActivationJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, err
	}
	if !validID(i.Request.PreparationID) {
		return i, errors.New("整体升级的原准备 UUID 无效")
	}
	p, r, err := readFail2banUpgradePreparation(data, i.Request.PreparationID, filepath.Join(fail2banUpgradePreparations(data), i.Request.PreparationID))
	if err != nil {
		return i, err
	}
	if err = i.validate(data, id, p, r); err != nil {
		return i, err
	}
	return i, i.childAudit(p.Request.OperationID, p.record(r))
}

func (i fail2banUpgradeRunIntent) facts() (f fail2banUpgradeRunFacts, err error) {
	f.Step = 1
	var marker fail2banUpgradeActivationMarker
	err = readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), &marker)
	if err != nil && !os.IsNotExist(err) {
		return f, err
	}
	f.Execution = err == nil
	if f.Execution && marker != i.marker() {
		return f, errors.New("整体升级执行标识变化")
	}
	last := i.CreatedAt
	gap := false
	for step := 2; step <= 5; step++ {
		var s fail2banUpgradeRunStage
		err = readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "stage-"+strconv.Itoa(step)+".json"), &s)
		if os.IsNotExist(err) {
			gap = true
			continue
		}
		if err != nil {
			return f, err
		}
		if gap || !f.Execution || s.fail2banUpgradeActivationMarker != i.marker() || s.Step != step || s.At < last || s.At > time.Now().Unix()+300 {
			return f, errors.New("整体升级阶段链不连续或与原授权冲突")
		}
		source, e := i.stageSource(step)
		if e != nil {
			return f, e
		}
		if source != s.SourceSHA256 {
			return f, errors.New("整体升级阶段的原子任务证明变化")
		}
		f.Step, last = step, s.At
	}
	var r fail2banUpgradeRunReceipt
	err = readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), &r)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if r.fail2banUpgradeActivationMarker != i.marker() || r.CompletedAt < last || r.CompletedAt > time.Now().Unix()+300 {
		return f, errors.New("整体升级完成回执变化")
	}
	if r.Outcome == "cancelled" {
		if f.Execution || f.Step != 1 || r.SourceSHA256 != "" {
			return f, errors.New("整体升级已执行，不能按未执行取消")
		}
	} else {
		if !f.Execution || r.Outcome != "upgraded" && r.Outcome != "restored" || r.Outcome == "upgraded" && f.Step != 3 || r.Outcome == "restored" && f.Step != 5 {
			return f, errors.New("整体升级完成结果与阶段不匹配")
		}
		source, e := i.completionSource(r.Outcome == "restored")
		if e != nil {
			return f, e
		}
		if source != r.SourceSHA256 {
			return f, errors.New("整体升级完成保护证明变化")
		}
	}
	f.Receipt = &r
	return f, nil
}

func reserveFail2banUpgradeRun(i fail2banUpgradeRunIntent) (resultErr error) {
	store := fail2banUpgradeRuns(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err := fail2banUpgradeActivationQuota(store, true); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(store, ".run-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	if err = writeFail2banUpgradeActivationJSON(filepath.Join(tmp, "intent.json"), i); err != nil {
		return err
	}
	if err = syncDir(tmp); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, i.dir(), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(store)
}

func pendingFail2banUpgradeRun(data string) (*fail2banUpgradeRunIntent, fail2banUpgradeRunFacts, error) {
	var empty fail2banUpgradeRunFacts
	var marker fail2banUpgradeActivationMarker
	err := readFail2banUpgradeActivationJSON(filepath.Join(fail2banUpgradeRuns(data), "current.json"), &marker)
	present := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, empty, err
	}
	if present && (marker.Schema != 1 || !validID(marker.ID) || !fail2banDigest.MatchString(marker.IntentSHA256)) {
		return nil, empty, errors.New("整体升级隔离格式无效")
	}
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return nil, empty, err
	}
	found := !present
	var pending *fail2banUpgradeRunIntent
	facts := empty
	for _, r := range records {
		if r.Kind != fail2banUpgradeRunKind {
			continue
		}
		i, e := readFail2banUpgradeRun(data, r.OperationID)
		if e != nil {
			return nil, empty, e
		}
		f, e := i.facts()
		if e != nil {
			return nil, empty, e
		}
		ack := f.Receipt != nil && sameFail2banUpgradePreparationRecord(r, i.record(f.Receipt))
		if !ack && !pendingFail2banUpgradeRunRecord(r, i.record(nil)) {
			return nil, empty, errors.New("整体升级原审计与意图冲突")
		}
		if present && marker.ID == i.Request.OperationID {
			if marker != i.marker() {
				return nil, empty, errors.New("整体升级隔离摘要变化")
			}
			found = true
		}
		if ack {
			continue
		}
		if !present || marker != i.marker() || pending != nil {
			return nil, empty, errors.New("整体升级缺少唯一隔离")
		}
		copy := i
		pending, facts = &copy, f
	}
	if !found {
		i, e := readFail2banUpgradeRun(data, marker.ID)
		if e != nil || marker != i.marker() {
			return nil, empty, errors.Join(errors.New("整体升级隔离缺少原意图"), e)
		}
		f, e := i.facts()
		if e != nil {
			return nil, empty, e
		}
		if _, e = (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(marker.ID); !os.IsNotExist(e) {
			return nil, empty, errors.Join(errors.New("整体升级隔离 UUID 存在其他审计"), e)
		}
		if f.Execution || f.Receipt != nil || f.Step != 1 {
			return nil, empty, errors.New("整体升级已有执行材料但原审计丢失，不重建授权")
		}
		pending, facts = &i, f
	}
	return pending, facts, nil
}

// Returns the only parent record a child may ignore in conflict scans.
func fail2banUpgradeRunAdmission(data, allowed string) (string, error) {
	i, f, err := pendingFail2banUpgradeRun(data)
	if err != nil || i == nil {
		return "", err
	}
	if i.Request.OperationID == allowed || f.Execution && f.Receipt == nil && i.child(f.Step) == allowed {
		return i.Request.OperationID, nil
	}
	return "", errors.New("Fail2ban 整体升级尚未完成，禁止冲突操作，须沿原父任务续办")
}

func fail2banUpgradeRunIdle(data, allowed string) error {
	_, err := fail2banUpgradeRunAdmission(data, allowed)
	return err
}

func fail2banUpgradeRunActions(data string) error {
	i, f, err := pendingFail2banUpgradeRun(data)
	if err != nil || i == nil {
		return err
	}
	if !f.Execution || f.Receipt != nil || f.Step != 3 && f.Step != 5 {
		return ErrBusy
	}
	a, af, err := pendingFail2banUpgradeActivation(data)
	if err != nil {
		return err
	}
	if a == nil || a.Request.OperationID != i.child(f.Step) || af.Started == nil || af.Stop != nil || af.Receipt != nil {
		return ErrBusy
	}
	return nil
}
