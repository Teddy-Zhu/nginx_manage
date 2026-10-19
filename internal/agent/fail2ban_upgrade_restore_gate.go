package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Only durable original material authenticates a fence; status never reopens a
// terminal operation merely because the live database has since changed.
func pendingFail2banUpgradeRestore(data string) (*fail2banUpgradeRestoreIntent, fail2banUpgradeRestoreFacts, error) {
	var marker fail2banUpgradeActivationMarker
	var empty fail2banUpgradeRestoreFacts
	err := readFail2banUpgradeActivationJSON(filepath.Join(fail2banUpgradeRestores(data), "current.json"), &marker)
	present := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, empty, err
	}
	if present && (marker.Schema != 1 || !validID(marker.ID) || !fail2banDigest.MatchString(marker.IntentSHA256)) {
		return nil, empty, errors.New("升级恢复隔离格式无效")
	}
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return nil, empty, err
	}
	found := !present
	var active *fail2banUpgradeRestoreIntent
	facts := empty
	for _, r := range records {
		if r.Kind != fail2banUpgradeRestoreKind {
			continue
		}
		i, _, e := readFail2banUpgradeRestore(data, r.OperationID)
		if e != nil {
			return nil, empty, e
		}
		f, e := i.facts()
		if e != nil {
			return nil, empty, e
		}
		done := f.Receipt != nil && sameFail2banUpgradePreparationRecord(r, i.record(f.Receipt))
		if !done && !pendingFail2banUpgradeRestoreRecord(r, i.record(nil)) {
			return nil, empty, errors.New("升级恢复原审计与意图冲突")
		}
		if present && marker.ID == i.Request.OperationID {
			if marker != i.marker() {
				return nil, empty, errors.New("升级恢复隔离摘要变化")
			}
			found = true
		}
		if done {
			continue
		}
		if !present || marker != i.marker() || active != nil {
			return nil, empty, errors.New("升级恢复缺少唯一隔离")
		}
		copy := i
		active, facts = &copy, f
	}
	if !found {
		i, _, e := readFail2banUpgradeRestore(data, marker.ID)
		if e != nil || marker != i.marker() {
			return nil, empty, errors.Join(errors.New("升级恢复隔离缺少原意图"), e)
		}
		f, e := i.facts()
		if e != nil {
			return nil, empty, e
		}
		if _, e = (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(marker.ID); !os.IsNotExist(e) {
			return nil, empty, errors.Join(errors.New("升级恢复隔离的 UUID 已有其他审计"), e)
		}
		if f.Execution || f.State != nil || f.Receipt != nil {
			return nil, empty, errors.New("升级恢复已有执行材料但原审计丢失，不重建授权")
		}
		active, facts = &i, f
	}
	return active, facts, nil
}

func fail2banUpgradeRestoreIdle(data, allowed string) error {
	i, _, err := pendingFail2banUpgradeRestore(data)
	if err != nil {
		return err
	}
	if i != nil && i.Request.OperationID != allowed {
		return errors.New("Fail2ban 升级恢复尚未确认，须沿原 UUID 续办")
	}
	return nil
}

func fail2banUpgradeRestoreTransferredParent(data string, parent Record) (bool, error) {
	i, _, err := readFail2banUpgradeRestore(data, parent.Fail2banUpgradeID)
	if err != nil {
		return false, err
	}
	f, err := i.facts()
	if err != nil {
		return false, err
	}
	if !f.Execution {
		return false, errors.New("持续会话交接缺少升级恢复的原执行授权")
	}
	expected := i.transferredParent()
	if expected == nil || !sameFail2banUpgradePreparationRecord(parent, *expected) {
		return false, errors.New("持续会话交接偏离升级恢复的原候选审计")
	}
	audit, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(i.Request.OperationID)
	if err != nil {
		return false, err
	}
	if f.Receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return true, nil
	}
	if !pendingFail2banUpgradeRestoreRecord(audit, i.record(nil)) {
		return false, errors.New("持续会话交接缺少升级恢复的原审计")
	}
	var current fail2banUpgradeActivationMarker
	if err = readFail2banUpgradeActivationJSON(filepath.Join(fail2banUpgradeRestores(data), "current.json"), &current); err != nil {
		return false, err
	}
	return current == i.marker(), nil
}

// Historical status authenticates durable facts; later legitimate starts or
// database changes cannot rewrite this stopped recovery outcome.
func ReadFail2banUpgradeRestore(ctx context.Context, data, scope, id string) (Fail2banUpgradeRestore, error) {
	var out Fail2banUpgradeRestore
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	i, _, err := readFail2banUpgradeRestore(data, id)
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
	if !pendingFail2banUpgradeRestoreRecord(audit, i.record(nil)) {
		return out, errors.New("升级恢复原审计与持久材料冲突")
	}
	if audit.State == "recovery_required" {
		out.State, out.Reason = audit.State, audit.Error
	}
	return out, nil
}

func (s *Server) resumeFail2banUpgradeRestore(ctx context.Context, gate *maintenanceGate) error {
	i, f, err := pendingFail2banUpgradeRestore(s.DataDir)
	if err != nil || i == nil || !f.Execution && f.Receipt == nil {
		return err
	}
	audit, err := (&Journal{Dir: filepath.Join(s.DataDir, "agent", "operations")}).Get(i.Request.OperationID)
	if err != nil {
		return err
	}
	if !pendingFail2banUpgradeRestoreRecord(audit, i.record(nil)) {
		return nil
	}
	leave, ok := gate.enter(true)
	if !ok {
		return nil
	}
	defer leave()
	call, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	_, err = ResumeFail2banUpgradeRestore(call, s.DataDir, "host", i.Request.OperationID)
	return err
}
