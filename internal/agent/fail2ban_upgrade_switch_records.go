package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func readFail2banUpgradeSwitchJSON(path string, out any) error {
	raw, err := listenerRead(path, fail2banUpgradeSwitchLimit)
	if err != nil {
		return err
	}
	if err = decodeFail2banNginxJSON(raw, out); err != nil {
		return err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("升级切换材料字段不完整或格式已变化")
	}
	return nil
}

func writeFail2banUpgradeSwitchJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(path, raw, fail2banUpgradeSwitchLimit)
}

func readFail2banUpgradeSwitch(data, id string) (fail2banUpgradeSwitch, error) {
	var i fail2banUpgradeSwitch
	if !validID(id) {
		return i, errors.New("升级切换操作标识无效")
	}
	dir := filepath.Join(fail2banUpgradeSwitches(data), id)
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, err
	}
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, err
	}
	return i, i.validate(data, id)
}

func (i fail2banUpgradeSwitch) undo() (*fail2banUpgradeSwitchUndo, error) {
	var u fail2banUpgradeSwitchUndo
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "undo.json"), &u); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := i.validateUndo(u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (i fail2banUpgradeSwitch) receipt() (*fail2banUpgradeSwitchReceipt, error) {
	var r fail2banUpgradeSwitchReceipt
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "receipt.json"), &r); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	u, err := i.undo()
	if err != nil {
		return nil, err
	}
	expected := i.After
	if r.Outcome == "reverted" && u != nil {
		expected = u.Managed
	} else if r.Outcome != "selected" || u != nil {
		return nil, errors.New("升级切换完成结果与补偿意图不匹配")
	}
	if r.fail2banUpgradeSwitchMarker != i.marker() || r.CompletedAt < i.CreatedAt || r.CompletedAt > time.Now().Unix()+300 || r.ManagedEvent != expected.EventID || r.ManagedSHA256 != fail2banUpgradeGrantHash("managed", expected) {
		return nil, errors.New("升级切换完成回执无效")
	}
	for _, name := range []string{"execution.json", "handover.json"} {
		var marker fail2banUpgradeSwitchMarker
		if err = readFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), name), &marker); err != nil {
			return nil, err
		}
		if marker != i.marker() {
			return nil, errors.New("升级完成回执缺少匹配的执行及交接证明")
		}
	}
	var historical fail2banManagedRecord
	if err = readFail2banUpgradeSwitchJSON(filepath.Join(fail2banManagedDir(i.Request.DataDir), "history", expected.EventID+".json"), &historical); err != nil {
		return nil, err
	}
	if fail2banUpgradeGrantHash("managed", historical) != r.ManagedSHA256 {
		return nil, errors.New("升级切换选择历史与完成回执不匹配")
	}
	return &r, nil
}

func currentFail2banUpgradeSwitch(data string) (*fail2banUpgradeSwitchMarker, error) {
	var m fail2banUpgradeSwitchMarker
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(fail2banUpgradeSwitches(data), "current.json"), &m); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if m.Schema != 1 || !validID(m.ID) || !fail2banDigest.MatchString(m.IntentSHA256) {
		return nil, errors.New("升级切换启动隔离标识无效")
	}
	return &m, nil
}

func pendingFail2banUpgradeSwitchRecord(actual, expected Record) bool {
	if len(actual.Error) > 1024 {
		return false
	}
	if actual.State == "recovery_required" {
		actual.State = expected.State
	}
	actual.Error = ""
	return sameFail2banUpgradePreparationRecord(actual, expected)
}

// Validate durable facts only. Later official startup is allowed to change DB
// bytes; it must not invalidate an already acknowledged stopped selection.
func fail2banUpgradeSwitchRecords(data string, records []Record, allowed string) (string, error) {
	marker, err := currentFail2banUpgradeSwitch(data)
	if err != nil {
		return "", err
	}
	found, pending := marker == nil, ""
	for _, r := range records {
		if r.Kind != fail2banUpgradeSwitchKind {
			continue
		}
		i, err := readFail2banUpgradeSwitch(data, r.OperationID)
		if err != nil {
			return "", err
		}
		u, err := i.undo()
		if err != nil {
			return "", err
		}
		receipt, err := i.receipt()
		if err != nil {
			return "", err
		}
		matches := sameFail2banUpgradePreparationRecord(r, i.record(receipt, u))
		if receipt == nil {
			matches = pendingFail2banUpgradeSwitchRecord(r, i.record(nil, u))
		}
		if !matches {
			unack := i.Request.OperationID == allowed && (pendingFail2banUpgradeSwitchRecord(r, i.record(nil, nil)) || pendingFail2banUpgradeSwitchRecord(r, i.record(nil, u)))
			if !unack {
				return "", errors.New("升级切换原意图、审计或完成回执不匹配")
			}
		}
		if marker != nil && marker.ID == i.Request.OperationID {
			if *marker != i.marker() {
				return "", errors.New("升级切换当前摘要不匹配")
			}
			found = true
		}
		if receipt == nil || !matches {
			if marker == nil || *marker != i.marker() || pending != "" && pending != i.Request.OperationID {
				return "", errors.New("升级切换缺少隔离或存在多个待决操作")
			}
			pending = i.Request.OperationID
		}
	}
	if !found {
		if marker.ID != allowed {
			return "", errors.New("升级切换隔离已发布但审计未完成，须沿原 UUID 续办")
		}
		i, err := readFail2banUpgradeSwitch(data, marker.ID)
		if err != nil || i.marker() != *marker {
			return "", errors.Join(errors.New("升级切换隔离无法核对"), err)
		}
		pending = marker.ID
	}
	return pending, nil
}

func fail2banUpgradeSwitchIdle(data, allowed string) error {
	records, err := fail2banStateRestoreRawRecords(data)
	if err != nil {
		return err
	}
	pending, err := fail2banUpgradeSwitchRecords(data, records, allowed)
	if err != nil {
		return err
	}
	if pending != "" && pending != allowed {
		return errors.New("Fail2ban 升级切换尚未结束，禁止启动或冲突操作，须沿原 UUID 续办或撤回")
	}
	return nil
}

func fail2banUpgradeTransferredParent(data string, r Record) (bool, error) {
	i, err := readFail2banUpgradeSwitch(data, r.Fail2banUpgradeID)
	if err != nil {
		return false, err
	}
	var handover fail2banUpgradeSwitchMarker
	if err = readFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "handover.json"), &handover); err != nil {
		return false, err
	}
	if handover != i.marker() {
		return false, errors.New("升级切换交接证明不匹配")
	}
	var execution fail2banUpgradeSwitchMarker
	if err = readFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "execution.json"), &execution); err != nil {
		return false, err
	}
	if execution != i.marker() {
		return false, errors.New("升级切换执行证明不匹配")
	}
	u, err := i.undo()
	if err != nil {
		return false, err
	}
	receipt, err := i.receipt()
	if err != nil {
		return false, err
	}
	audit, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(i.Request.OperationID)
	if err != nil {
		return false, err
	}
	acknowledged := receipt != nil && sameFail2banUpgradePreparationRecord(audit, i.record(receipt, u))
	if !acknowledged {
		current, err := currentFail2banUpgradeSwitch(data)
		if err != nil {
			return false, err
		}
		if current == nil || *current != i.marker() || !pendingFail2banUpgradeSwitchRecord(audit, i.record(nil, u)) && !pendingFail2banUpgradeSwitchRecord(audit, i.record(nil, nil)) {
			return false, errors.New("持续会话交接缺少原切换审计及隔离")
		}
	}
	expected, err := i.transferredParent(r.OperationID)
	return err == nil && sameFail2banUpgradePreparationRecord(r, expected), err
}

func fail2banUpgradeTransferredRuntime(data string, parent Record, event *fail2banHostSyncEvent, runtime *fail2banHostRuntime) bool {
	ok, err := fail2banUpgradeTransferredParent(data, parent)
	if err != nil || !ok {
		return false
	}
	i, err := readFail2banUpgradeSwitch(data, parent.Fail2banUpgradeID)
	return err == nil && i.Prepared.Basis.HostSync != nil && i.Prepared.Basis.HostSync.ID == event.ID && i.Prepared.Recovery.Runtime != nil && fail2banUpgradeGrantHash("runtime", runtime) == fail2banUpgradeGrantHash("runtime", i.Prepared.Recovery.Runtime)
}
