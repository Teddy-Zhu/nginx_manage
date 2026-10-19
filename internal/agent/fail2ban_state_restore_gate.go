package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func sameFail2banStateRestoreRecord(a, b Record) bool {
	a.UpdatedAt, b.UpdatedAt = 0, 0
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func samePendingFail2banStateRestoreRecord(actual, expected Record) bool {
	if actual.State != "running" || actual.Stage != "restoring" || len(actual.Error) > 1024 {
		return false
	}
	actual.Error = ""
	return sameFail2banStateRestoreRecord(actual, expected)
}

func currentFail2banStateRestore(data string) (*fail2banStateRestoreMarker, error) {
	var out fail2banStateRestoreMarker
	if err := readFail2banNginxJSON(filepath.Join(fail2banStateRestores(data), "current.json"), &out, 4096); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if out.Schema != 1 || !validID(out.ID) || !fail2banDigest.MatchString(out.IntentSHA256) {
		return nil, errors.New("Fail2ban 状态恢复启动隔离指针无效")
	}
	return &out, nil
}

// This checks durable facts only. A completed restore must remain admissible
// after a later service start naturally changes the live SQLite files.
func fail2banStateRestoreRecords(data string, records []Record, allowUnack string) (string, error) {
	current, err := currentFail2banStateRestore(data)
	if err != nil {
		return "", err
	}
	pending := ""
	found := current == nil
	for _, r := range records {
		if r.Kind != fail2banStateRestoreKind {
			continue
		}
		i, err := readFail2banStateRestore(data, r.OperationID)
		if err != nil {
			return "", err
		}
		receipt, err := i.receipt()
		if err != nil {
			return "", err
		}
		if !sameFail2banStateRestoreRecord(r, i.record(receipt)) && !(receipt == nil && samePendingFail2banStateRestoreRecord(r, i.record(nil))) {
			if i.ID != allowUnack || receipt == nil || !samePendingFail2banStateRestoreRecord(r, i.record(nil)) {
				return "", errors.New("Fail2ban 状态恢复回执与原意图不匹配")
			}
			pending = i.ID
		}
		if current != nil && current.ID == i.ID {
			if *current != i.marker() {
				return "", errors.New("Fail2ban 状态恢复当前意图摘要不匹配")
			}
			found = true
		}
		if receipt == nil {
			if current == nil || current.ID != i.ID || pending != "" && pending != i.ID {
				return "", errors.New("Fail2ban 状态恢复存在多个意图或缺少启动隔离")
			}
			pending = i.ID
		}
	}
	if !found {
		if current.ID != allowUnack {
			return "", errors.New("Fail2ban 状态恢复意图尚未登记回执，须沿原 UUID 续办")
		}
		i, err := readFail2banStateRestore(data, current.ID)
		if err != nil || i.marker() != *current {
			return "", errors.Join(errors.New("Fail2ban 状态恢复原意图无法核对"), err)
		}
		pending = current.ID
	}
	return pending, nil
}

func fail2banStateRestoreRawRecords(data string) ([]Record, error) {
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	if _, err := os.Lstat(j.Dir); os.IsNotExist(err) {
		return []Record{}, nil
	} else if err != nil {
		return nil, err
	}
	return (&maintenanceGate{journal: j}).rawRecords()
}

func fail2banStateRestoreIdle(data, allowed string) error {
	if err := fail2banUpgradeSwitchIdle(data, allowed); err != nil {
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
		return errors.New("Fail2ban 状态恢复尚未完成，禁止启动或冲突操作，须沿原 UUID 续办或撤回")
	}
	return nil
}
