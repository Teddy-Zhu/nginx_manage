package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func (i fail2banUpgradeSwitch) noExecution() error {
	for _, name := range []string{"execution.json", "handover.json", "undo.json", "receipt.json"} {
		if _, err := os.Lstat(filepath.Join(i.dir(), name)); !os.IsNotExist(err) {
			return errors.Join(errors.New("切换审计缺失或隔离变化且存在执行材料，不重新创建授权"), err)
		}
	}
	return nil
}

func ensureFail2banUpgradeSwitchJournal(ctx context.Context, i fail2banUpgradeSwitch, j *Journal, u *fail2banUpgradeSwitchUndo, receipt *fail2banUpgradeSwitchReceipt) error {
	actual, auditErr := j.Get(i.Request.OperationID)
	if auditErr != nil && !os.IsNotExist(auditErr) {
		return auditErr
	}
	if receipt != nil && auditErr == nil && sameFail2banUpgradePreparationRecord(actual, i.record(receipt, u)) {
		return nil
	}
	current, err := currentFail2banUpgradeSwitch(i.Request.DataDir)
	if err != nil {
		return err
	}
	if current == nil || *current != i.marker() {
		if receipt != nil || auditErr == nil {
			return errors.New("切换原审计或执行证明存在但启动隔离变化，不重新取得授权")
		}
		if err = i.noExecution(); err != nil {
			return err
		}
		if err = fail2banUpgradeSwitchAdmission(i.Request.DataDir, ""); err != nil {
			return err
		}
		if err = i.original(ctx); err != nil {
			return err
		}
		if err = rootJSONWrite(filepath.Join(fail2banUpgradeSwitches(i.Request.DataDir), "current.json"), i.marker(), 4096); err != nil {
			return err
		}
	}
	if os.IsNotExist(auditErr) {
		if receipt != nil {
			return errors.New("切换完成证明缺少原审计，保留现场")
		}
		if err = i.noExecution(); err != nil {
			return err
		}
		if err = i.original(ctx); err != nil {
			return err
		}
		return j.Put(i.record(nil, nil))
	}
	if !pendingFail2banUpgradeSwitchRecord(actual, i.record(nil, u)) && !pendingFail2banUpgradeSwitchRecord(actual, i.record(nil, nil)) {
		return errors.New("切换原审计与持久意图冲突，不覆盖审计")
	}
	return nil
}

func ReadFail2banUpgradeSwitchStatus(parent context.Context, data, scope, id string) (Fail2banUpgradeSwitchStatus, error) {
	var out Fail2banUpgradeSwitchStatus
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = parent.Err(); err != nil {
		return out, err
	}
	i, err := readFail2banUpgradeSwitch(data, id)
	if err != nil {
		return out, err
	}
	u, err := i.undo()
	if err != nil {
		return out, err
	}
	receipt, err := i.receipt()
	if err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	r, err := j.Get(id)
	if os.IsNotExist(err) && receipt == nil {
		out = i.status(i.record(nil, u), nil)
		out.State, out.Stage, out.Error = "recovery_required", "intent_reserved", "原意图尚无审计确认，须沿原 UUID 续办"
		if i.noExecution() != nil {
			out.Stage, out.Error = "journal_missing", "执行材料存在但原审计缺失，保留现场，不重新生成授权"
		}
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if receipt != nil && sameFail2banUpgradePreparationRecord(r, i.record(receipt, u)) {
		return i.status(r, receipt), nil
	}
	if !pendingFail2banUpgradeSwitchRecord(r, i.record(nil, u)) && !pendingFail2banUpgradeSwitchRecord(r, i.record(nil, nil)) {
		return out, errors.New("切换状态缺少匹配的原审计")
	}
	current, err := currentFail2banUpgradeSwitch(data)
	if err != nil {
		return out, err
	}
	if current == nil || *current != i.marker() {
		return out, errors.New("未完成切换缺少原启动隔离")
	}
	out = i.status(r, receipt)
	if receipt != nil {
		out.State, out.Stage, out.Error = "recovery_required", "completion_unacknowledged", "停止实例结果已有证明，审计尚未确认，须沿原 UUID 续办"
	} else if u != nil && r.Stage != "reverting" {
		out.State, out.Stage, out.Error = "recovery_required", "undo_unacknowledged", "撤回意图已保存，须沿原 UUID 续办补偿"
	}
	return out, nil
}
