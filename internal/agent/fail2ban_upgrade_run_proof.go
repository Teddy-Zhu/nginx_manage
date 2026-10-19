package agent

import (
	"errors"
	"path/filepath"
)

var errFail2banUpgradeRunChildPending = errors.New("整体升级的启动子任务尚未完成")

// These are immutable child facts, not live observations. They are safe to
// authenticate from admission and after an engine has changed its database.
func (i fail2banUpgradeRunIntent) quiescence() (fail2banUpgradeQuiesceIntent, *fail2banUpgradeQuiesceReceipt, error) {
	q, p, err := readFail2banUpgradeQuiesce(i.Request.DataDir, i.QuiesceID)
	if err != nil {
		return q, nil, err
	}
	if q.Request.PreparationID != i.Request.PreparationID || q.Request.Target != i.Request.Target || q.CreatedAt < i.CreatedAt {
		return q, nil, errors.New("整体升级的停止子任务与原准备不匹配")
	}
	f, err := q.facts(p)
	if err != nil {
		return q, nil, err
	}
	if f.Receipt == nil || f.Receipt.Outcome != "prepared" {
		return q, nil, errors.New("整体升级尚无已完成的停止与状态捕获")
	}
	return q, f.Receipt, i.childAudit(q.Request.OperationID, q.record(f.Receipt))
}

func (i fail2banUpgradeRunIntent) switched() (fail2banUpgradeSwitch, *fail2banUpgradeSwitchReceipt, error) {
	var s fail2banUpgradeSwitch
	q, qr, err := i.quiescence()
	if err != nil {
		return s, nil, err
	}
	s, err = readFail2banUpgradeSwitch(i.Request.DataDir, i.SwitchID)
	if err != nil {
		return s, nil, err
	}
	if s.Request.PreparationID != q.StoppedPreparationID || s.Request.SnapshotID != q.SnapshotID || s.Request.Target != qr.PreparationSHA256 || s.CreatedAt < qr.CompletedAt {
		return s, nil, errors.New("整体升级的切换子任务与原停止捕获不匹配")
	}
	u, err := s.undo()
	if err != nil {
		return s, nil, err
	}
	r, err := s.receipt()
	if err != nil {
		return s, nil, err
	}
	if u != nil || r == nil || r.Outcome != "selected" {
		return s, nil, errors.New("整体升级尚无完整候选选择，或切换已撤回")
	}
	return s, r, i.childAudit(i.SwitchID, s.record(r, nil))
}

func (i fail2banUpgradeRunIntent) activated(restored bool) (fail2banUpgradeActivationIntent, fail2banUpgradeActivationFacts, error) {
	id, switchID, restoreID := i.ActivationID, i.SwitchID, ""
	if restored {
		id, switchID, restoreID = i.RecoveryActivationID, "", i.RestoreID
	}
	a, _, err := readFail2banUpgradeActivation(i.Request.DataDir, id)
	if err != nil {
		return a, fail2banUpgradeActivationFacts{}, err
	}
	r := a.Request
	if r.SwitchID != switchID || r.RestoreID != restoreID || r.NginxBinary != i.Request.NginxBinary || r.NginxWorker != i.Request.NginxWorker || r.NginxContainer != i.Request.NginxContainer || a.NginxRuntimeSHA256 != i.NginxRuntimeSHA256 || a.CreatedAt < i.CreatedAt {
		return a, fail2banUpgradeActivationFacts{}, errors.New("整体升级的启动子任务或 Nginx 来源不匹配")
	}
	f, err := a.facts()
	if err != nil {
		return a, f, err
	}
	if f.Receipt == nil {
		audit, e := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(id)
		if e != nil || !pendingFail2banUpgradeActivationRecord(audit, a.record(nil)) {
			return a, f, errors.Join(errors.New("整体升级启动子任务缺少原审计"), e)
		}
		return a, f, errFail2banUpgradeRunChildPending
	}
	return a, f, i.childAudit(id, a.record(f.Receipt))
}

func (i fail2banUpgradeRunIntent) restored() (fail2banUpgradeRestoreIntent, *fail2banUpgradeRestoreReceipt, error) {
	r, _, err := readFail2banUpgradeRestore(i.Request.DataDir, i.RestoreID)
	if err != nil {
		return r, nil, err
	}
	if r.Request.ActivationID != i.ActivationID || r.CreatedAt < i.CreatedAt {
		return r, nil, errors.New("整体升级的恢复子任务不匹配")
	}
	f, err := r.facts()
	if err != nil {
		return r, nil, err
	}
	if f.Receipt == nil || f.Receipt.Outcome != "restored" {
		return r, nil, errors.New("整体升级尚未恢复原代码、配置和数据库")
	}
	return r, f.Receipt, i.childAudit(i.RestoreID, r.record(f.Receipt))
}

func (i fail2banUpgradeRunIntent) childAudit(id string, expected Record) error {
	a, err := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(id)
	if err != nil || !sameFail2banUpgradePreparationRecord(a, expected) {
		return errors.Join(errors.New("整体升级缺少匹配的原子任务终态审计"), err)
	}
	return nil
}

func (i fail2banUpgradeRunIntent) stageSource(step int) (string, error) {
	switch step {
	case 2:
		q, r, err := i.quiescence()
		if err != nil {
			return "", err
		}
		return fail2banUpgradeGrantHash("run-quiescence", struct {
			Intent  string
			Receipt *fail2banUpgradeQuiesceReceipt
		}{q.hash(), r}), nil
	case 3:
		s, r, err := i.switched()
		if err != nil {
			return "", err
		}
		return fail2banUpgradeGrantHash("run-switch", struct {
			Intent  string
			Receipt *fail2banUpgradeSwitchReceipt
		}{s.hash(), r}), nil
	case 4:
		a, f, err := i.activated(false)
		if err != nil {
			return "", err
		}
		if f.Receipt.Outcome != "stopped" {
			return "", errors.New("整体升级不能恢复已通过保护核对的候选")
		}
		return fail2banUpgradeGrantHash("run-failed-activation", struct {
			Intent  string
			Receipt *fail2banUpgradeActivationReceipt
		}{a.hash(), f.Receipt}), nil
	case 5:
		r, receipt, err := i.restored()
		if err != nil {
			return "", err
		}
		return fail2banUpgradeGrantHash("run-restoration", struct {
			Intent  string
			Receipt *fail2banUpgradeRestoreReceipt
		}{r.hash(), receipt}), nil
	}
	return "", errors.New("整体升级阶段无效")
}

func (i fail2banUpgradeRunIntent) completionSource(restored bool) (string, error) {
	a, f, err := i.activated(restored)
	if err != nil {
		return "", err
	}
	if f.Receipt.Outcome != "verified" {
		return "", errors.New("整体升级尚无完整实时保护核对证明")
	}
	return fail2banUpgradeGrantHash("run-verified-activation", struct {
		Intent  string
		Receipt *fail2banUpgradeActivationReceipt
	}{a.hash(), f.Receipt}), nil
}
