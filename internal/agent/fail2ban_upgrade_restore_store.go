package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func readFail2banUpgradeRestoreSource(data, id string) (fail2banUpgradeActivationIntent, fail2banUpgradeSwitch, fail2banUpgradeActivationFacts, error) {
	var s fail2banUpgradeSwitch
	a, err := readFail2banUpgradeActivationIntent(data, id)
	if err != nil {
		return a, s, fail2banUpgradeActivationFacts{}, err
	}
	if a.Request.RestoreID != "" || !validID(a.Request.SwitchID) {
		return a, s, fail2banUpgradeActivationFacts{}, errors.New("原版本恢复只接受升级候选启动，不能递归引用恢复启动")
	}
	s, receipt, err := readFail2banUpgradeVerificationSwitch(data, a.Request.SwitchID)
	if err != nil {
		return a, s, fail2banUpgradeActivationFacts{}, err
	}
	if err = a.validate(data, id, selectionFromFail2banUpgradeSwitch(s, receipt)); err != nil {
		return a, s, fail2banUpgradeActivationFacts{}, err
	}
	// Reject other outcomes before facts can follow a successful activation's
	// proof reference. Recovery dependencies must terminate at a stopped source.
	var stopped fail2banUpgradeActivationReceipt
	if err = readFail2banUpgradeActivationJSON(filepath.Join(a.dir(), "receipt.json"), &stopped); err != nil {
		return a, s, fail2banUpgradeActivationFacts{}, err
	}
	if stopped.Outcome != "stopped" {
		return a, s, fail2banUpgradeActivationFacts{}, errors.New("升级恢复只接受已停止候选，不能引用成功启动的保护证明")
	}
	f, err := a.facts()
	if err != nil {
		return a, s, f, err
	}
	if f.Receipt == nil || f.Receipt.Outcome != "stopped" {
		return a, s, f, errors.New("升级恢复须先完成原候选停止；已通过保护核对的升级不使用失败恢复授权")
	}
	r, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if err != nil || !sameFail2banUpgradePreparationRecord(r, a.record(f.Receipt)) {
		return a, s, f, errors.Join(errors.New("升级恢复缺少原候选停止的完整审计"), err)
	}
	return a, s, f, nil
}

func readFail2banUpgradeRestore(data, id string) (fail2banUpgradeRestoreIntent, fail2banUpgradeSwitch, error) {
	var i fail2banUpgradeRestoreIntent
	var s fail2banUpgradeSwitch
	if !validID(id) {
		return i, s, errors.New("升级恢复 UUID 无效")
	}
	dir := filepath.Join(fail2banUpgradeRestores(data), id)
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, s, err
	}
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, s, err
	}
	a, s, f, err := readFail2banUpgradeRestoreSource(data, i.Request.ActivationID)
	if err != nil {
		return i, s, err
	}
	return i, s, i.validate(data, id, a, s, f)
}

func (i fail2banUpgradeRestoreIntent) facts() (f fail2banUpgradeRestoreFacts, err error) {
	var marker fail2banUpgradeActivationMarker
	err = readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "execution.json"), &marker)
	if err != nil && !os.IsNotExist(err) {
		return f, err
	}
	f.Execution = err == nil
	if f.Execution && marker != i.marker() {
		return f, errors.New("升级恢复执行授权变化")
	}
	state := i.stateRestore()
	ready, err := state.ready()
	if err != nil {
		return f, err
	}
	f.State, err = state.receipt()
	if err != nil {
		return f, err
	}
	if !f.Execution {
		if err = i.unexecuted(); err != nil {
			return f, err
		}
		if ready != nil || f.State != nil {
			return f, errors.New("升级恢复未记录执行但已有状态交换证明")
		}
		if _, err = os.Lstat(filepath.Join(state.dir(), "exchange")); !os.IsNotExist(err) {
			return f, errors.Join(errors.New("升级恢复未记录执行但已有状态交换材料"), err)
		}
	}
	if f.State != nil && (f.State.Outcome != "restored" || f.State.CompletedAt < i.CreatedAt) {
		return f, errors.New("升级恢复状态交换结果不匹配")
	}
	var receipt fail2banUpgradeRestoreReceipt
	err = readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "receipt.json"), &receipt)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if receipt.fail2banUpgradeActivationMarker != i.marker() || receipt.CompletedAt < i.CreatedAt || receipt.CompletedAt > time.Now().Unix()+300 {
		return f, errors.New("升级恢复完成回执无效")
	}
	switch receipt.Outcome {
	case "restored":
		if !f.Execution || f.State == nil || receipt.CompletedAt < f.State.CompletedAt || receipt.StateReceiptSHA256 != fail2banUpgradeGrantHash("upgrade-restore-state", f.State) {
			return f, errors.New("升级恢复未完整确认原数据库交换")
		}
		for _, event := range i.events() {
			raw, e := listenerRead(event.path, event.limit)
			if e != nil {
				return f, e
			}
			want, e := json.Marshal(event.value)
			if e != nil || !bytes.Equal(raw, want) {
				return f, errors.Join(errors.New("升级恢复历史事件与完成回执冲突"), e)
			}
		}
	case "cancelled":
		if f.Execution || f.State != nil || receipt.StateReceiptSHA256 != "" {
			return f, errors.New("升级恢复执行后不能按未执行取消")
		}
	default:
		return f, errors.New("升级恢复完成结果未知")
	}
	f.Receipt = &receipt
	return f, nil
}

type fail2banUpgradeRestoreEvent struct {
	path  string
	value any
	limit int64
}

func (i fail2banUpgradeRestoreIntent) events() []fail2banUpgradeRestoreEvent {
	data, u := i.Request.DataDir, i.Undo
	events := []fail2banUpgradeRestoreEvent{{filepath.Join(fail2banManagedDir(data), "history", u.Managed.EventID+".json"), u.Managed, 16384}}
	if u.Nginx != nil {
		events = append(events, fail2banUpgradeRestoreEvent{filepath.Join(fail2banNginxDir(data), "grants", u.Nginx.ID+".json"), u.Nginx, 32 << 10})
	}
	if u.Sources != nil {
		events = append(events, fail2banUpgradeRestoreEvent{filepath.Join(fail2banHostSourcesDir(data), "events", u.Sources.ID+".json"), u.Sources, fail2banHostProtectionBytes})
	}
	if u.Sync != nil {
		events = append(events, fail2banUpgradeRestoreEvent{filepath.Join(fail2banHostSyncDir(data), "events", u.Sync.ID+".json"), u.Sync, fail2banHostProtectionBytes})
	}
	return events
}

func (i fail2banUpgradeRestoreIntent) unexecuted() error {
	for _, event := range i.events() {
		if _, err := os.Lstat(event.path); !os.IsNotExist(err) {
			return errors.Join(errors.New("升级恢复未记录执行但已有本次选择或批准事件"), err)
		}
	}
	if i.Undo.Sync != nil {
		if _, err := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(i.Undo.Sync.ID); !os.IsNotExist(err) {
			return errors.Join(errors.New("升级恢复未记录执行但已有新持续会话审计"), err)
		}
	}
	return nil
}

func reserveFail2banUpgradeRestore(i fail2banUpgradeRestoreIntent) (resultErr error) {
	store := fail2banUpgradeRestores(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err := fail2banUpgradeSwitchQuota(store, true); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(store, ".restore-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	if err = writeFail2banUpgradeSwitchJSON(filepath.Join(tmp, "intent.json"), i); err != nil {
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

func (i fail2banUpgradeRestoreIntent) reserveState() error {
	store := fail2banUpgradeRestoreStates(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	var before, after int64
	for _, file := range i.State.Input.Before {
		before += file.Size
	}
	for _, file := range i.State.After {
		after += file.Size
	}
	_, err := os.Lstat(i.stateRestore().dir())
	add := os.IsNotExist(err)
	if err != nil && !add {
		return err
	}
	reserve := max(before, after) + (2 << 20)
	ready, err := i.stateRestore().ready()
	if err != nil {
		return err
	}
	if ready != nil {
		reserve = 2 << 20
	}
	return fail2banStateQuota(store, reserve, add)
}
