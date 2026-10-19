package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func readFail2banUpgradeQuiesce(data, id string) (fail2banUpgradeQuiesceIntent, fail2banUpgradePreparation, error) {
	var i fail2banUpgradeQuiesceIntent
	var p fail2banUpgradePreparation
	if !validID(id) {
		return i, p, errors.New("升级停止 UUID 无效")
	}
	dir := filepath.Join(fail2banUpgradeQuiescences(data), id)
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, p, err
	}
	if err := readFail2banUpgradeSwitchJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, p, err
	}
	p, receipt, err := readFail2banUpgradePreparation(data, i.Request.PreparationID, filepath.Join(fail2banUpgradePreparations(data), i.Request.PreparationID))
	if err != nil {
		return i, p, err
	}
	if err = i.validate(data, id, p, receipt); err != nil {
		return i, p, err
	}
	return i, p, nil
}

func (i fail2banUpgradeQuiesceIntent) facts(p fail2banUpgradePreparation) (f fail2banUpgradeQuiesceFacts, err error) {
	read := func(name string, out any) (bool, error) {
		err := readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), name), out)
		if os.IsNotExist(err) {
			return false, nil
		}
		return err == nil, err
	}
	var execution fail2banUpgradeActivationMarker
	if f.Execution, err = read("execution.json", &execution); err != nil {
		return f, err
	}
	if f.Execution && execution != i.marker() {
		return f, errors.New("升级停止执行授权变化")
	}
	var stopped fail2banUpgradeQuiesceStopped
	if present, e := read("stopped.json", &stopped); e != nil {
		return f, e
	} else if present {
		service := stopped.Service
		if !f.Execution || stopped.fail2banUpgradeActivationMarker != i.marker() || stopped.At < i.CreatedAt || stopped.At > time.Now().Unix()+300 || !service.Available || service.ID != fail2banManagedService || service.Load != "loaded" || service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" || !i.stoppedInvocation(stopped.Invocation) || !fail2banDigest.MatchString(stopped.FilesSHA256) {
			return f, errors.New("升级停止回执与原服务不匹配")
		}
		f.Stopped = &stopped
	}
	var receipt fail2banUpgradeQuiesceReceipt
	if present, e := read("receipt.json", &receipt); e != nil {
		return f, e
	} else if present {
		if receipt.fail2banUpgradeActivationMarker != i.marker() || receipt.CompletedAt < i.CreatedAt || receipt.CompletedAt > time.Now().Unix()+300 {
			return f, errors.New("升级停止完成回执无效")
		}
		switch receipt.Outcome {
		case "cancelled":
			if f.Execution || f.Stopped != nil || receipt.SnapshotReceiptSHA256 != "" || receipt.PreparationSHA256 != "" || receipt.Bans != nil {
				return f, errors.New("已进入停止执行，不得按未执行取消")
			}
		case "prepared":
			if f.Stopped == nil || receipt.CompletedAt < f.Stopped.At || receipt.Bans == nil || !fail2banDigest.MatchString(receipt.Bans.SHA256) || receipt.Bans.Count < 0 || receipt.Bans.ObservedAt < f.Stopped.At || receipt.Bans.ObservedAt > receipt.CompletedAt {
				return f, errors.New("升级停止缺少快照封禁核对证明")
			}
			var r fail2banStateReceipt
			if e = readFail2banNginxJSON(filepath.Join(fail2banStateDir(i.Request.DataDir), i.SnapshotID, "receipt.json"), &r, 16<<10); e != nil {
				return f, e
			}
			if e = r.validate(i.Request.DataDir, i.SnapshotID); e != nil {
				return f, e
			}
			if r.CreatedAt < f.Stopped.At || r.CreatedAt > receipt.CompletedAt || r.InstallationID != p.Basis.Current.OperationID || r.EventID != p.Basis.Current.EventID || r.Component != fail2banUpgradeComponent(&p.Basis.Current) || r.MachineID != i.MachineID || receipt.SnapshotReceiptSHA256 != fail2banUpgradeGrantHash("quiesce-snapshot", r) {
				return f, errors.New("升级停止快照不属于原安装或完成回执")
			}
			next, proof, e := readFail2banUpgradePreparation(i.Request.DataDir, i.StoppedPreparationID, filepath.Join(fail2banUpgradePreparations(i.Request.DataDir), i.StoppedPreparationID))
			if e != nil {
				return f, e
			}
			wanted := p.Request
			wanted.OperationID, wanted.Target = i.StoppedPreparationID, next.Basis.hash()
			if next.Request != wanted || next.CreatedAt < f.Stopped.At || next.CreatedAt > receipt.CompletedAt || next.hash() != receipt.PreparationSHA256 || !i.sameSelection(next.Basis, p) || !fail2banUpgradeOneOf(next.Basis.Service, f.Stopped.Service) || next.Basis.Invocation != f.Stopped.Invocation || next.Recovery.hash() != i.Recovery.hash() {
				return f, errors.New("升级停止后的准备超出原候选或批准范围")
			}
			audit, e := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(i.StoppedPreparationID)
			if e != nil || !sameFail2banUpgradePreparationRecord(audit, next.record(proof)) {
				return f, errors.Join(errors.New("停止态升级准备缺少独立审计"), e)
			}
		default:
			return f, errors.New("升级停止完成结果未知")
		}
		f.Receipt = &receipt
	}
	inode, e := strconv.ParseUint(i.SocketInode, 10, 64)
	if e != nil || inode == 0 {
		return f, errors.New("升级停止的原 Socket 身份无效")
	}
	return f, nil
}

func reserveFail2banUpgradeQuiesce(i fail2banUpgradeQuiesceIntent) (resultErr error) {
	store := fail2banUpgradeQuiescences(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err := fail2banUpgradeSwitchQuota(store, true); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(store, ".quiesce-")
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
