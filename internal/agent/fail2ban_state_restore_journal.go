package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

func readFail2banStateRestoreJournal(j *Journal, id string) (Record, error) {
	var out Record
	err := readFail2banNginxJSON(filepath.Join(j.Dir, id+".json"), &out, 256<<10)
	return out, err
}

func noFail2banStateRestoreExecution(i fail2banStateRestoreIntent) error {
	for _, name := range []string{"ready.json", "revert.json", "receipt.json", "exchange"} {
		if _, err := os.Lstat(filepath.Join(i.dir(), name)); !os.IsNotExist(err) {
			return errors.Join(errors.New("恢复审计缺失或当前指针变化且存在执行材料，不重新创建授权"), err)
		}
	}
	return nil
}

func beginFail2banStateRestore(ctx context.Context, in Fail2banStateRestoreOptions, j *Journal) (fail2banStateRestoreIntent, error) {
	var out fail2banStateRestoreIntent
	if _, err := readFail2banStateRestoreJournal(j, in.OperationID); !os.IsNotExist(err) {
		return out, errors.Join(errors.New("恢复 UUID 已存在审计记录或无法确认，不复用"), err)
	}
	t, m, err := planFail2banStateRestore(ctx, in.DataDir, in.SnapshotID)
	if err != nil {
		return out, err
	}
	if t.hash() != in.Target {
		return out, errors.New("状态恢复目标已变化，须重新预览")
	}
	out = fail2banStateRestoreIntent{Schema: 1, ID: in.OperationID, CreatedAt: time.Now().Unix(), DataDir: in.DataDir, Target: in.Target, Input: t, After: m.Files}
	if err = out.validate(in.DataDir, in.OperationID); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	store := fail2banStateRestores(in.DataDir)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	var before, after int64
	for _, file := range t.Before {
		before += file.Size
	}
	for _, file := range m.Files {
		after += file.Size
	}
	add := true
	if _, err = os.Lstat(out.dir()); err == nil {
		add = false
		if err = fail2banStatePrivateDir(out.dir(), false); err != nil {
			return fail2banStateRestoreIntent{}, err
		}
		f, e := os.Open(out.dir())
		if e != nil {
			return fail2banStateRestoreIntent{}, e
		}
		entries, readErr := f.ReadDir(1)
		closeErr := f.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) != 0 {
			return fail2banStateRestoreIntent{}, errors.Join(errors.New("恢复 UUID 目录含无意图材料，保留现场"), readErr, closeErr)
		}
	} else if !os.IsNotExist(err) {
		return fail2banStateRestoreIntent{}, err
	}
	if err = fail2banStateQuota(store, max(before, after)+(2<<20), add); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	if add {
		if err = os.Mkdir(out.dir(), 0700); err != nil {
			return fail2banStateRestoreIntent{}, err
		}
	}
	raw, err := fail2banStateJSON(out)
	if err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	if err = writeFail2banJailImmutable(filepath.Join(out.dir(), "intent.json"), raw, fail2banStateManifestLimit); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	if err = syncDir(store); err != nil {
		return fail2banStateRestoreIntent{}, err
	}
	return out, nil
}

func ensureFail2banStateRestoreJournal(i fail2banStateRestoreIntent, j *Journal) error {
	receipt, err := i.receipt()
	if err != nil {
		return err
	}
	current, err := currentFail2banStateRestore(i.DataDir)
	if err != nil {
		return err
	}
	if receipt == nil && (current == nil || *current != i.marker()) {
		if err = fail2banStateRestoreAdmission(i.DataDir, ""); err != nil {
			return err
		}
		if err = noFail2banStateRestoreExecution(i); err != nil {
			return err
		}
		if err = rootJSONWrite(filepath.Join(fail2banStateRestores(i.DataDir), "current.json"), i.marker(), 4096); err != nil {
			return err
		}
		marker := i.marker()
		current = &marker
	}
	r, err := readFail2banStateRestoreJournal(j, i.ID)
	if os.IsNotExist(err) {
		if receipt != nil {
			return errors.New("已完成恢复缺少原审计，不重新生成历史记录")
		}
		if err = noFail2banStateRestoreExecution(i); err != nil {
			return err
		}
		return j.Put(i.record(nil))
	}
	if err != nil {
		return err
	}
	if receipt != nil && sameFail2banStateRestoreRecord(r, i.record(receipt)) {
		return nil
	}
	if current == nil || *current != i.marker() || !samePendingFail2banStateRestoreRecord(r, i.record(nil)) {
		return errors.New("状态恢复原审计或当前意图冲突，停止修改")
	}
	return nil
}

func acknowledgeFail2banStateRestore(i fail2banStateRestoreIntent, j *Journal, receipt *fail2banStateRestoreReceipt) error {
	r, err := readFail2banStateRestoreJournal(j, i.ID)
	if err != nil {
		return err
	}
	if sameFail2banStateRestoreRecord(r, i.record(receipt)) {
		return nil
	}
	if !samePendingFail2banStateRestoreRecord(r, i.record(nil)) {
		return errors.New("状态恢复完成前原审计变化，不覆盖审计")
	}
	return j.Put(i.record(receipt))
}

func ReadFail2banStateRestoreStatus(parent context.Context, in Fail2banStateRestoreOptions) (Fail2banStateRestoreStatus, error) {
	var out Fail2banStateRestoreStatus
	unlock, err := fail2banStateSnapshotAccess(Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: in.OperationID})
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = parent.Err(); err != nil {
		return out, err
	}
	i, err := readFail2banStateRestore(in.DataDir, in.OperationID)
	if err != nil {
		return out, err
	}
	receipt, err := i.receipt()
	if err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	r, err := readFail2banStateRestoreJournal(j, i.ID)
	if os.IsNotExist(err) && receipt == nil {
		out = i.status(i.record(nil), nil)
		out.State, out.Stage, out.Error = "recovery_required", "intent_reserved", "原意图尚无审计确认，须沿原 UUID 续办"
		if noFail2banStateRestoreExecution(i) != nil {
			out.Stage, out.Error = "journal_missing", "执行材料存在但原审计缺失，保留现场，不重新生成授权"
		}
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if receipt != nil && sameFail2banStateRestoreRecord(r, i.record(receipt)) {
		return i.status(r, receipt), nil
	}
	if !samePendingFail2banStateRestoreRecord(r, i.record(nil)) {
		return out, errors.New("状态恢复审计与原意图不匹配")
	}
	out = i.status(r, receipt)
	if receipt != nil {
		out.State, out.Stage, out.Error = "recovery_required", "completion_unacknowledged", "目录结果已有完成证明，审计尚未确认；须沿原 UUID 续办"
	} else if reverting, e := i.reverting(); e != nil {
		return Fail2banStateRestoreStatus{}, e
	} else if reverting {
		out.Stage = "reverting"
	}
	return out, nil
}
