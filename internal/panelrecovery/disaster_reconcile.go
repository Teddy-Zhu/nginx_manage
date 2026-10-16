package panelrecovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// DisasterReview records the disposition of source work, not a claim that
// remote effects have been undone. Foreign DNS values and grants remain visible.
type DisasterReview struct {
	AbandonSourceTasks           bool `json:"abandon_source_tasks"`
	PreserveTargetAccess         bool `json:"preserve_target_access"`
	KeepAutomationDisabled       bool `json:"keep_automation_disabled"`
	ExternalEffectsRequireReview bool `json:"external_effects_require_review"`
}

func (r DisasterReview) Validate() error {
	if !r.AbandonSourceTasks || !r.PreserveTargetAccess || !r.KeepAutomationDisabled || !r.ExternalEffectsRequireReview {
		return errors.New("恢复对账须明确确认源任务终止、目标可达性保留、自动化停用和外部结果另行核对")
	}
	return nil
}

type DisasterReconciliation struct {
	Schema       int            `json:"schema"`
	OperationID  string         `json:"operation_id"`
	IntentSHA256 string         `json:"intent_sha256"`
	PlanSHA256   string         `json:"plan_sha256"`
	Epoch        string         `json:"epoch"`
	PreparedAt   int64          `json:"prepared_at"`
	Review       DisasterReview `json:"review"`
	File         File           `json:"file"`
	Database     Database       `json:"database"`
	ReportSHA256 string         `json:"report_sha256"`
}

func (r DisasterReconciliation) Validate(i DisasterIntent) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if err := r.Review.Validate(); err != nil {
		return err
	}
	if r.Schema != 1 || r.OperationID != i.OperationID || r.IntentSHA256 != i.SHA256() || r.PlanSHA256 != i.PlanSHA256 || !idValue.MatchString(r.Epoch) || r.PreparedAt < i.CreatedAt || r.PreparedAt >= i.ExpiresAt || r.PreparedAt > time.Now().Unix()+300 || r.File.Name != i.Files[0].Name || r.File.Size < 1 || r.File.Size > DatabaseMax || !hashValue.MatchString(r.File.SHA256) || !hashValue.MatchString(r.ReportSHA256) || r.Database.SchemaVersion != i.Rollback.Manifest.Database.SchemaVersion || !idValue.MatchString(r.Database.NodeID) || r.Database.DesiredRevision != i.PlanID || r.Database.AppliedRevision != i.PlanID || r.Database.HeadVersion < 1 {
		return errors.New("恢复对账材料与原安装批准不一致")
	}
	return nil
}

func (r DisasterReconciliation) SHA256() string { raw, _ := json.Marshal(r); return secure.Hash(raw) }

type DisasterReconciliationProof struct {
	ReconciliationSHA256 string `json:"reconciliation_sha256"`
	VerifiedAt           int64  `json:"verified_at"`
}

func ReadDisasterReconciliation(i DisasterIntent) (out DisasterReconciliation, err error) {
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	raw, err := readReconciliationRecord(filepath.Join(dir, "reconcile.json"))
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return out, errors.New("恢复对账意图不是原规范记录")
	}
	return out, out.Validate(i)
}

func ReadDisasterReconciliationProof(i DisasterIntent, r DisasterReconciliation) (out DisasterReconciliationProof, err error) {
	if err = r.Validate(i); err != nil {
		return out, err
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	raw, err := readReconciliationRecord(filepath.Join(dir, "reconciled-proof.json"))
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) || out.ReconciliationSHA256 != r.SHA256() || out.VerifiedAt < r.PreparedAt || out.VerifiedAt >= i.ExpiresAt || out.VerifiedAt > time.Now().Unix()+300 {
		return out, errors.New("恢复对账核对证明与原批准不一致")
	}
	return out, nil
}

func readReconciliationRecord(path string) ([]byte, error) {
	f, info, err := secure.OpenRootFile(path, 32<<10)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 {
		return nil, errors.New("恢复对账记录须为 root 只读")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<10 || !secure.RootFileUnchanged(f, info) {
		return nil, errors.New("恢复对账记录读取期间变化")
	}
	return raw, nil
}

func saveReconciliationRecord(dir, name string, value any) error {
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	scratch := filepath.Join(dir, name+".copy")
	if f, info, err := secure.OpenRootFile(scratch, 32<<10); err == nil {
		f.Close()
		if info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 {
			return errors.New("恢复对账暂存记录权限无效")
		}
		if err = os.Remove(scratch); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > 32<<10 {
		return errors.New("恢复对账记录超过限制")
	}
	if err = writeFile(scratch, raw, 0400); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, filepath.Join(dir, name), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}

// FreezeDisasterReconciliation publishes a bounded intent and opaque database.
// Only a subsequent independent verifier can approve it for installation.
func FreezeDisasterReconciliation(ctx context.Context, i DisasterIntent, r DisasterReconciliation, source *os.File) error {
	if err := r.Validate(i); err != nil {
		return err
	}
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if prior, e := ReadDisasterReconciliation(i); e == nil {
		if prior.SHA256() != r.SHA256() {
			return errors.New("原恢复已绑定不同对账内容")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		if time.Now().Unix() >= i.ExpiresAt {
			return errors.New("原恢复授权已到期，不能新增对账批准")
		}
		if err = disasterBudget(filepath.Dir(dir), dir, i, r.File.Size); err != nil {
			return err
		}
		if err = saveReconciliationRecord(dir, "reconcile.json", r); err != nil {
			return err
		}
	}
	return freezeDisasterDatabase(ctx, i, dir, "reconciled.db", r.File, source)
}

func freezeDisasterDatabase(ctx context.Context, i DisasterIntent, dir, name string, file File, source *os.File) error {
	target := filepath.Join(dir, name)
	if h, n, e := rootFileHash(ctx, target, file.Size, 0400); e == nil {
		if h != file.SHA256 || n != file.Size {
			return errors.New("固定对账数据库偏离原批准")
		}
		return syncDir(dir)
	} else if !os.IsNotExist(e) {
		return e
	}
	if source == nil {
		return errors.New("固定对账数据库尚未完成，原暂存不可用")
	}
	info, err := source.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 || int(st.Uid) != i.Rollback.Manifest.UID || int(st.Gid) != i.Rollback.Manifest.GID || info.Size() != file.Size {
		return errors.New("对账助手暂存身份无效")
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scratch := filepath.Join(dir, name+".copy")
	if f, info, e := secure.OpenRootFile(scratch, DatabaseMax); e == nil {
		f.Close()
		if info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 {
			return errors.New("固定对账复制暂存权限无效")
		}
		if err = os.Remove(scratch); err != nil {
			return err
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	dst, err := os.OpenFile(scratch, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, contextReader{ctx, io.LimitReader(source, file.Size+1)})
	err = errors.Join(copyErr, dst.Sync(), dst.Close())
	if err != nil {
		return err
	}
	h, n, err := rootFileHash(ctx, scratch, file.Size, 0600)
	if err != nil {
		return err
	}
	if h != file.SHA256 || n != file.Size || !secure.RootFileUnchanged(source, info) {
		return errors.New("对账复制与原助手摘要不一致")
	}
	if err = os.Chmod(scratch, 0400); err != nil {
		return err
	}
	f, _, err := secure.OpenRootFile(scratch, file.Size)
	if err != nil {
		return err
	}
	err = errors.Join(f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}

func ApproveDisasterReconciliation(i DisasterIntent, r DisasterReconciliation, p DisasterReconciliationProof) error {
	stored, err := ReadDisasterReconciliation(i)
	if err != nil {
		return err
	}
	if stored.SHA256() != r.SHA256() || p.ReconciliationSHA256 != r.SHA256() || p.VerifiedAt < r.PreparedAt || p.VerifiedAt >= i.ExpiresAt || p.VerifiedAt > time.Now().Unix()+300 {
		return errors.New("恢复对账证明不匹配或原授权已到期")
	}
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if _, err = ReadDisasterReconciliationProof(i, r); err == nil {
		return syncDir(dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if time.Now().Unix() >= i.ExpiresAt {
		return errors.New("原恢复授权已到期，不能新增对账核对批准")
	}
	return saveReconciliationRecord(dir, "reconciled-proof.json", p)
}

func approvedDisasterDatabase(i DisasterIntent) (File, string, error) {
	r, err := ReadDisasterReconciliation(i)
	if os.IsNotExist(err) {
		return i.Files[0], disasterMaterialPath(i, 0), nil
	}
	if err != nil {
		return File{}, "", err
	}
	if _, err = ReadDisasterReconciliationProof(i, r); os.IsNotExist(err) {
		return i.Files[0], disasterMaterialPath(i, 0), nil
	} else if err != nil {
		return File{}, "", err
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	return r.File, filepath.Join(dir, "reconciled.db"), err
}

func InstallDisasterReconciled(ctx context.Context, i DisasterIntent) error {
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if err = checkDisasterOriginals(ctx, dir, i); err != nil {
		return err
	}
	file, path, err := approvedDisasterDatabase(i)
	if err != nil {
		return err
	}
	if path == disasterMaterialPath(i, 0) {
		return errors.New("恢复对账尚未取得独立核对批准")
	}
	h, n, err := rootFileHash(ctx, path, file.Size, 0400)
	if err != nil {
		return err
	}
	if h != file.SHA256 || n != file.Size {
		return errors.New("固定对账数据库不完整")
	}
	before, after := disasterTargets(i), disasterTargets(i)
	after[5].Size, after[5].SHA256 = file.Size, file.SHA256
	actual, err := ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	for index, value := range actual {
		if value != before[index] && value != after[index] {
			return errors.New("对账安装发现目标资源偏离原安装或本次批准")
		}
	}
	if err = installOne(ctx, i.Rollback.Manifest, i.OperationID, before[5], after[5], 5, path); err != nil {
		return err
	}
	return CheckDisasterTarget(ctx, i, true)
}
