package panelrecovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

// The completed database is a separate approved postimage. The parent must
// durably commit activation before installing it or allowing serve to open it.
type DisasterActivation struct {
	Schema               int                    `json:"schema"`
	OperationID          string                 `json:"operation_id"`
	IntentSHA256         string                 `json:"intent_sha256"`
	ReconciliationSHA256 string                 `json:"reconciliation_sha256"`
	ExternalReview       DisasterExternalReview `json:"external_review"`
	Epoch                string                 `json:"epoch"`
	PreparedAt           int64                  `json:"prepared_at"`
	StartID              string                 `json:"start_id"`
	File                 File                   `json:"file"`
	ReportSHA256         string                 `json:"report_sha256"`
}

func (a DisasterActivation) SHA256() string { raw, _ := json.Marshal(a); return secure.Hash(raw) }

func (a DisasterActivation) Validate(i DisasterIntent, r DisasterReconciliation) error {
	if err := r.Validate(i); err != nil {
		return err
	}
	if err := a.ExternalReview.Validate(i.OperationID, r.SHA256()); err != nil {
		return err
	}
	if a.Schema != 2 || a.OperationID != i.OperationID || a.IntentSHA256 != i.SHA256() || a.ReconciliationSHA256 != r.SHA256() || !idValue.MatchString(a.Epoch) || !idValue.MatchString(a.StartID) || a.StartID == i.OperationID || a.StartID == i.PlanID || a.StartID == i.Stop.OperationID || a.StartID == i.Stop.MaintenanceID || a.PreparedAt < r.PreparedAt || a.PreparedAt >= i.ExpiresAt || a.PreparedAt > time.Now().Unix()+300 || a.File.Name != i.Files[0].Name || a.File.Size < 1 || a.File.Size > DatabaseMax || !hashValue.MatchString(a.File.SHA256) || !hashValue.MatchString(a.ReportSHA256) {
		return errors.New("恢复激活材料与原安装、对账批准不一致")
	}
	return nil
}

type DisasterActivationProof struct {
	ActivationSHA256 string `json:"activation_sha256"`
	VerifiedAt       int64  `json:"verified_at"`
}

func ReadDisasterActivation(i DisasterIntent) (out DisasterActivation, err error) {
	r, err := ReadDisasterReconciliation(i)
	if err != nil {
		return out, err
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	raw, err := readReconciliationRecord(filepath.Join(dir, "activate.json"))
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return out, errors.New("恢复激活意图不是原规范记录")
	}
	return out, out.Validate(i, r)
}

func ReadDisasterActivationProof(i DisasterIntent, a DisasterActivation) (out DisasterActivationProof, err error) {
	stored, err := ReadDisasterActivation(i)
	if err != nil {
		return out, err
	}
	if stored.SHA256() != a.SHA256() {
		return out, errors.New("恢复激活意图已变化")
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	raw, err := readReconciliationRecord(filepath.Join(dir, "activated-proof.json"))
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) || out.ActivationSHA256 != a.SHA256() || out.VerifiedAt < a.PreparedAt || out.VerifiedAt >= i.ExpiresAt || out.VerifiedAt > time.Now().Unix()+300 {
		return out, errors.New("恢复激活证明与原批准不一致")
	}
	return out, nil
}

func FreezeDisasterActivation(ctx context.Context, i DisasterIntent, a DisasterActivation, source *os.File) error {
	r, err := ReadDisasterReconciliation(i)
	if err != nil {
		return err
	}
	if err = a.Validate(i, r); err != nil {
		return err
	}
	if _, err = ReadDisasterReconciliationProof(i, r); err != nil {
		return err
	}
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if prior, e := ReadDisasterActivation(i); e == nil {
		if prior.SHA256() != a.SHA256() {
			return errors.New("原恢复已有不同激活批准")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		if time.Now().Unix() >= i.ExpiresAt {
			return errors.New("原恢复授权已到期，禁止新增激活材料")
		}
		if err = disasterBudget(filepath.Dir(dir), dir, i, a.File.Size); err != nil {
			return err
		}
		if err = saveReconciliationRecord(dir, "activate.json", a); err != nil {
			return err
		}
	}
	return freezeDisasterDatabase(ctx, i, dir, "activated.db", a.File, source)
}

func ApproveDisasterActivation(i DisasterIntent, a DisasterActivation, p DisasterActivationProof) error {
	stored, err := ReadDisasterActivation(i)
	if err != nil {
		return err
	}
	if stored.SHA256() != a.SHA256() || p.ActivationSHA256 != a.SHA256() || p.VerifiedAt < a.PreparedAt || p.VerifiedAt >= i.ExpiresAt || p.VerifiedAt > time.Now().Unix()+300 {
		return errors.New("恢复激活证明不匹配或已到期")
	}
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if _, err = ReadDisasterActivationProof(i, a); err == nil {
		return syncDir(dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if time.Now().Unix() >= i.ExpiresAt {
		return errors.New("原恢复授权已到期，禁止新增激活证明")
	}
	return saveReconciliationRecord(dir, "activated-proof.json", p)
}

// Caller holds the original stop and writer fence and has already persisted
// the irreversible activation commit. No database bytes are interpreted here.
func InstallDisasterActivated(ctx context.Context, i DisasterIntent) error {
	a, err := ReadDisasterActivation(i)
	if err != nil {
		return err
	}
	if _, err = ReadDisasterActivationProof(i, a); err != nil {
		return err
	}
	dir, err := checkedDisasterDirectory(i)
	if err != nil {
		return err
	}
	if err = checkDisasterOriginals(ctx, dir, i); err != nil {
		return err
	}
	r, err := ReadDisasterReconciliation(i)
	if err != nil {
		return err
	}
	before, after := disasterTargets(i), disasterTargets(i)
	before[5].Size, before[5].SHA256 = r.File.Size, r.File.SHA256
	after[5].Size, after[5].SHA256 = a.File.Size, a.File.SHA256
	actual, err := ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	for n, f := range actual {
		if f != before[n] && f != after[n] {
			return errors.New("激活安装发现目标偏离原对账或激活材料")
		}
	}
	path := filepath.Join(dir, "activated.db")
	h, n, err := rootFileHash(ctx, path, a.File.Size, 0400)
	if err != nil {
		return err
	}
	if h != a.File.SHA256 || n != a.File.Size {
		return errors.New("固定激活数据库不完整")
	}
	if err = installOne(ctx, i.Rollback.Manifest, i.OperationID, before[5], after[5], 5, path); err != nil {
		return err
	}
	actual, err = ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	for n, f := range actual {
		if f != after[n] {
			return errors.New("激活安装后资源尚未完全匹配")
		}
	}
	return nil
}

func CheckDisasterActiveMaterial(ctx context.Context, i DisasterIntent) error {
	// Secrets remain pinned after startup, while SQLite legitimately writes WAL.
	if os.Geteuid() != 0 {
		return errors.New("恢复激活密钥核对需要本机 root")
	}
	if err := i.Validate(); err != nil {
		return err
	}
	return checkMaterialFiles(ctx, i.DataDir, i.Rollback.Manifest.UID, i.Rollback.Manifest.GID, i.Files)
}

// This check is only valid before the first writable open; after startup the
// database and its WAL legitimately change and must never be reinstalled.
func CheckDisasterActivatedTarget(ctx context.Context, i DisasterIntent) error {
	a, err := ReadDisasterActivation(i)
	if err != nil {
		return err
	}
	if _, err = ReadDisasterActivationProof(i, a); err != nil {
		return err
	}
	expected := disasterTargets(i)
	expected[5].Size, expected[5].SHA256 = a.File.Size, a.File.SHA256
	actual, err := ObserveTarget(ctx, i.Rollback)
	if err != nil {
		return err
	}
	for n, file := range actual {
		if file != expected[n] {
			return errors.New("解除激活屏障前目标资源偏离原固定副本")
		}
	}
	return nil
}
