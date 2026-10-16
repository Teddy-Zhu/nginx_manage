package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type AdoptionCleanup struct {
	Schema         int                 `json:"schema"`
	DataDir        string              `json:"data_dir"`
	OperationID    string              `json:"operation_id"`
	Stop           storage.ServiceHold `json:"stop"`
	IntentSHA256   string              `json:"intent_sha256"`
	AdoptionSHA256 string              `json:"adoption_sha256"`
	StartedAt      int64               `json:"started_at"`
}
type adoptionCleaned struct {
	CleanupSHA256 string `json:"cleanup_sha256"`
	CompletedAt   int64  `json:"completed_at"`
}

func adoptionValueHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

// Cleanup records retain approval/audit metadata after plaintext deletion.
func readAdoptionCleanup(data, id, dir string, intent *AdoptionIntent) (*AdoptionCleanup, error) {
	var c AdoptionCleanup
	if err := readAdoptionJSON(filepath.Join(dir, "cleanup.json"), &c); err != nil {
		return nil, err
	}
	h := c.Stop
	if c.Schema != 1 || c.DataDir != data || c.OperationID != id || c.StartedAt <= 0 || c.StartedAt > time.Now().Unix()+300 || h.Schema != 1 || !validID.MatchString(h.OperationID) || !validID.MatchString(h.MaintenanceID) || !validHash.MatchString(h.RequestSHA256) || !validHash.MatchString(h.ReleaseID) || !validHash.MatchString(h.BindingSHA256) || c.AdoptionSHA256 != "" && !validHash.MatchString(c.AdoptionSHA256) {
		return nil, errors.New("恢复接入清理意图无效")
	}
	if intent == nil {
		if c.IntentSHA256 != "" || c.AdoptionSHA256 != "" {
			return nil, errors.New("恢复接入清理缺少原批准历史")
		}
	} else {
		hash, err := adoptionValueHash(*intent)
		if err != nil {
			return nil, err
		}
		if c.IntentSHA256 != hash || c.Stop != intent.Stop {
			return nil, errors.New("恢复接入清理与原批准历史不一致")
		}
	}
	if c.AdoptionSHA256 != "" {
		var a Adoption
		if err := readAdoptionJSON(filepath.Join(dir, "adoption.json"), &a); err != nil {
			return nil, err
		}
		if err := a.Validate(data, id); err != nil {
			return nil, err
		}
		if a.SHA256 != c.AdoptionSHA256 || intent == nil || !sameAdoptionValue(a.Intent, *intent) {
			return nil, errors.New("恢复接入清理批准摘要不一致")
		}
	} else if _, err := os.Lstat(filepath.Join(dir, "adoption.json")); !os.IsNotExist(err) {
		return nil, errors.New("恢复接入清理遗漏了已核对批准记录")
	}
	return &c, nil
}
func readAdoptionCleaned(dir string, c AdoptionCleanup) error {
	var completed adoptionCleaned
	if err := readAdoptionJSON(filepath.Join(dir, "cleaned.json"), &completed); err != nil {
		return err
	}
	hash, err := adoptionValueHash(c)
	if err != nil {
		return err
	}
	if completed.CleanupSHA256 != hash || completed.CompletedAt < c.StartedAt || completed.CompletedAt > time.Now().Unix()+300 {
		return errors.New("恢复接入清理完成记录不一致")
	}
	return nil
}
func readAdoptionHistory(data, id, dir string, completed bool) (out AdoptionStatus, err error) {
	items, _, err := adoptionEntries(dir)
	if err != nil {
		return out, err
	}
	var intent *AdoptionIntent
	var original AdoptionIntent
	if err = readAdoptionJSON(filepath.Join(dir, "intent.json"), &original); err == nil {
		if err = original.Validate(data, id); err != nil {
			return out, err
		}
		intent = &original
	} else if !os.IsNotExist(err) {
		return out, err
	}
	if intent == nil {
		for _, item := range items {
			if item.Name() != ".json-copy" && item.Name() != "cleanup.json" && item.Name() != "cleaned.json" {
				return out, errors.New("恢复接入清理缺少原意图但仍有资源")
			}
		}
	}
	if _, err = os.Lstat(filepath.Join(dir, "cleanup.json")); os.IsNotExist(err) && !completed {
		if _, e := os.Lstat(filepath.Join(dir, "cleaned.json")); !os.IsNotExist(e) {
			return out, errors.New("恢复接入清理完成记录缺少原清理意图")
		}
		// The directory rename is already durable; the first cleanup record may
		// still need to be published before any resource can be removed.
		return AdoptionStatus{State: "cleaning", Intent: intent}, nil
	}
	if err != nil {
		return out, err
	}
	c, err := readAdoptionCleanup(data, id, dir, intent)
	if err != nil {
		return out, err
	}
	out = AdoptionStatus{State: "cleaning", Intent: intent, Cleanup: c}
	if !completed {
		if _, e := os.Lstat(filepath.Join(dir, "cleaned.json")); os.IsNotExist(e) {
			return out, nil
		} else if e != nil {
			return out, e
		}
	}
	for _, item := range items {
		switch item.Name() {
		case "intent.json", "adoption.json", "cleanup.json", "cleaned.json":
		default:
			return out, errors.New("已清理恢复历史仍含材料或暂存")
		}
	}
	if err = readAdoptionCleaned(dir, *c); err != nil {
		return out, err
	}
	if completed {
		out.State = "cleaned"
	}
	return out, nil
}
