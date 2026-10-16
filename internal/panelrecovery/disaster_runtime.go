package panelrecovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type DisasterRuntimeApproval struct {
	Schema       int    `json:"schema"`
	OperationID  string `json:"operation_id"`
	IntentSHA256 string `json:"intent_sha256"`
	PlanSHA256   string `json:"plan_sha256"`
	Rollback     bool   `json:"rollback"`
	Epoch        string `json:"epoch"`
	ApprovedAt   int64  `json:"approved_at"`
}

func runtimeApprovalName(rollback bool) string {
	if rollback {
		return "runtime-rollback.json"
	}
	return "runtime-apply.json"
}

func ReadDisasterRuntimeApproval(i DisasterIntent, rollback bool) (out DisasterRuntimeApproval, err error) {
	if err = i.Validate(); err != nil {
		return out, err
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return out, err
	}
	f, info, err := secure.OpenRootFile(filepath.Join(dir, runtimeApprovalName(rollback)), 8192)
	if err != nil {
		return out, err
	}
	f.Close()
	if info.Mode().Perm() != 0400 {
		return out, errors.New("恢复运行授权须由 root 固定为只读")
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, runtimeApprovalName(rollback)), 8192)
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) || out.Schema != 1 || out.OperationID != i.OperationID || out.IntentSHA256 != i.SHA256() || out.PlanSHA256 != i.PlanSHA256 || out.Rollback != rollback || !idValue.MatchString(out.Epoch) || out.ApprovedAt < i.CreatedAt || out.ApprovedAt > time.Now().Unix()+300 || (!rollback && out.ApprovedAt >= i.ExpiresAt) {
		return out, errors.New("恢复运行授权与原安装意图不一致")
	}
	return out, nil
}

// ApproveDisasterRuntime requires the caller to hold the independent restore
// and maintenance admission locks. Approval cannot be renewed or overwritten.
func ApproveDisasterRuntime(i DisasterIntent, epoch string, rollback bool) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if !idValue.MatchString(epoch) {
		return errors.New("恢复运行授权 epoch 无效")
	}
	if !rollback {
		if _, err := ReadDisasterRuntimeApproval(i, true); err == nil {
			return errors.New("原恢复已明确选择补偿")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := ReadDisasterRuntimeApproval(i, rollback); err == nil {
		dir, e := disasterDirectory(i.DataDir, i.OperationID)
		if e != nil {
			return e
		}
		return syncDir(dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if !rollback && time.Now().Unix() >= i.ExpiresAt {
		return errors.New("原恢复授权已到期，禁止新建运行批准")
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return err
	}
	if err = checkPrivateDir(dir); err != nil {
		return err
	}
	name := runtimeApprovalName(rollback)
	scratch := filepath.Join(dir, name+".copy")
	if f, info, e := secure.OpenRootFile(scratch, 8192); e == nil {
		f.Close()
		if info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 {
			return errors.New("恢复运行授权暂存权限无效")
		}
		if err = os.Remove(scratch); err != nil {
			return err
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	raw, err := json.Marshal(DisasterRuntimeApproval{Schema: 1, OperationID: i.OperationID, IntentSHA256: i.SHA256(), PlanSHA256: i.PlanSHA256, Rollback: rollback, Epoch: epoch, ApprovedAt: time.Now().Unix()})
	if err != nil {
		return err
	}
	if err = writeFile(scratch, raw, 0400); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, filepath.Join(dir, name), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}
