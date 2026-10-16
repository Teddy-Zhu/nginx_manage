package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

type Fail2banHostRecoveryStatus struct {
	ID             string `json:"id"`
	State          string `json:"state"`
	RetirementID   string `json:"retirement_id"`
	RegistrationID string `json:"registration_id"`
	SessionID      string `json:"session_id"`
	BootID         string `json:"boot_id"`
	UpdatedAt      int64  `json:"updated_at"`
	Reason         string `json:"reason"`
}

func (r *fail2banHostBootRecovery) status(dataDir string) (Fail2banHostRecoveryStatus, error) {
	out := Fail2banHostRecoveryStatus{ID: r.ID, RetirementID: r.RetirementID, RegistrationID: r.RegistrationID, SessionID: r.SyncID, BootID: r.BootID}
	record, err := r.record(dataDir)
	out.State, out.UpdatedAt, out.Reason = record.State, record.UpdatedAt, record.Error
	if err == nil && record.State == "running" && record.Error == "" {
		out.Reason = "启动范围正在恢复，持续保护尚未确认"
	}
	if err == nil && record.State == "succeeded" {
		out.Reason = "新的本机会话已建立，实际封禁以持续采样和内核核对状态为准"
	}
	return out, err
}

// Cancellation withdraws this bootstrap's execution right. It does not claim
// that partial registration, old rules or uncertain requests were undone.
func ManageFail2banHostRecovery(ctx context.Context, dataDir, scope, action, operationID string) (Fail2banHostRecoveryStatus, error) {
	var out Fail2banHostRecoveryStatus
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("启动恢复管理须本机 root、宿主机范围及规范绝对数据目录")
	}
	if action != "status" && action != "cancel" || operationID != "" && !validID(operationID) || action == "cancel" && operationID == "" {
		return out, errors.New("启动恢复参数无效，取消须原恢复 UUID")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if action == "status" {
		var r *fail2banHostBootRecovery
		var err error
		if operationID == "" {
			r, err = loadFail2banHostBootRecovery(dataDir)
		} else {
			r, err = loadFail2banHostBootRecoveryEvent(dataDir, operationID)
		}
		if err != nil {
			return out, err
		}
		if r == nil {
			return Fail2banHostRecoveryStatus{State: "uninitialized", Reason: "尚无本机启动恢复操作"}, nil
		}
		return r.status(dataDir)
	}
	leave, err := fail2banHostSyncLocks(dataDir)
	if err != nil {
		return out, err
	}
	defer leave()
	r, err := loadFail2banHostBootRecovery(dataDir)
	if err != nil {
		return out, err
	}
	if r == nil || r.ID != operationID {
		return out, errors.New("取消标识与当前启动恢复不匹配")
	}
	if err = ensureFail2banHostBootRecoveryRecord(dataDir, r); err != nil {
		return out, err
	}
	record, err := r.record(dataDir)
	if err != nil {
		return out, err
	}
	if record.State == "succeeded" {
		return out, errors.New("启动恢复已完成，须明确停用当前持续会话")
	}
	if record.State == "running" {
		if err = (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(r.journal("cancelled")); err != nil {
			return out, err
		}
	}
	return r.status(dataDir)
}
