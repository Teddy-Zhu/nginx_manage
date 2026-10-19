package agent

import (
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
)

const fail2banUpgradeRestoreKind = "nginx.fail2ban-upgrade-restore"

type Fail2banUpgradeRestoreOptions struct {
	DataDir, Scope, OperationID, ActivationID string
}

type Fail2banUpgradeRestore struct {
	ID           string `json:"id"`
	ActivationID string `json:"activation_id"`
	SnapshotID   string `json:"snapshot_id"`
	EventID      string `json:"event_id"`
	State        string `json:"state"`
	Stage        string `json:"stage"`
	CompletedAt  int64  `json:"completed_at"`
	Reason       string `json:"reason"`
}

type fail2banUpgradeRestoreIntent struct {
	Schema                                    int
	CreatedAt                                 int64
	Request                                   Fail2banUpgradeRestoreOptions
	ActivationSHA256, ActivationReceiptSHA256 string
	Before                                    fail2banStateBasis
	Recovery                                  fail2banUpgradeHostRecovery
	Nginx                                     *fail2banUpgradeQuiesceNginx
	Kernel                                    firewall.KernelView
	Undo                                      fail2banUpgradeSwitchUndo
	State                                     fail2banStateRestoreIntent
}

type fail2banUpgradeRestoreReceipt struct {
	fail2banUpgradeActivationMarker
	Outcome, StateReceiptSHA256 string
	CompletedAt                 int64
}

type fail2banUpgradeRestoreFacts struct {
	Execution bool
	State     *fail2banStateRestoreReceipt
	Receipt   *fail2banUpgradeRestoreReceipt
}

func fail2banUpgradeRestores(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-restores")
}

func fail2banUpgradeRestoreStates(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-restore-states")
}

func (i fail2banUpgradeRestoreIntent) dir() string {
	return filepath.Join(fail2banUpgradeRestores(i.Request.DataDir), i.Request.OperationID)
}

func (i fail2banUpgradeRestoreIntent) hash() string {
	return fail2banUpgradeGrantHash("upgrade-restore", i)
}

func (i fail2banUpgradeRestoreIntent) marker() fail2banUpgradeActivationMarker {
	return fail2banUpgradeActivationMarker{1, i.Request.OperationID, i.hash()}
}

func (i fail2banUpgradeRestoreIntent) stateRestore() fail2banStateRestoreIntent {
	state := i.State
	state.privateDir = filepath.Join(fail2banUpgradeRestoreStates(i.Request.DataDir), i.Request.OperationID)
	return state
}

func fail2banUpgradeRestoreUndo(s fail2banUpgradeSwitch, recovery fail2banUpgradeHostRecovery, ids fail2banUpgradeUndoIDs, at int64) (fail2banUpgradeSwitchUndo, error) {
	registry, sources, sync := fail2banUpgradeVerificationGrants(s)
	var sourceID, syncID string
	if sources != nil {
		sourceID = sources.ID
	}
	if sync != nil {
		syncID = sync.ID
	}
	u, err := s.makeUndo(s.After.EventID, registry.ID, sourceID, syncID, ids, at)
	if err != nil {
		return u, err
	}
	if u.Sync != nil {
		// Candidate convergence may have authored a newer confirmed runtime.
		// Retain that exact base until the restored engine can converge bans.
		u.Sync.RuntimeBaseID = ""
		if recovery.Runtime != nil {
			u.Sync.RuntimeBaseID = recovery.Runtime.Intent.OperationID
		}
		u.Sync.RequestHash = u.Sync.requestHash()
		if !u.Sync.valid() {
			return u, errors.New("升级恢复的持续同步基础无效")
		}
	}
	return u, nil
}

func (i fail2banUpgradeRestoreIntent) validate(data, id string, a fail2banUpgradeActivationIntent, s fail2banUpgradeSwitch, f fail2banUpgradeActivationFacts) error {
	in := i.Request
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || in.ActivationID != a.Request.OperationID || f.Receipt == nil || f.Receipt.Outcome != "stopped" || i.CreatedAt < f.Receipt.CompletedAt || i.CreatedAt > time.Now().Unix()+300 || i.ActivationSHA256 != a.hash() || i.ActivationReceiptSHA256 != fail2banUpgradeGrantHash("activation-receipt", f.Receipt) {
		return errors.New("升级恢复必须绑定已确认停止的原失败候选")
	}
	if err := fail2banUpgradeVerificationID(id, s); err != nil {
		return err
	}
	if id == in.ActivationID || id == a.VerificationID {
		return errors.New("升级恢复须使用独立操作 UUID")
	}
	if !fail2banUpgradeOneOf(i.Before.Managed, s.After) || i.Before.MachineID != s.Manifest.Basis.MachineID || i.Before.BootID != s.Manifest.Basis.BootID || !fail2banUpgradeOneOf(i.Before.Bundle, s.Prepared.Material.Bundle) || i.Before.StateLabel != s.Manifest.Basis.StateLabel || i.Recovery.Stopping != nil {
		return errors.New("升级恢复的候选、完整配置或本机身份超出原范围")
	}
	service := i.Before.Service
	if service.Load != "loaded" || service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" || service.UnitFile != s.Prepared.Basis.Service.UnitFile {
		return errors.New("升级恢复仅接受原启用偏好下的已停止服务")
	}
	stopped := f.Receipt.Stopped
	if stopped == nil || i.Before.Invocation != stopped.Invocation || !fail2banUpgradeOneOf(i.Before.Service, stopped.Service) || i.State.Input.Directory != stopped.Directory || fail2banStateFilesHash(i.State.Input.Before) != stopped.FilesSHA256 {
		return errors.New("升级恢复不得覆盖候选停止回执以外的服务或数据库状态")
	}
	ids := fail2banUpgradeUndoIDs{Managed: i.Undo.Managed.EventID}
	if i.Undo.Nginx != nil {
		ids.Nginx = i.Undo.Nginx.ID
	}
	if i.Undo.Sources != nil {
		ids.Sources = i.Undo.Sources.ID
	}
	if i.Undo.Sync != nil {
		ids.Sync = i.Undo.Sync.ID
	}
	for _, event := range []string{ids.Managed, ids.Nginx, ids.Sources, ids.Sync} {
		if event != "" && (event == id || event == in.ActivationID || event == a.VerificationID) {
			return errors.New("升级恢复不能复用父操作或保护证明标识")
		}
	}
	expected, err := fail2banUpgradeRestoreUndo(s, i.Recovery, ids, i.CreatedAt)
	if err != nil || !fail2banUpgradeOneOf(expected, i.Undo) {
		return errors.Join(errors.New("升级恢复改变了原代码或动作批准范围"), err)
	}
	state := i.State
	if state.ID != id || state.DataDir != data || state.CreatedAt != i.CreatedAt || state.Input.Snapshot != s.Snapshot || !fail2banUpgradeOneOf(state.After, s.Manifest.Files) || state.Input.Directory != s.Directory || !fail2banUpgradeOneOf(state.Input.Basis.Managed, i.Undo.Managed) || !compatibleFail2banStateSnapshot(state.Input.Basis, s.Manifest.Basis) {
		return errors.New("升级恢复未绑定原状态快照及候选数据库保留范围")
	}
	basis := state.Input.Basis
	basis.Managed, basis.Bundle, basis.Configuration = i.Before.Managed, i.Before.Bundle, i.Before.Configuration
	if !fail2banUpgradeOneOf(basis, i.Before) {
		return errors.New("升级恢复改变了原状态目录、机器或停止观察")
	}
	if err = state.validate(data, id); err != nil {
		return err
	}
	before := fail2banStateManifest{Schema: 1, OperationID: s.Request.SnapshotID, DataDir: data, CreatedAt: i.CreatedAt, Basis: i.Before, Files: state.Input.Before}
	if err = before.validate(data, before.OperationID); err != nil {
		return err
	}
	return i.validateActions(s)
}

func (i fail2banUpgradeRestoreIntent) record(receipt *fail2banUpgradeRestoreReceipt) Record {
	r := Record{Kind: fail2banUpgradeRestoreKind, OperationID: i.Request.OperationID, RelatedOperationID: i.Request.ActivationID, RequestHash: fail2banUpgradeGrantHash("upgrade-restore-request", i.Request), CandidateHash: i.hash(), BeforeRevision: i.Before.Managed.EventID, AfterRevision: i.Undo.Managed.EventID, State: "running", Stage: "restoring_stopped"}
	if receipt != nil {
		r.ObservedRevision = fail2banUpgradeGrantHash("upgrade-restore-receipt", receipt)
		r.State, r.Stage = "succeeded", "original_restored_stopped"
		if receipt.Outcome == "cancelled" {
			r.State, r.Stage = "failed", "cancelled"
		}
	}
	return r
}

func (i fail2banUpgradeRestoreIntent) result(f fail2banUpgradeRestoreFacts, acknowledged bool) Fail2banUpgradeRestore {
	out := Fail2banUpgradeRestore{ID: i.Request.OperationID, ActivationID: i.Request.ActivationID, SnapshotID: i.State.Input.Snapshot.OperationID, EventID: i.Undo.Managed.EventID, State: "running", Stage: "intent_reserved"}
	if f.Execution {
		out.State, out.Stage = "compensating", "restoring_stopped"
	}
	if f.State != nil {
		out.Stage = "state_restored"
	}
	if f.Receipt != nil {
		r := i.record(f.Receipt)
		out.State, out.Stage, out.CompletedAt = r.State, r.Stage, f.Receipt.CompletedAt
		if !acknowledged {
			out.State, out.Stage = "recovery_required", "completion_unacknowledged"
		}
	}
	return out
}

func pendingFail2banUpgradeRestoreRecord(actual, expected Record) bool {
	return pendingFail2banUpgradeActivationRecord(actual, expected)
}
