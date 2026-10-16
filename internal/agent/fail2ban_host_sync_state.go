package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

const fail2banHostSyncKind = "fail2ban_host_sync"

// One root-approved continuous session is one long-running operation. Its
// current subtransaction is a crash checkpoint, not a new global audit entry
// per IP change. Explicit grants and completed manual audits stay immutable.
type fail2banHostSyncEvent struct {
	Schema         int    `json:"schema"`
	ID             string `json:"id"`
	PreviousID     string `json:"previous_id"`
	Action         string `json:"action"`
	SessionID      string `json:"session_id"`
	Owner          string `json:"owner"`
	RegistrationID string `json:"registration_id"`
	NamespaceID    string `json:"namespace_id"`
	EngineKey      string `json:"engine_key"`
	ProtectionID   string `json:"protection_id"`
	SourcesID      string `json:"sources_id"`
	RuntimeBaseID  string `json:"runtime_base_id"`
	ApprovedAt     int64  `json:"approved_at"`
	RequestHash    string `json:"request_hash"`
}

func (e fail2banHostSyncEvent) requestHash() string {
	e.ApprovedAt, e.RequestHash = 0, ""
	raw, _ := json.Marshal(e)
	return secure.Hash(append([]byte("nginxpanel:fail2ban-host-sync:v1:"), raw...))
}

func (e fail2banHostSyncEvent) valid() bool {
	if e.Schema != 1 || !validID(e.ID) || e.PreviousID != "" && !validID(e.PreviousID) || e.ID == e.PreviousID || !validID(e.SessionID) || !validID(e.Owner) || !validID(e.RegistrationID) || !fail2banDigest.MatchString(e.NamespaceID) || !fail2banDigest.MatchString(e.EngineKey) || !validID(e.ProtectionID) || !validID(e.SourcesID) || e.RuntimeBaseID != "" && !validID(e.RuntimeBaseID) || e.ApprovedAt <= 0 || e.RequestHash != e.requestHash() {
		return false
	}
	return e.Action == "enable" && e.SessionID == e.ID || e.Action == "disable" && e.ID != e.SessionID && e.PreviousID == e.SessionID
}

func fail2banHostSyncDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-sync")
}

func loadFail2banHostSyncEvent(dataDir, id string) (*fail2banHostSyncEvent, error) {
	if !validID(id) {
		return nil, errors.New("持续同步批准标识无效")
	}
	var e fail2banHostSyncEvent
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostSyncDir(dataDir), "events", id+".json"), &e); err != nil {
		return nil, err
	}
	if !e.valid() || e.ID != id {
		return nil, errors.New("持续同步批准内容无效")
	}
	return &e, nil
}

func loadFail2banHostSync(dataDir string) (*fail2banHostSyncEvent, error) {
	var pointer struct {
		ID string `json:"id"`
	}
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostSyncDir(dataDir), "current.json"), &pointer); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadFail2banHostSyncEvent(dataDir, pointer.ID)
}

func writeFail2banHostSyncEvent(dataDir string, e *fail2banHostSyncEvent) error {
	if !e.valid() {
		return errors.New("拒绝保存无效持续同步批准")
	}
	dir := filepath.Join(fail2banHostSyncDir(dataDir), "events")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	saved, err := loadFail2banHostSyncEvent(dataDir, e.ID)
	if err == nil {
		if saved.RequestHash != e.RequestHash {
			return errors.New("持续同步 UUID 已用于其他批准")
		}
		e.ApprovedAt = saved.ApprovedAt
	} else {
		if !os.IsNotExist(err) {
			return err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) >= 2048 {
			return errors.New("持续同步批准容量已满，须本机维护")
		}
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(filepath.Join(dir, e.ID+".json"), raw, fail2banHostProtectionBytes)
}

func publishFail2banHostSync(dataDir string, e *fail2banHostSyncEvent) error {
	return rootJSONWrite(filepath.Join(fail2banHostSyncDir(dataDir), "current.json"), struct {
		ID string `json:"id"`
	}{e.ID}, 1024)
}

func fail2banHostSyncInactive(dataDir string) error {
	e, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return err
	}
	if e != nil && e.Action == "enable" {
		return errors.New("持续宿主机封禁同步仍获批准，须先明确停用并清除其规则")
	}
	return nil
}

func fail2banHostSyncOwns(e *fail2banHostSyncEvent, v *fail2banHostRuntime) bool {
	i := v.Intent
	return e.Action == "enable" && i.ControllerID == e.ID && i.Owner == e.Owner && i.RegistrationID == e.RegistrationID && i.Baseline.NamespaceID == e.NamespaceID && (i.Action == "clear" || i.Sources != nil && i.Sources.ID == e.SourcesID && i.ProtectionID == e.ProtectionID)
}

func fail2banHostSyncParent(e *fail2banHostSyncEvent) Record {
	return Record{Kind: fail2banHostSyncKind, OperationID: e.ID, RelatedOperationID: e.PreviousID, RequestHash: e.RequestHash, State: "running", Stage: "approved", BeforeRevision: e.RuntimeBaseID}
}

func fail2banHostSyncParentMatches(r Record, e *fail2banHostSyncEvent) bool {
	return r.Kind == fail2banHostSyncKind && r.OperationID == e.ID && r.RequestHash == e.RequestHash && r.RelatedOperationID == e.PreviousID
}

func fail2banHostSyncRuntimeJournal(e *fail2banHostSyncEvent, v *fail2banHostRuntime) Record {
	r := fail2banHostSyncParent(e)
	r.Stage = v.Intent.Action + "/" + v.State
	r.BeforeRevision, r.AfterRevision = v.Intent.Baseline.Fingerprint, v.Intent.hash()
	r.CandidateHash, r.ObservedRevision, r.Error = v.Intent.TransactionHash, v.Confirmed.Fingerprint, v.Error
	return r
}

func fail2banHostSyncRuntimeReceipt(dataDir string, v *fail2banHostRuntime) bool {
	e, err := loadFail2banHostSyncEvent(dataDir, v.Intent.ControllerID)
	if err != nil || !fail2banHostSyncOwns(e, v) {
		return false
	}
	r, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(e.ID)
	want := fail2banHostSyncRuntimeJournal(e, v)
	return err == nil && fail2banHostSyncParentMatches(r, e) && (r.State == "running" || r.State == "succeeded" && (v.State == "succeeded" || v.State == "failed") && v.effective().Set == nil) && r.Stage == want.Stage && r.BeforeRevision == want.BeforeRevision && r.AfterRevision == want.AfterRevision && r.CandidateHash == want.CandidateHash && r.ObservedRevision == want.ObservedRevision && r.Error == want.Error
}

func saveFail2banHostSyncRuntime(dataDir string, v *fail2banHostRuntime) error {
	e, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return err
	}
	if e == nil || !fail2banHostSyncOwns(e, v) {
		return errors.New("持续同步批准已变化，禁止提交或改写旧会话")
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	parent, err := j.Get(e.ID)
	if err != nil || !fail2banHostSyncParentMatches(parent, e) || parent.State != "running" {
		return errors.Join(errors.New("持续同步父操作不再允许推进"), err)
	}
	// Preserve each submitted intent until its exact outcome is reconciled.
	current, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return err
	}
	if current != nil {
		if current.Intent.OperationID == v.Intent.OperationID {
			if current.Intent.hash() != v.Intent.hash() || (current.State == "succeeded" || current.State == "failed") && (current.State != v.State || current.Confirmed != v.Confirmed || current.Error != v.Error) {
				return errors.New("禁止替换在途意图或改写已确认子事务")
			}
		} else if current.Intent.OperationID != v.Intent.BaseOperationID || current.State == "running" || current.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, current) {
			return errors.New("持续同步基础对象变化或原子事务尚未核对")
		}
	} else if v.Intent.BaseOperationID != "" {
		return errors.New("持续同步基础运行记录缺失")
	}
	if err = secure.RootDirectory(fail2banHostRuntimeDir(dataDir), 0700); err != nil {
		return err
	}
	if err = rootJSONWrite(filepath.Join(fail2banHostRuntimeDir(dataDir), "current.json"), v, fail2banHostRuntimeBytes); err != nil {
		return err
	}
	return j.Put(fail2banHostSyncRuntimeJournal(e, v))
}

func fail2banHostSyncMaintenanceIdle(dataDir string, r Record) (bool, error) {
	e, err := loadFail2banHostSyncEvent(dataDir, r.OperationID)
	if err != nil || !fail2banHostSyncParentMatches(r, e) {
		return false, errors.Join(errors.New("持续同步维护回执无效"), err)
	}
	if r.State == "succeeded" {
		if r.Stage == "disabled-empty" && r.AfterRevision == "" || (r.Stage == "clear/succeeded" || r.Stage == "apply/failed" && r.Error != "") && fail2banDigest.MatchString(r.AfterRevision) && fail2banDigest.MatchString(r.ObservedRevision) {
			return true, nil
		}
		return false, errors.New("持续同步停用回执不完整")
	}
	if r.State != "running" {
		return false, errors.New("持续同步父操作状态无效")
	}
	v, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return false, err
	}
	if v == nil || v.Intent.ControllerID != e.ID {
		return r.Stage == "approved" && r.AfterRevision == "", nil
	}
	return (v.State == "succeeded" || v.State == "failed") && fail2banHostRuntimeReceipt(dataDir, v), nil
}
