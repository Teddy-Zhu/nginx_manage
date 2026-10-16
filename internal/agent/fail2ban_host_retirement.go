package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banHostRetirementKind = "fail2ban_host_retirement"
const fail2banHostRetirementBytes = 512 << 10

// A retirement closes a local grant, not the outcome of an old kernel request.
// The complete old checkpoint is retained even when its parent journal advances.
type fail2banHostRetirement struct {
	Schema         int                      `json:"schema"`
	ID             string                   `json:"id"`
	PreviousID     string                   `json:"previous_id"`
	RegistrationID string                   `json:"registration_id"`
	StopID         string                   `json:"stop_id"`
	RequestedAt    int64                    `json:"requested_at"`
	RequestHash    string                   `json:"request_hash"`
	Root           fail2banHostRegistration `json:"root"`
	Runtime        *fail2banHostRuntime     `json:"runtime"`
	RuntimeCurrent bool                     `json:"runtime_current"`
	RuntimeJournal *Record                  `json:"runtime_journal"`
	Sync           *fail2banHostSyncEvent   `json:"sync"`
	SyncParent     *Record                  `json:"sync_parent"`
	Stopping       *fail2banHostSyncEvent   `json:"stopping"`
	Absent         firewall.KernelView      `json:"absent"`
}

type Fail2banHostRetirementStatus struct {
	ID                 string `json:"id"`
	State              string `json:"state"`
	PreviousID         string `json:"previous_id"`
	BeforeRegistration string `json:"before_registration"`
	AfterRegistration  string `json:"after_registration"`
	RuntimeID          string `json:"runtime_id"`
	SessionID          string `json:"session_id"`
	OldNamespace       string `json:"old_namespace"`
	ObservedNamespace  string `json:"observed_namespace"`
	Disposition        string `json:"disposition"`
	CompletedAt        int64  `json:"completed_at"`
	Reason             string `json:"reason"`
}

type fail2banHostRetirementReceipt struct {
	Schema      int                 `json:"schema"`
	ID          string              `json:"id"`
	IntentHash  string              `json:"intent_hash"`
	CompletedAt int64               `json:"completed_at"`
	Kernel      firewall.KernelView `json:"kernel"`
}

func (r *fail2banHostRetirement) receiptPath(dataDir string) string {
	return filepath.Join(fail2banHostRetirementDir(dataDir), "receipts", r.ID+".json")
}

func (r *fail2banHostRetirement) receipt(dataDir string) (*fail2banHostRetirementReceipt, error) {
	var receipt fail2banHostRetirementReceipt
	if err := readFail2banHostProtectionJSON(r.receiptPath(dataDir), &receipt); err != nil {
		return nil, err
	}
	if receipt.Schema != 1 || receipt.ID != r.ID || receipt.IntentHash != r.hash() || receipt.CompletedAt <= 0 || !validFail2banHostAbsence(receipt.Kernel) {
		return nil, errors.New("宿主机退役完成证明无效")
	}
	return &receipt, nil
}

func (r *fail2banHostRetirement) completed(receipt *fail2banHostRetirementReceipt) Record {
	record := r.journal("succeeded")
	raw, _ := json.Marshal(receipt)
	record.ObservedRevision = secure.Hash(raw)
	return record
}

func fail2banHostRetirementDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-retirements")
}

func fail2banHostRetirementRequest(id, base string) string {
	return secure.Hash([]byte("nginxpanel:fail2ban-host-retirement:v1:" + id + ":" + base))
}

func sameFail2banRetirementRecord(a, b Record) bool {
	a.UpdatedAt, b.UpdatedAt = 0, 0
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (r *fail2banHostRetirement) hash() string {
	raw, _ := json.Marshal(r)
	return secure.Hash(raw)
}

func validFail2banHostAbsence(k firewall.KernelView) bool {
	return k.Available && !k.TableExists && k.Generation != 0 && fail2banDigest.MatchString(k.NamespaceID) && fail2banDigest.MatchString(k.Fingerprint) && k.ObservedAt > 0 && k.Bytes > 0 && k.Bytes <= nftReadBytes && k.Chains == 0 && k.Rules == 0 && k.Reason == ""
}

func (r *fail2banHostRetirement) valid(dataDir string) error {
	if r.Schema != 1 || !validID(r.ID) || !validID(r.RegistrationID) || r.ID == r.RegistrationID || r.RegistrationID == r.Root.OperationID || r.PreviousID != "" && !validID(r.PreviousID) || r.PreviousID == r.ID || r.RequestedAt <= 0 || r.Root.Action == "retire" || r.Root.RetirementID != "" || r.Root.State != "registered" || r.RequestHash != fail2banHostRetirementRequest(r.ID, r.Root.OperationID) || !validFail2banHostAbsence(r.Absent) {
		return errors.New("宿主机动作退役意图无效")
	}
	raw, _ := json.Marshal(r.Root)
	if _, err := decodeFail2banHostRegistration(dataDir, raw); err != nil {
		return err
	}
	if r.Runtime != nil && !r.Runtime.valid() || r.RuntimeCurrent && (r.Runtime == nil || !fail2banHostRuntimeMatches(r.Runtime, &r.Root)) {
		return errors.New("退役的原运行意图无效或不属于原登记")
	}
	if r.RuntimeJournal != nil && (r.Runtime == nil || !r.RuntimeCurrent || r.Runtime.Intent.ControllerID != "" || r.RuntimeJournal.OperationID != r.Runtime.Intent.OperationID || r.RuntimeJournal.Kind != fail2banHostRuntimeKind || r.RuntimeJournal.RequestHash != r.Runtime.Intent.RequestHash) {
		return errors.New("退役的原手动操作回执不匹配")
	}
	if r.Sync != nil && !r.Sync.valid() || r.Stopping != nil && (!r.Stopping.valid() || r.Sync == nil || r.Stopping.PreviousID != r.Sync.ID) {
		return errors.New("退役的原持续批准或停止意图无效")
	}
	if r.Sync != nil && r.Sync.Action == "enable" {
		if r.Sync.Owner != r.Root.Owner || r.Sync.RegistrationID != r.Root.OperationID || !validID(r.StopID) || r.StopID == r.ID || r.StopID == r.RegistrationID || r.SyncParent == nil || !fail2banHostSyncParentMatches(*r.SyncParent, r.Sync) || r.SyncParent.State != "running" {
			return errors.New("退役的持续会话所属范围或父回执不匹配")
		}
	} else if r.StopID != "" || r.SyncParent != nil || r.Stopping != nil {
		return errors.New("无活跃会话的退役不接受会话写入材料")
	}
	return nil
}

func loadFail2banHostRetirementEvent(dataDir, id string) (*fail2banHostRetirement, error) {
	if !validID(id) {
		return nil, errors.New("宿主机退役标识无效")
	}
	var r fail2banHostRetirement
	raw, err := listenerRead(filepath.Join(fail2banHostRetirementDir(dataDir), "events", id+".json"), fail2banHostRetirementBytes)
	if err != nil {
		return nil, err
	}
	if err = decodeFail2banNginxJSON(raw, &r); err != nil {
		return nil, err
	}
	if r.ID != id {
		return nil, errors.New("宿主机退役文件标识不匹配")
	}
	return &r, r.valid(dataDir)
}

func loadFail2banHostRetirement(dataDir string) (*fail2banHostRetirement, error) {
	var pointer struct {
		ID string `json:"id"`
	}
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostRetirementDir(dataDir), "current.json"), &pointer); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadFail2banHostRetirementEvent(dataDir, pointer.ID)
}

func (r *fail2banHostRetirement) journal(state string) Record {
	return Record{Kind: fail2banHostRetirementKind, OperationID: r.ID, RelatedOperationID: r.Root.OperationID, RequestHash: r.RequestHash, State: state, Stage: "scope_retired", CandidateHash: r.hash(), ObservedRevision: r.Absent.Fingerprint, Fail2banHostRetirementID: r.ID}
}

func (r *fail2banHostRetirement) record(dataDir string) (Record, error) {
	actual, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(r.ID)
	want := r.journal(actual.State)
	if err == nil && actual.State == "succeeded" {
		receipt, e := r.receipt(dataDir)
		if e != nil {
			return Record{}, e
		}
		want = r.completed(receipt)
	}
	if err != nil || !sameFail2banRetirementRecord(actual, want) || actual.State != "running" && actual.State != "succeeded" {
		return Record{}, errors.Join(errors.New("宿主机退役回执无法核对"), err)
	}
	return actual, nil
}

func fail2banHostRetirementIdle(dataDir string) error {
	r, err := loadFail2banHostRetirement(dataDir)
	if err != nil || r == nil {
		return err
	}
	record, err := r.record(dataDir)
	if err != nil {
		return err
	}
	if record.State != "succeeded" {
		return errors.New("宿主机动作退役尚未完成，须沿原操作续办")
	}
	return nil
}

func retiredFail2banHostRuntime(dataDir string, runtime *fail2banHostRuntime) (bool, error) {
	r, err := loadFail2banHostRetirement(dataDir)
	if err != nil || r == nil || r.Runtime == nil {
		return false, err
	}
	if _, err = r.record(dataDir); err != nil {
		return false, err
	}
	a, _ := json.Marshal(runtime)
	b, _ := json.Marshal(r.Runtime)
	return string(a) == string(b), nil
}

func (r *fail2banHostRetirement) released() *fail2banHostRegistration {
	return &fail2banHostRegistration{Schema: 1, Owner: r.Root.Owner, OperationID: r.RegistrationID, BaseOperationID: r.Root.OperationID, Action: "retire", State: "released", OperationState: "succeeded", RequestHash: fail2banHostRegistrationRequest("retire", r.RegistrationID, r.Root.OperationID), TransactionHash: r.hash(), Baseline: r.Absent, Confirmed: r.Root.Confirmed, RetirementID: r.ID, Error: "本机已退役失联动作范围；未重建目标或修改其他命名空间，原事务结果保留"}
}

func (r *fail2banHostRetirement) stopped() *fail2banHostSyncEvent {
	if r.Sync == nil || r.Sync.Action != "enable" {
		return nil
	}
	e := *r.Sync
	e.ID, e.PreviousID, e.Action, e.ApprovedAt, e.RetirementID = r.StopID, r.Sync.ID, "disable", r.RequestedAt, r.ID
	e.RequestHash = e.requestHash()
	return &e
}

func (r *fail2banHostRetirement) status(dataDir string) (Fail2banHostRetirementStatus, error) {
	out := Fail2banHostRetirementStatus{ID: r.ID, PreviousID: r.PreviousID, BeforeRegistration: r.Root.OperationID, AfterRegistration: r.RegistrationID, OldNamespace: r.Root.Baseline.NamespaceID, ObservedNamespace: r.Absent.NamespaceID, Reason: "原范围退役尚未完整发布，须沿原操作续办；不证明旧事务未执行"}
	if r.Runtime != nil {
		out.RuntimeID = r.Runtime.Intent.OperationID
	}
	if r.Sync != nil {
		out.SessionID = r.Sync.SessionID
	}
	record, err := r.record(dataDir)
	out.State = record.State
	if err == nil && record.State == "succeeded" {
		receipt, e := r.receipt(dataDir)
		if e != nil {
			return out, e
		}
		out.ObservedNamespace, out.CompletedAt = receipt.Kernel.NamespaceID, receipt.CompletedAt
		out.Reason = "完成退役时目标缺失，已关闭原授权；不证明历史事务未执行，也不重放封禁"
	}
	out.Disposition = "target_missing"
	if out.ObservedNamespace != out.OldNamespace {
		out.Disposition = "scope_changed"
		if out.State == "succeeded" {
			out.Reason = "完成退役时命名空间已变化；只关闭原授权，未核对或修改旧命名空间对象"
		}
	}
	return out, err
}

// No kernel mutation occurs here. Fresh absence is required until an immutable
// completion proof exists. Later namespace changes cannot replay an old ban.
func finishFail2banHostRetirement(ctx context.Context, dataDir string, r *fail2banHostRetirement) error {
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	record, err := r.record(dataDir)
	if err != nil {
		return err
	}
	if record.State == "succeeded" {
		return nil
	}
	receipt, err := r.receipt(dataDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if receipt == nil {
		if (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
			return errors.New("当前宿主机范围无法核对")
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		kernel, e := snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
		cancel()
		if e != nil || !validFail2banHostAbsence(kernel) {
			return errors.Join(errors.New("当前目标未证明缺失，禁止退役或覆盖同名表"), e)
		}
	}
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return err
	}
	if root == nil || root.OperationID != r.Root.OperationID && root.OperationID != r.RegistrationID {
		return errors.New("退役的登记基础变化")
	}
	wantRoot := r.Root
	if root.OperationID == r.RegistrationID {
		wantRoot = *r.released()
	}
	actualRoot := *root
	actualRoot.UpdatedAt, wantRoot.UpdatedAt = 0, 0
	a, _ := json.Marshal(actualRoot)
	b, _ := json.Marshal(wantRoot)
	if string(a) != string(b) {
		return errors.New("退役的完整登记材料变化")
	}
	current, err := loadFail2banHostRuntimeRecord(dataDir)
	if err != nil {
		return err
	}
	a, _ = json.Marshal(current)
	b, _ = json.Marshal(r.Runtime)
	if string(a) != string(b) {
		return errors.New("退役的原运行检查点变化")
	}
	sync, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return err
	}
	stop := r.stopped()
	wantSync := r.Sync
	if sync != nil && stop != nil && sync.ID == stop.ID {
		wantSync = stop
	}
	a, _ = json.Marshal(sync)
	b, _ = json.Marshal(wantSync)
	if string(a) != string(b) {
		return errors.New("退役的持续会话基础变化")
	}
	if stop != nil {
		stopping, e := loadFail2banHostSyncStop(dataDir, r.Sync)
		if e != nil {
			return e
		}
		wantStopping := r.Stopping
		if stopping != nil && stopping.ID == stop.ID {
			wantStopping = stop
		}
		a, _ = json.Marshal(stopping)
		b, _ = json.Marshal(wantStopping)
		if string(a) != string(b) {
			return errors.New("退役的原停止意图变化")
		}
	}
	if r.RuntimeCurrent && r.Runtime.Intent.ControllerID == "" {
		old, e := j.Get(r.Runtime.Intent.OperationID)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		original := fail2banHostRuntimeJournal(r.Runtime)
		if r.RuntimeJournal != nil {
			original = *r.RuntimeJournal
		}
		if original.State == "running" || original.State == "recovery_required" {
			want := original
			want.State, want.Stage, want.Error, want.Fail2banHostRetirementID = "failed", "retired_unconfirmed", "本机明确退役原范围；原内核事务结果未知，未重发或逆向补偿", r.ID
			if e == nil && !sameFail2banRetirementRecord(old, original) && !sameFail2banRetirementRecord(old, want) {
				return errors.New("退役的原手动回执变化")
			}
			if e != nil || !sameFail2banRetirementRecord(old, want) {
				if err = j.Put(want); err != nil {
					return err
				}
			}
		} else if r.RuntimeJournal != nil && (e != nil || !sameFail2banRetirementRecord(old, original)) {
			return errors.New("已完成的原手动回执变化，禁止覆盖历史")
		}
	}
	if stop != nil {
		parent, e := j.Get(r.Sync.ID)
		if e != nil {
			return e
		}
		want := *r.SyncParent
		want.State, want.Stage, want.Fail2banHostRetirementID = "succeeded", "disabled_retired", r.ID
		if !sameFail2banRetirementRecord(parent, *r.SyncParent) && !sameFail2banRetirementRecord(parent, want) {
			return errors.New("退役的父会话回执变化")
		}
		if !sameFail2banRetirementRecord(parent, want) {
			if err = j.Put(want); err != nil {
				return err
			}
		}
		if err = writeFail2banHostSyncEvent(dataDir, stop); err != nil {
			return err
		}
		if err = rootJSONWrite(filepath.Join(fail2banHostSyncDir(dataDir), "stopping.json"), struct {
			ID string `json:"id"`
		}{stop.ID}, 1024); err != nil {
			return err
		}
		if err = publishFail2banHostSync(dataDir, stop); err != nil {
			return err
		}
	}
	if root.OperationID != r.RegistrationID || !fail2banHostRegistrationReceipt(dataDir, root) {
		if err = saveFail2banHostRegistration(dataDir, r.released()); err != nil {
			return err
		}
	}
	if receipt == nil {
		if (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
			return errors.New("发布完成前宿主机范围变化，保留恢复阻塞")
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		kernel, e := snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
		cancel()
		if e != nil || !validFail2banHostAbsence(kernel) {
			return errors.Join(errors.New("退役发布后当前目标无法证明为空缺，保留恢复阻塞"), e)
		}
		receipt = &fail2banHostRetirementReceipt{Schema: 1, ID: r.ID, IntentHash: r.hash(), CompletedAt: time.Now().Unix(), Kernel: kernel}
		raw, e := json.Marshal(receipt)
		if e != nil {
			return e
		}
		if e = secure.RootDirectory(filepath.Dir(r.receiptPath(dataDir)), 0700); e != nil {
			return e
		}
		if e = writeFail2banJailImmutable(r.receiptPath(dataDir), raw, fail2banHostProtectionBytes); e != nil {
			return e
		}
	}
	return j.Put(r.completed(receipt))
}

func fail2banHostRetiredParent(dataDir string, parent Record, event *fail2banHostSyncEvent) (bool, error) {
	r, err := loadFail2banHostRetirementEvent(dataDir, parent.Fail2banHostRetirementID)
	if err != nil {
		return false, err
	}
	record, err := r.record(dataDir)
	if err != nil {
		return false, err
	}
	if r.Sync == nil || r.Sync.ID != event.ID || r.SyncParent == nil {
		return false, errors.New("退役父操作不属于原会话")
	}
	want := *r.SyncParent
	want.State, want.Stage, want.Fail2banHostRetirementID = "succeeded", "disabled_retired", r.ID
	return record.State == "succeeded" && sameFail2banRetirementRecord(parent, want), nil
}

func fail2banHostRetirementSyncView(dataDir string, out fail2ban.HostInputSyncView) fail2ban.HostInputSyncView {
	r, err := loadFail2banHostRetirement(dataDir)
	if err != nil {
		return fail2ban.EmptyHostInputSync("宿主机退役材料无法完整读取")
	}
	if r == nil {
		return out
	}
	record, err := r.record(dataDir)
	if err == nil && record.State == "succeeded" {
		return out
	}
	out.RetirementID, out.State, out.Queued = r.ID, "recovery_required", false
	out.CollectedAt, out.ConfirmedAt, out.SourceHash, out.KernelOperationID = 0, 0, "", ""
	out.Reason = "本机退役尚未完整发布，须沿原退役标识续办；不执行原封禁或重建对象"
	return out
}
