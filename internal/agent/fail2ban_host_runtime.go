package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banHostRuntimeKind = "fail2ban_host_runtime"
const fail2banHostRuntimeBytes = 256 << 10

type fail2banHostProgram struct {
	Set    *firewall.NFTBanSet `json:"set"`
	Marker string              `json:"marker"`
}

func fail2banHostRuntimeMarker(owner, operationID string) string {
	return "nginxpanel:fail2ban:runtime:v1:" + owner + ":" + operationID
}

func (p fail2banHostProgram) valid(owner string) bool {
	if p.Set == nil {
		marker, err := nftTargetRegistrationMarker(firewall.NFTFail2banInput, owner)
		return err == nil && marker == p.Marker
	}
	id, ok := strings.CutPrefix(p.Marker, "nginxpanel:fail2ban:runtime:v1:"+owner+":")
	if !ok || !validID(id) {
		return false
	}
	set, err := p.Set.Normalize()
	a, _ := json.Marshal(set)
	b, _ := json.Marshal(p.Set)
	return err == nil && bytes.Equal(a, b)
}

func (p fail2banHostProgram) snapshot(ctx context.Context) (firewall.KernelView, error) {
	var program *firewall.NFTProgram
	var err error
	if p.Set != nil {
		program, err = firewall.CompileNFTBans(*p.Set)
		if err != nil {
			return firewall.KernelView{}, err
		}
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return snapshotNFTTargetProgram(call, firewall.NFTFail2banInput, program, p.Marker)
}

func (p fail2banHostProgram) batch(baseline firewall.KernelView) (firewall.NFTCreateBatch, error) {
	if p.Set == nil {
		return firewall.PrepareNFTBanEmpty(baseline, p.Marker)
	}
	return firewall.PrepareNFTBans(*p.Set, baseline, p.Marker)
}

type fail2banHostRuntimeIntent struct {
	Schema          int                            `json:"schema"`
	Owner           string                         `json:"owner"`
	RegistrationID  string                         `json:"registration_id"`
	OperationID     string                         `json:"operation_id"`
	BaseOperationID string                         `json:"base_operation_id"`
	ControllerID    string                         `json:"controller_id"`
	Action          string                         `json:"action"`
	RequestHash     string                         `json:"request_hash"`
	ProtectionID    string                         `json:"protection_id"`
	Sources         *fail2ban.HostInputSourcesView `json:"sources"`
	Before          fail2banHostProgram            `json:"before"`
	Candidate       fail2banHostProgram            `json:"candidate"`
	Baseline        firewall.KernelView            `json:"baseline"`
	TransactionHash string                         `json:"transaction_hash"`
}

type fail2banHostRuntime struct {
	Intent    fail2banHostRuntimeIntent `json:"intent"`
	State     string                    `json:"state"`
	Confirmed firewall.KernelView       `json:"confirmed"`
	UpdatedAt int64                     `json:"updated_at"`
	Error     string                    `json:"error"`
}

func fail2banHostRuntimeRequest(action, id, base string) string {
	return secure.Hash([]byte("nginxpanel:fail2ban-host-runtime:v1:" + action + ":" + id + ":" + base))
}

func (i fail2banHostRuntimeIntent) hash() string {
	raw, _ := json.Marshal(i)
	return secure.Hash(raw)
}

func validFail2banHostRuntimeKernel(k firewall.KernelView) bool {
	return k.Available && k.TableExists && k.Generation != 0 && fail2banDigest.MatchString(k.NamespaceID) && fail2banDigest.MatchString(k.Fingerprint) && k.ObservedAt > 0 && k.Bytes > 0 && k.Bytes <= nftReadBytes && k.Chains >= 0 && k.Chains <= 1 && k.Rules >= 0 && k.Rules <= firewall.NFTBanLimit+firewall.NFTBanProtectionLimit+2 && k.Reason == ""
}

func fail2banHostProgramShape(p fail2banHostProgram, k firewall.KernelView) bool {
	if !validFail2banHostRuntimeKernel(k) {
		return false
	}
	if p.Set == nil {
		return k.Chains == 0 && k.Rules == 0
	}
	return k.Chains == 1 && k.Rules == len(p.Set.Addresses)+len(p.Set.Protected)+2
}

func (i fail2banHostRuntimeIntent) valid() bool {
	if i.ControllerID != "" && !validID(i.ControllerID) || i.Schema != 1 || !validID(i.Owner) || !validID(i.RegistrationID) || !validID(i.OperationID) || i.BaseOperationID != "" && !validID(i.BaseOperationID) || i.BaseOperationID == i.OperationID || i.RequestHash != fail2banHostRuntimeRequest(i.Action, i.OperationID, i.BaseOperationID) || !i.Before.valid(i.Owner) || !i.Candidate.valid(i.Owner) || !fail2banHostProgramShape(i.Before, i.Baseline) {
		return false
	}
	switch i.Action {
	case "apply":
		if i.Candidate.Set == nil || i.Candidate.Marker != fail2banHostRuntimeMarker(i.Owner, i.OperationID) || !validID(i.ProtectionID) || i.Sources == nil || !i.Sources.Valid() || i.Sources.State != "ready" || len(i.Candidate.Set.Addresses) != i.Sources.BannedCount {
			return false
		}
	case "clear":
		if i.Candidate.Set != nil || i.Before.Set == nil || i.ProtectionID != "" || i.Sources != nil {
			return false
		}
	default:
		return false
	}
	batch, err := i.Candidate.batch(i.Baseline)
	return err == nil && i.TransactionHash == batch.Hash
}

func (v *fail2banHostRuntime) effective() fail2banHostProgram {
	if v.State == "failed" {
		return v.Intent.Before
	}
	return v.Intent.Candidate
}

func (v *fail2banHostRuntime) valid() bool {
	if !v.Intent.valid() || v.UpdatedAt <= 0 || len(v.Error) > 1024 {
		return false
	}
	switch v.State {
	case "running", "recovery_required":
		return v.Confirmed == (firewall.KernelView{}) && (v.State == "running" && v.Error == "" || v.State == "recovery_required" && v.Error != "")
	case "succeeded", "failed":
		if !fail2banHostProgramShape(v.effective(), v.Confirmed) || v.Confirmed.NamespaceID != v.Intent.Baseline.NamespaceID {
			return false
		}
		return v.State == "succeeded" && v.Error == "" || v.State == "failed" && v.Error != "" && v.Confirmed.Fingerprint == v.Intent.Baseline.Fingerprint
	}
	return false
}

func fail2banHostRuntimeDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-runtime")
}

func readFail2banHostRuntimeJSON(path string, value any) error {
	raw, err := listenerRead(path, fail2banHostRuntimeBytes)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("宿主机动作运行记录格式无效")
	}
	return nil
}

func loadFail2banHostRuntimeIntent(dataDir, id string) (*fail2banHostRuntimeIntent, error) {
	if !validID(id) {
		return nil, errors.New("宿主机动作运行标识无效")
	}
	var i fail2banHostRuntimeIntent
	if err := readFail2banHostRuntimeJSON(filepath.Join(fail2banHostRuntimeDir(dataDir), "intents", id+".json"), &i); err != nil {
		return nil, err
	}
	if i.OperationID != id || !i.valid() {
		return nil, errors.New("宿主机动作持久意图无效")
	}
	return &i, nil
}

func loadFail2banHostRuntime(dataDir string) (*fail2banHostRuntime, error) {
	v, err := loadFail2banHostRuntimeRecord(dataDir)
	if err != nil || v == nil {
		return v, err
	}
	retired, err := retiredFail2banHostRuntime(dataDir, v)
	if err != nil || retired {
		return nil, err
	}
	return v, nil
}

func loadFail2banHostRuntimeRecord(dataDir string) (*fail2banHostRuntime, error) {
	var v fail2banHostRuntime
	err := readFail2banHostRuntimeJSON(filepath.Join(fail2banHostRuntimeDir(dataDir), "current.json"), &v)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v.Intent.ControllerID != "" {
		event, e := loadFail2banHostSyncEvent(dataDir, v.Intent.ControllerID)
		if e != nil || event.Action != "enable" || !v.valid() || !fail2banHostSyncOwns(event, &v) {
			return nil, errors.Join(errors.New("持续同步检查点与本机批准不一致"), e)
		}
		return &v, nil
	}
	i, err := loadFail2banHostRuntimeIntent(dataDir, v.Intent.OperationID)
	if err != nil || !v.valid() || i.hash() != v.Intent.hash() {
		return nil, errors.Join(errors.New("宿主机动作运行记录与不可变意图不一致"), err)
	}
	return &v, nil
}

func fail2banHostRuntimeJournal(v *fail2banHostRuntime) Record {
	i := v.Intent
	return Record{Kind: fail2banHostRuntimeKind, OperationID: i.OperationID, RelatedOperationID: i.BaseOperationID, RequestHash: i.RequestHash, State: v.State, Stage: i.Action, BeforeRevision: i.Baseline.Fingerprint, AfterRevision: i.hash(), CandidateHash: i.TransactionHash, ObservedRevision: v.Confirmed.Fingerprint, Error: v.Error}
}

func fail2banHostRuntimeReceipt(dataDir string, v *fail2banHostRuntime) bool {
	if v.Intent.ControllerID != "" {
		return fail2banHostSyncRuntimeReceipt(dataDir, v)
	}
	r, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(v.Intent.OperationID)
	want := fail2banHostRuntimeJournal(v)
	return err == nil && r.Kind == want.Kind && r.OperationID == want.OperationID && r.RelatedOperationID == want.RelatedOperationID && r.RequestHash == want.RequestHash && r.State == want.State && r.Stage == want.Stage && r.BeforeRevision == want.BeforeRevision && r.AfterRevision == want.AfterRevision && r.CandidateHash == want.CandidateHash && r.ObservedRevision == want.ObservedRevision && r.Error == want.Error
}

// The immutable full intent precedes the checkpoint and audit. No submit is
// permitted until all three are durable. Terminal receipts cannot be changed.
func saveFail2banHostRuntime(dataDir string, v *fail2banHostRuntime) error {
	v.UpdatedAt = time.Now().Unix()
	if !v.valid() {
		return errors.New("拒绝保存无效宿主机动作运行记录")
	}
	if v.Intent.ControllerID != "" {
		return saveFail2banHostSyncRuntime(dataDir, v)
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if err := secure.RootDirectory(j.Dir, 0700); err != nil {
		return err
	}
	want := fail2banHostRuntimeJournal(v)
	previous, err := j.Get(v.Intent.OperationID)
	if err == nil {
		if previous.Kind != want.Kind || previous.RequestHash != want.RequestHash || previous.RelatedOperationID != want.RelatedOperationID || previous.Stage != want.Stage || previous.BeforeRevision != want.BeforeRevision || previous.AfterRevision != want.AfterRevision || previous.CandidateHash != want.CandidateHash {
			return errors.New("宿主机动作操作标识已用于其他意图")
		}
		if (previous.State == "succeeded" || previous.State == "failed") && (previous.State != want.State || previous.ObservedRevision != want.ObservedRevision || previous.Error != want.Error) {
			return errors.New("禁止改写已终结宿主机动作审计")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := fail2banHostRuntimeDir(dataDir)
	intents := filepath.Join(dir, "intents")
	if err = secure.RootDirectory(intents, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(intents)
	if err != nil {
		return err
	}
	path := filepath.Join(intents, v.Intent.OperationID+".json")
	if len(entries) >= 2048 {
		if _, err = os.Lstat(path); err != nil {
			return errors.New("宿主机动作意图容量已满，须本机维护")
		}
	}
	raw, err := json.Marshal(v.Intent)
	if err != nil {
		return err
	}
	if err = writeFail2banJailImmutable(path, raw, fail2banHostRuntimeBytes); err != nil {
		return err
	}
	if err = rootJSONWrite(filepath.Join(dir, "current.json"), v, fail2banHostRuntimeBytes); err != nil {
		return err
	}
	return j.Put(want)
}

func fail2banHostRuntimeMatches(v *fail2banHostRuntime, root *fail2banHostRegistration) bool {
	return root != nil && root.State == "registered" && v.Intent.Owner == root.Owner && v.Intent.RegistrationID == root.OperationID && v.Intent.Baseline.NamespaceID == root.Confirmed.NamespaceID
}

// Changing the selected engine must not strand an approved continuous session
// or an explicitly installed host snapshot.
func fail2banHostRuntimeIdle(dataDir string) error {
	if err := fail2banHostRetirementIdle(dataDir); err != nil {
		return err
	}
	if err := fail2banHostSyncInactive(dataDir); err != nil {
		return err
	}
	v, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return err
	}
	if v != nil && (v.State == "running" || v.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, v) || v.effective().Set != nil) {
		return errors.New("宿主机动作仍有规则或待核对事务，须先恢复原操作并明确清除动作规则")
	}
	return nil
}

// The original empty registration remains immutable. A completed matching
// runtime receipt hands its current fingerprint back to ownership readers.
func fail2banHostOwnedKernel(dataDir string, root *fail2banHostRegistration) (firewall.KernelView, error) {
	v, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return firewall.KernelView{}, err
	}
	if v == nil {
		return root.Confirmed, nil
	}
	if v.State == "running" || v.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, v) {
		return firewall.KernelView{}, errors.New("宿主机动作运行意图或回执待恢复")
	}
	if !fail2banHostRuntimeMatches(v, root) {
		return root.Confirmed, nil
	}
	return v.Confirmed, nil
}

func fail2banHostRuntimeView(dataDir string, kernel firewall.KernelView, root *fail2banHostRegistration) fail2ban.HostInputRuntimeView {
	out := fail2ban.EmptyHostInputRuntime("尚未核对宿主机动作运行记录")
	v, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		out.Reason = "宿主机动作运行记录无法完整读取"
		return out
	}
	if v == nil {
		out.State, out.Reason = "uninitialized", "当前登记尚无运行规则操作"
		return out
	}
	out.OperationID, out.Action, out.OperationState, out.UpdatedAt = v.Intent.OperationID, v.Intent.Action, v.State, v.UpdatedAt
	if !fail2banHostRuntimeMatches(v, root) {
		out.State, out.Reason = "drifted", "原运行记录不属于当前登记，保留历史操作标识，不重放封禁"
		return out
	}
	if v.State == "running" || v.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, v) {
		out.State, out.Reason = "recovery_required", "宿主机动作提交结果未核对，须本机恢复原操作"
		return out
	}
	if !kernel.Available {
		out.Reason = "内核快照不可用"
		return out
	}
	if !kernel.TableExists {
		out.State, out.Reason = "missing", "已确认宿主机动作表缺失，不自动重建或重放封禁"
		return out
	}
	if !fail2banHostRegistrationReceipt(dataDir, root) || kernel.NamespaceID != v.Confirmed.NamespaceID || kernel.Fingerprint != v.Confirmed.Fingerprint {
		out.State, out.Reason = "drifted", "宿主机动作对象或独立登记发生变化，禁止覆盖"
		return out
	}
	out.State, out.Verified, out.Reason = "empty", true, v.Error
	if p := v.effective(); p.Set != nil {
		out.State, out.BannedCount, out.ProtectedCount = "applied", len(p.Set.Addresses), len(p.Set.Protected)
	}
	return out
}
