package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

const fail2banHostBootRecoveryKind = "fail2ban_host_boot_recovery"
const fail2banHostBootRecoveryBytes = 64 << 10
const fail2banHostBootCancelled = "本机已取消本次启动恢复；现场和原事务结果保留，须显式停用或退役后重新核对"

// The original local grant and immutable retirement are the authority for one
// new boot. No IP sample, kernel transaction or imported approval is replayed.
type fail2banHostBootRecovery struct {
	Schema         int                         `json:"schema"`
	ID             string                      `json:"id"`
	PreviousID     string                      `json:"previous_id"`
	RetirementID   string                      `json:"retirement_id"`
	RetirementHash string                      `json:"retirement_hash"`
	BootID         string                      `json:"boot_id"`
	NamespaceID    string                      `json:"namespace_id"`
	Owner          string                      `json:"owner"`
	RegistrationID string                      `json:"registration_id"`
	ProtectionID   string                      `json:"protection_id"`
	SourcesID      string                      `json:"sources_id"`
	SyncID         string                      `json:"sync_id"`
	ApprovedAt     int64                       `json:"approved_at"`
	Protection     fail2banHostProtectionEvent `json:"protection"`
	Sources        fail2banHostSourcesEvent    `json:"sources"`
}

func fail2banHostBootRecoveryDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-boot-recovery")
}

func (r *fail2banHostBootRecovery) retirement(dataDir string) (*fail2banHostRetirement, error) {
	old, err := loadFail2banHostRetirementEvent(dataDir, r.RetirementID)
	if err != nil {
		return nil, err
	}
	if old.hash() != r.RetirementHash {
		return nil, errors.New("启动恢复的原退役材料变化")
	}
	return old, nil
}

func (r *fail2banHostBootRecovery) valid(dataDir string) error {
	if r.Schema != 1 || r.ApprovedAt <= 0 || r.PreviousID != "" && !validID(r.PreviousID) || !validID(r.BootID) || !fail2banDigest.MatchString(r.NamespaceID) || !fail2banDigest.MatchString(r.RetirementHash) {
		return errors.New("启动恢复意图无效")
	}
	ids := map[string]bool{}
	for _, id := range []string{r.ID, r.RetirementID, r.Owner, r.RegistrationID, r.ProtectionID, r.SourcesID, r.SyncID} {
		if !validID(id) || ids[id] || id == r.PreviousID {
			return errors.New("启动恢复的新标识无效或重复")
		}
		ids[id] = true
	}
	old, err := r.retirement(dataDir)
	if err != nil {
		return err
	}
	s := old.Sync
	if s == nil || s.Action != "enable" || !s.RecoverOnBoot || s.BootID == r.BootID || s.NamespaceID == r.NamespaceID || r.NamespaceID != old.Absent.NamespaceID || r.Owner == old.Root.Owner {
		return errors.New("原持续会话未授权此启动恢复范围")
	}
	for label, actual := range map[string]string{"recovery": r.ID, "retirement": r.RetirementID, "owner": r.Owner, "registration": r.RegistrationID, "protection": r.ProtectionID, "sources": r.SourcesID, "sync": r.SyncID} {
		if actual != fail2banHostBootOperationID(label, s.ID, r.BootID) {
			return errors.New("启动恢复标识不属于原会话和目标启动")
		}
	}
	if !r.Protection.valid() || r.Protection.Action != "approve" || r.Protection.ID != s.ProtectionID || r.Protection.Owner != s.Owner || r.Protection.RegistrationID != s.RegistrationID || r.Protection.NamespaceID != s.NamespaceID || !r.Sources.valid() || r.Sources.Action != "approve" || r.Sources.ID != s.SourcesID || r.Sources.Owner != s.Owner || r.Sources.RegistrationID != s.RegistrationID || r.Sources.NamespaceID != s.NamespaceID || r.Sources.EngineKey != s.EngineKey {
		return errors.New("启动恢复的保护或官方来源不属于原持续批准")
	}
	return nil
}

func (r *fail2banHostBootRecovery) hash() string {
	raw, _ := json.Marshal(r)
	return secure.Hash(raw)
}

func loadFail2banHostBootRecoveryEvent(dataDir, id string) (*fail2banHostBootRecovery, error) {
	if !validID(id) {
		return nil, errors.New("启动恢复标识无效")
	}
	raw, err := listenerRead(filepath.Join(fail2banHostBootRecoveryDir(dataDir), "events", id+".json"), fail2banHostBootRecoveryBytes)
	if err != nil {
		return nil, err
	}
	var r fail2banHostBootRecovery
	if err = decodeFail2banNginxJSON(raw, &r); err != nil {
		return nil, err
	}
	if r.ID != id {
		return nil, errors.New("启动恢复文件标识不匹配")
	}
	return &r, r.valid(dataDir)
}

func loadFail2banHostBootRecovery(dataDir string) (*fail2banHostBootRecovery, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostBootRecoveryDir(dataDir), "current.json"), &p); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadFail2banHostBootRecoveryEvent(dataDir, p.ID)
}

func (r *fail2banHostBootRecovery) protection() *fail2banHostProtectionEvent {
	e := r.Protection
	e.ID, e.PreviousID, e.Owner, e.RegistrationID, e.NamespaceID, e.ApprovedAt = r.ProtectionID, e.ID, r.Owner, r.RegistrationID, r.NamespaceID, r.ApprovedAt
	e.RequestHash = e.requestHash()
	return &e
}

func (r *fail2banHostBootRecovery) sources() *fail2banHostSourcesEvent {
	e := r.Sources
	e.ID, e.PreviousID, e.Owner, e.RegistrationID, e.NamespaceID, e.ApprovedAt = r.SourcesID, e.ID, r.Owner, r.RegistrationID, r.NamespaceID, r.ApprovedAt
	e.RequestHash = e.requestHash()
	return &e
}

func (r *fail2banHostBootRecovery) sync(old *fail2banHostRetirement) *fail2banHostSyncEvent {
	e := *old.Sync
	e.ID, e.SessionID, e.PreviousID, e.Owner, e.RegistrationID, e.NamespaceID = r.SyncID, r.SyncID, old.StopID, r.Owner, r.RegistrationID, r.NamespaceID
	e.RuntimeBaseID, e.RetirementID, e.BootID, e.RecoveryID, e.ApprovedAt = "", "", r.BootID, r.ID, r.ApprovedAt
	e.ProtectionID, e.SourcesID = r.ProtectionID, r.SourcesID
	e.RequestHash = e.requestHash()
	return &e
}

func (r *fail2banHostBootRecovery) journal(state string) Record {
	out := Record{Kind: fail2banHostBootRecoveryKind, OperationID: r.ID, RelatedOperationID: r.RetirementID, RequestHash: r.hash(), CandidateHash: r.hash(), State: state, Stage: "recovering", AfterRevision: r.SyncID}
	switch state {
	case "succeeded":
		out.Stage = "resumed"
	case "cancelled":
		out.Stage, out.Error = "cancelled", fail2banHostBootCancelled
	}
	return out
}

func (r *fail2banHostBootRecovery) validateRecord(actual Record) error {
	want := r.journal(actual.State)
	if actual.State == "running" {
		want.Error = actual.Error
	}
	if len(actual.Error) > 1024 || actual.State != "running" && actual.State != "succeeded" && actual.State != "cancelled" || !sameFail2banRetirementRecord(actual, want) {
		return errors.New("启动恢复回执不匹配")
	}
	return nil
}

func (r *fail2banHostBootRecovery) record(dataDir string) (Record, error) {
	out, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(r.ID)
	if err != nil {
		return out, err
	}
	return out, r.validateRecord(out)
}

func fail2banHostBootRecoveryIdle(dataDir string) error {
	r, err := loadFail2banHostBootRecovery(dataDir)
	if err != nil || r == nil {
		return err
	}
	record, err := r.record(dataDir)
	if err != nil {
		return err
	}
	if record.State == "running" {
		return errors.New("宿主机启动恢复尚未结束，须核对原操作或明确取消")
	}
	return nil
}

func fail2banHostBootRecoveryView(dataDir string, out fail2ban.HostInputSyncView) fail2ban.HostInputSyncView {
	r, err := loadFail2banHostBootRecovery(dataDir)
	if err != nil {
		return fail2ban.EmptyHostInputSync("启动恢复材料无法完整读取")
	}
	if r == nil {
		return out
	}
	old, err := r.retirement(dataDir)
	if err != nil {
		return fail2ban.EmptyHostInputSync("启动恢复的原范围无法核对")
	}
	record, err := r.record(dataDir)
	if err == nil && record.State == "succeeded" {
		return out
	}
	if out.ID != old.Sync.ID && out.ID != old.StopID && out.ID != r.SyncID {
		if err == nil && record.State == "cancelled" {
			return out
		}
		return fail2ban.EmptyHostInputSync("启动恢复期间持续会话发生变化")
	}
	out.RecoveryID, out.RecoverOnBoot, out.State, out.Reason = r.ID, true, "recovering", "正在恢复本机启动范围；尚未确认新的持续保护"
	if err != nil || record.Error != "" {
		out.State, out.Reason = "recovery_required", "启动恢复尚未完成，须核对原操作"
		if err == nil {
			out.Reason = record.Error
		}
	}
	if err == nil && record.State == "cancelled" {
		out.RecoverOnBoot, out.State, out.Reason = false, "paused", fail2banHostBootCancelled
	}
	out.Queued, out.CollectedAt, out.ConfirmedAt, out.SourceHash, out.KernelOperationID = false, 0, 0, "", ""
	return out
}

func ensureFail2banHostBootRecoveryRecord(dataDir string, r *fail2banHostBootRecovery) error {
	if _, err := r.record(dataDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := checkFail2banHostBootRecoveryBase(dataDir, r); err != nil {
		return err
	}
	return (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(r.journal("running"))
}

func checkFail2banHostBootRecoveryBase(dataDir string, r *fail2banHostBootRecovery) error {
	old, err := r.retirement(dataDir)
	if err != nil {
		return err
	}
	if err = checkFail2banHostRetirementBase(dataDir, old); err != nil {
		return err
	}
	protection, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return err
	}
	sources, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(protection)
	b, _ := json.Marshal(r.Protection)
	c, _ := json.Marshal(sources)
	d, _ := json.Marshal(r.Sources)
	if string(a) != string(b) || string(c) != string(d) {
		return errors.New("尚未开始的启动恢复授权基础变化")
	}
	return nil
}

func fail2banHostBootRecoveryFailure(dataDir string, r *fail2banHostBootRecovery, err error) error {
	record, readErr := r.record(dataDir)
	if readErr != nil || record.State != "running" {
		return errors.Join(err, readErr)
	}
	reason := err.Error()
	if len(reason) > 1024 {
		reason = "启动恢复失败，诊断超过记录上限；须本机核对原操作与官方实例"
	}
	if record.Error == reason {
		return err
	}
	record.Error = reason
	return errors.Join(err, (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(record))
}

// Grant publication, not a ban sample, completes this parent. The ordinary
// sync worker still has to collect and prove the first new kernel rule set.
func finishFail2banHostBootRecovery(dataDir string, r *fail2banHostBootRecovery) error {
	return (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(r.journal("succeeded"))
}

func newFail2banHostBootRecovery(previous *fail2banHostBootRecovery, old *fail2banHostRetirement, boot string, protection *fail2banHostProtectionEvent, sources *fail2banHostSourcesEvent) *fail2banHostBootRecovery {
	id := func(label string) string { return fail2banHostBootOperationID(label, old.Sync.ID, boot) }
	r := &fail2banHostBootRecovery{Schema: 1, ID: id("recovery"), RetirementID: old.ID, RetirementHash: old.hash(), BootID: boot, NamespaceID: old.Absent.NamespaceID, Owner: id("owner"), RegistrationID: id("registration"), ProtectionID: id("protection"), SourcesID: id("sources"), SyncID: id("sync"), ApprovedAt: time.Now().Unix(), Protection: *protection, Sources: *sources}
	if previous != nil {
		r.PreviousID = previous.ID
	}
	return r
}

// Stable IDs bound preparation retries before pointer publication; they are
// operation identifiers, never credentials or authority to invoke a child.
func fail2banHostBootOperationID(label, session, boot string) string {
	h := secure.Hash([]byte("nginxpanel:fail2ban-host-boot:v1:" + label + ":" + session + ":" + boot))
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}
