package agent

import (
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banUpgradeSwitchKind = "nginx.fail2ban-upgrade-switch"
const fail2banUpgradeSwitchLimit = 8 << 20

type Fail2banUpgradeSwitchOptions struct {
	DataDir, Scope, OperationID, PreparationID, SnapshotID, Target string
}

type fail2banUpgradeSwitch struct {
	Schema    int
	CreatedAt int64
	Request   Fail2banUpgradeSwitchOptions
	Prepared  fail2banUpgradePreparation
	Snapshot  fail2banStateReceipt
	Manifest  fail2banStateManifest
	Directory fail2banStateDirectory
	Kernel    firewall.KernelView
	After     fail2banManagedRecord
}

type fail2banUpgradeSwitchMarker struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	IntentSHA256 string `json:"intent_sha256"`
}

type fail2banUpgradeSwitchUndo struct {
	fail2banUpgradeSwitchMarker
	CreatedAt int64
	Managed   fail2banManagedRecord
	Nginx     *fail2banNginxRegistry
	Sources   *fail2banHostSourcesEvent
	Sync      *fail2banHostSyncEvent
}

type fail2banUpgradeSwitchReceipt struct {
	fail2banUpgradeSwitchMarker
	Outcome       string `json:"outcome"`
	CompletedAt   int64  `json:"completed_at"`
	ManagedEvent  string `json:"managed_event"`
	ManagedSHA256 string `json:"managed_sha256"`
}

type Fail2banUpgradeSwitchStatus struct {
	ID             string `json:"id"`
	PreparationID  string `json:"preparation_id"`
	SnapshotID     string `json:"snapshot_id"`
	InstallationID string `json:"installation_id"`
	State          string `json:"state"`
	Stage          string `json:"stage"`
	Outcome        string `json:"outcome"`
	EventID        string `json:"event_id"`
	CompletedAt    int64  `json:"completed_at"`
	Error          string `json:"error"`
}

func fail2banUpgradeSwitches(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-switches")
}
func (i fail2banUpgradeSwitch) dir() string {
	return filepath.Join(fail2banUpgradeSwitches(i.Request.DataDir), i.Request.OperationID)
}
func (i fail2banUpgradeSwitch) hash() string { return fail2banUpgradeGrantHash("stopped-switch", i) }
func (i fail2banUpgradeSwitch) marker() fail2banUpgradeSwitchMarker {
	return fail2banUpgradeSwitchMarker{1, i.Request.OperationID, i.hash()}
}

func fail2banUpgradeManagedEvent(source fail2banManagedRecord, id, previous, selection, action string, at int64) fail2banManagedRecord {
	source.EventID, source.PreviousEvent, source.At = id, previous, at
	source.State, source.Action, source.ActionState, source.Reason, source.JailSelection = "installed", action, "completed", "", selection
	return source
}

func (i fail2banUpgradeSwitch) validate(data, id string) error {
	in, p := i.Request, i.Prepared
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || in.PreparationID != p.Request.OperationID || in.SnapshotID != i.Snapshot.OperationID || in.Target != p.hash() || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || id == in.PreparationID || id == in.SnapshotID || in.PreparationID == in.SnapshotID {
		return errors.New("已停止实例升级切换意图无效")
	}
	if err := p.validate(data, in.PreparationID); err != nil {
		return err
	}
	service := p.Basis.Service
	if service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" {
		return errors.New("此切换事务仅接受已停止实例的准备材料")
	}
	if err := i.Snapshot.validate(data, in.SnapshotID); err != nil {
		return err
	}
	if err := i.Manifest.validate(data, in.SnapshotID); err != nil {
		return err
	}
	if i.Snapshot.CreatedAt != i.Manifest.CreatedAt || i.Snapshot.InstallationID != p.Basis.Current.OperationID || i.Snapshot.EventID != p.Basis.Current.EventID || i.Snapshot.Component != fail2banUpgradeComponent(&p.Basis.Current) || i.Snapshot.MachineID != i.Manifest.Basis.MachineID {
		return errors.New("原状态快照回执与安装及清单身份不匹配")
	}
	if i.Directory.Inode == 0 || i.Directory.SELinux != i.Manifest.Basis.StateLabel || fail2banUpgradeGrantHash("managed", i.Manifest.Basis.Managed) != fail2banUpgradeGrantHash("managed", p.Basis.Current) || fail2banUpgradeGrantHash("bundle", i.Manifest.Basis.Bundle) != fail2banUpgradeGrantHash("bundle", p.Basis.Bundle) {
		return errors.New("切换快照不属于原安装及完整配置选择")
	}
	manifest, err := fail2banStateJSON(i.Manifest)
	if err != nil {
		return err
	}
	if i.Snapshot.ManifestSHA256 != secure.Hash(manifest) {
		return errors.New("切换快照清单摘要不匹配")
	}
	expected := fail2banUpgradeManagedEvent(p.Basis.Candidate, i.After.EventID, p.Basis.Current.EventID, p.Material.IDs.Jails, "upgrade", i.CreatedAt)
	expected.Start, expected.Enable = p.Basis.Current.Start, p.Basis.Current.Enable
	if !validID(i.After.EventID) || fail2banUpgradeGrantHash("managed", expected) != fail2banUpgradeGrantHash("managed", i.After) {
		return errors.New("切换候选选择超出原批准")
	}
	if err = validateFail2banManagedRecord(i.After, data); err != nil {
		return err
	}
	if i.After.EventID == id || i.After.EventID == in.PreparationID || i.After.EventID == in.SnapshotID {
		return errors.New("切换操作和选择事件标识不得重复")
	}
	for _, reserved := range []string{p.Material.IDs.Jails, p.Material.IDs.Nginx, p.Material.IDs.Sources, p.Material.IDs.Sync} {
		if reserved != "" && (reserved == id || reserved == in.SnapshotID || reserved == i.After.EventID) {
			return errors.New("切换事件不得占用预留批准标识")
		}
	}
	for _, old := range fail2banUpgradeOriginalIDs(p.Basis, p.Recovery) {
		if old == id || old == in.SnapshotID || old == i.After.EventID {
			return errors.New("切换标识不得复用原操作或资源")
		}
	}
	if root := p.Basis.HostRegistration; root != nil && root.State == "registered" {
		program, expectedKernel := fail2banUpgradeOriginalHostProgram(p)
		if !fail2banHostProgramShape(program, i.Kernel) || i.Kernel.NamespaceID != expectedKernel.NamespaceID || i.Kernel.Fingerprint != expectedKernel.Fingerprint {
			return errors.New("原宿主机规则未完整证明，禁止移交批准")
		}
	} else if i.Kernel != (firewall.KernelView{}) {
		return errors.New("无宿主机登记的切换不接受内核证明")
	}
	return nil
}

func fail2banUpgradeOriginalHostProgram(p fail2banUpgradePreparation) (fail2banHostProgram, firewall.KernelView) {
	if p.Recovery.Runtime != nil {
		return p.Recovery.Runtime.effective(), p.Recovery.Runtime.Confirmed
	}
	marker, _ := nftTargetRegistrationMarker(firewall.NFTFail2banInput, p.Basis.HostRegistration.Owner)
	return fail2banHostProgram{Marker: marker}, p.Basis.HostRegistration.Confirmed
}

func (i fail2banUpgradeSwitch) parentBefore(id string) (*Record, error) {
	if before := i.Prepared.Basis.HostSync; before != nil && before.Action == "enable" && before.ID == id {
		if i.Prepared.Recovery.Parent == nil {
			return nil, errors.New("原持续会话缺少审计")
		}
		return i.Prepared.Recovery.Parent, nil
	}
	if after := i.Prepared.Material.Sync; after != nil && after.ID == id {
		r := fail2banHostSyncParent(after)
		return &r, nil
	}
	return nil, errors.New("持续会话不属于原切换范围")
}

func (i fail2banUpgradeSwitch) transferredParent(id string) (Record, error) {
	before, err := i.parentBefore(id)
	if err != nil {
		return Record{}, err
	}
	r := *before
	r.State, r.Stage, r.Fail2banUpgradeID = "succeeded", "transferred", i.Request.OperationID
	return r, nil
}

func (i fail2banUpgradeSwitch) record(receipt *fail2banUpgradeSwitchReceipt, undo *fail2banUpgradeSwitchUndo) Record {
	r := Record{Kind: fail2banUpgradeSwitchKind, OperationID: i.Request.OperationID, RelatedOperationID: i.Request.PreparationID, RequestHash: fail2banUpgradeGrantHash("switch-request", i.Request), CandidateHash: i.hash(), BeforeRevision: i.Prepared.Basis.Current.EventID, AfterRevision: i.After.EventID, State: "running", Stage: "switching"}
	if undo != nil {
		r.State, r.Stage, r.AfterRevision = "compensating", "reverting", undo.Managed.EventID
	}
	if receipt != nil {
		r.ObservedRevision = fail2banUpgradeGrantHash("switch-receipt", receipt)
		r.State, r.Stage = "succeeded", "selected_stopped"
		if receipt.Outcome == "reverted" {
			r.State, r.Stage, r.Error = "failed", "reverted", "已撤回停止实例的升级切换；保留原代码、状态快照及规则证明"
		}
	}
	return r
}

func (i fail2banUpgradeSwitch) status(r Record, receipt *fail2banUpgradeSwitchReceipt) Fail2banUpgradeSwitchStatus {
	out := Fail2banUpgradeSwitchStatus{ID: i.Request.OperationID, PreparationID: i.Request.PreparationID, SnapshotID: i.Request.SnapshotID, InstallationID: i.Prepared.Basis.Current.OperationID, State: r.State, Stage: r.Stage, Error: r.Error}
	if receipt != nil {
		out.Outcome, out.EventID, out.CompletedAt = receipt.Outcome, receipt.ManagedEvent, receipt.CompletedAt
	}
	return out
}
