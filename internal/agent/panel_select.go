package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const panelSelectKind = "panel.select"

var panelSelectionDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type PanelSelectionIntent struct {
	Stage                panelruntime.StageInput `json:"stage"`
	MaintenanceID        string                  `json:"maintenance_id"`
	Snapshot             panelrecovery.Receipt   `json:"snapshot"`
	BeforeID             string                  `json:"before_id"`
	TargetID             string                  `json:"target_id"`
	BindingSHA256        string                  `json:"binding_sha256"`
	ApprovalSHA256       string                  `json:"approval_sha256"`
	DatabaseSchema       int64                   `json:"database_schema"`
	BeforeDatabaseSchema int64                   `json:"before_database_schema"`
}

func selectionHash(id string, in PanelSelectionIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int                  `json:"protocol"`
		ID       string               `json:"operation_id"`
		Intent   PanelSelectionIntent `json:"intent"`
	}{Protocol, id, in})
	return secure.Hash(raw)
}

func selectionValueHash(value any) string {
	raw, _ := json.Marshal(value)
	return secure.Hash(raw)
}

func validPanelSelection(r Record) error {
	i := r.PanelSelection
	if r.Kind != panelSelectKind || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) || i == nil {
		return errors.New("面板版本选择记录身份无效")
	}
	if err := i.Snapshot.Validate(i.Stage.DataDir, i.Snapshot.Manifest.OperationID); err != nil {
		return err
	}
	if !validID(i.MaintenanceID) || i.Snapshot.Manifest.MaintenanceID != i.MaintenanceID || !panelSelectionDigest.MatchString(i.Stage.PlanID) || !filepath.IsAbs(i.Stage.TrustPath) || filepath.Clean(i.Stage.TrustPath) != i.Stage.TrustPath || len(i.Stage.TrustPath) > 512 || !panelSelectionDigest.MatchString(i.BeforeID) || !panelSelectionDigest.MatchString(i.TargetID) || i.BeforeID == i.TargetID || !panelSelectionDigest.MatchString(i.BindingSHA256) || !panelSelectionDigest.MatchString(i.ApprovalSHA256) || i.DatabaseSchema < i.Snapshot.Manifest.Database.SchemaVersion || r.RequestHash != selectionHash(r.OperationID, *i) {
		return errors.New("面板版本选择记录与原批准不一致")
	}
	if !(r.State == "running" && r.Stage == "selecting" || r.State == "recovery_required" && r.Stage == "selecting" || r.State == "succeeded" && r.Stage == "version_selected") {
		return errors.New("面板版本选择阶段无效")
	}
	if i.BeforeDatabaseSchema <= 0 || i.DatabaseSchema < i.BeforeDatabaseSchema {
		return errors.New("版本选择不能直接降低程序数据库版本")
	}
	return nil
}

// SelectPanelVersion changes only the persistent program pointer. A root
// operator must stop serve first; readiness, service control and complete
// program/data rollback belong to the independent update worker.
func SelectPanelVersion(ctx context.Context, in panelruntime.StageInput, id, snapshot, maintenanceID, epoch string) (Record, error) {
	var out Record
	if os.Geteuid() != 0 || !validID(id) || !validID(snapshot) || !validID(maintenanceID) || !validID(epoch) || id == maintenanceID {
		return out, errors.New("版本选择需要 root、操作标识和原维护授权")
	}
	if _, err := panelruntime.Root(in.DataDir); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".panel-select.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	if err = installGrant(j, maintenanceID, epoch, true); err != nil {
		return out, err
	}
	prior, err := panelSelectionRecord(in.DataDir, id)
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		return out, err
	}
	if !fresh {
		i := prior.PanelSelection
		if i.Stage != in || i.MaintenanceID != maintenanceID || i.Snapshot.Manifest.OperationID != snapshot {
			return out, errors.New("操作标识已有不同的版本选择授权")
		}
		out = prior
		// Historical success is a receipt, never permission to overwrite a later
		// selection. It does not claim that this version is still running.
		if out.State == "succeeded" {
			return out, nil
		}
	}
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		if r.OperationID == id {
			continue
		}
		if r.Kind == "maintenance.lock" {
			if r.State != "succeeded" && r.OperationID != maintenanceID {
				return out, errors.New("存在其他未结束的维护会话")
			}
			continue
		}
		settled, e := settledPanelUpdate(r, maintenanceID)
		if e != nil {
			return out, e
		}
		if settled {
			continue
		}
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return out, errors.New("仍有其他独立任务执行中或待恢复")
		}
	}
	uid, gid, err := panelSnapshotIdentity(in.DataDir)
	if err != nil {
		return out, err
	}
	hold, holdErr := storage.ReadServiceHold(in.DataDir)
	if holdErr == nil {
		if hold.MaintenanceID != maintenanceID {
			return out, errors.New("面板由其他维护会话停机")
		}
	} else if !errors.Is(holdErr, os.ErrNotExist) {
		return out, holdErr
	}
	unlockWriter, err := storage.LockWriterForMaintenance(in.DataDir, gid)
	if err != nil {
		return out, err
	}
	defer unlockWriter()
	current, err := panelruntime.Read(in.DataDir)
	if err != nil {
		return out, err
	}
	if current.Deployment.UID != uid || current.Deployment.GID != gid {
		return out, errors.New("版本选择与专用面板账户不一致")
	}
	if holdErr == nil && (hold.BindingSHA256 != selectionValueHash(current.Deployment) || fresh && current.Release.ID != hold.ReleaseID) {
		return out, errors.New("持久停机期间只能从原停机版本选择一次目标程序")
	}
	var recovery panelrecovery.Result
	if fresh || current.Release.ID == out.PanelSelection.BeforeID {
		recovery, err = panelrecovery.Inspect(ctx, in.DataDir, snapshot)
		if err != nil {
			return out, err
		}
		m := recovery.Receipt.Manifest
		if fresh && recovery.Expired || m.MaintenanceID != maintenanceID || m.UID != uid || m.GID != gid {
			return out, errors.New("快照已过期或不属于原维护会话和面板账户")
		}
		if !fresh && selectionValueHash(recovery.Receipt) != selectionValueHash(out.PanelSelection.Snapshot) {
			return out, errors.New("原版本选择的恢复快照已变化")
		}
	}
	target, err := panelruntime.Staged(ctx, in)
	if err != nil {
		return out, err
	}
	if fresh {
		m := recovery.Receipt.Manifest
		if target.Compatibility.DatabaseSchema < m.Database.SchemaVersion || target.Compatibility.DatabaseSchema < current.Release.DatabaseSchema {
			return out, errors.New("目标程序的数据库版本低于当前程序或快照，禁止直接降级")
		}
		if target.Release.ID == current.Release.ID {
			return out, errors.New("目标版本已经是当前选择，无需切换")
		}
		intent := &PanelSelectionIntent{Stage: in, MaintenanceID: maintenanceID, Snapshot: recovery.Receipt, BeforeID: current.Release.ID, TargetID: target.Release.ID, BindingSHA256: selectionValueHash(current.Deployment), ApprovalSHA256: selectionValueHash(target.Approval), DatabaseSchema: target.Compatibility.DatabaseSchema, BeforeDatabaseSchema: current.Release.DatabaseSchema}
		out = Record{OperationID: id, Kind: panelSelectKind, State: "running", Stage: "selecting", MaintenanceEpoch: epoch, PanelSelection: intent, Deadline: time.Now().Unix() + 600}
		out.RequestHash = selectionHash(id, *intent)
	}
	i := out.PanelSelection
	if i.BindingSHA256 != selectionValueHash(current.Deployment) || i.ApprovalSHA256 != selectionValueHash(target.Approval) || i.TargetID != target.Release.ID || i.DatabaseSchema != target.Compatibility.DatabaseSchema || i.Snapshot.Manifest.UID != uid || i.Snapshot.Manifest.GID != gid {
		return out, errors.New("版本选择的运行绑定或批准已变化")
	}
	out.State, out.Error = "running", ""
	if err = j.Put(out); err == nil {
		if err = ctx.Err(); err == nil {
			err = panelruntime.SwitchCurrent(in.DataDir, i.BeforeID, i.TargetID, id)
		}
	}
	if err != nil {
		out.State, out.Error = "recovery_required", panelRestoreError(err)
		if save := j.Put(out); save != nil {
			return out, errors.Join(err, save)
		}
		return out, err
	}
	out.State, out.Stage = "succeeded", "version_selected"
	if err = j.Put(out); err != nil {
		return out, err
	}
	return panelSelectionRecord(in.DataDir, id)
}

func panelSelectionRecord(data, id string) (Record, error) {
	var out Record
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 64<<10)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || string(raw) != string(canonical) {
		return out, errors.New("版本选择记录不是原始规范记录")
	}
	if err = validPanelSelection(out); err != nil {
		return out, err
	}
	if out.OperationID != id || out.PanelSelection.Stage.DataDir != data {
		return out, errors.New("版本选择记录不属于当前节点")
	}
	return out, nil
}

func PanelSelectionStatus(data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("版本选择查询需要 root 和原操作标识")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return Record{}, err
	}
	return panelSelectionRecord(data, id)
}
