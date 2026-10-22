package agent

import (
	"context"
	"encoding/json"
	"errors"
	"nginxpanel/internal/protocol"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const panelRestoreKind = "panel.restore"

type PanelRestoreIntent struct {
	Receipt panelrecovery.Receipt    `json:"receipt"`
	Before  []panelrecovery.Original `json:"before,omitempty"`
}

func panelRestoreHash(id string, receipt panelrecovery.Receipt) string {
	raw, _ := json.Marshal(struct {
		Protocol int                   `json:"protocol"`
		ID       string                `json:"operation_id"`
		Receipt  panelrecovery.Receipt `json:"receipt"`
	}{protocol.Journal, id, receipt})
	return secure.Hash(raw)
}

func validPanelRestoreRecord(r Record) error {
	if r.Kind != panelRestoreKind || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) || r.PanelRestore == nil {
		return errors.New("面板恢复独立记录身份无效")
	}
	i := r.PanelRestore
	if err := i.Receipt.Validate(i.Receipt.Manifest.DataDir, i.Receipt.Manifest.OperationID); err != nil {
		return err
	}
	if r.RequestHash != panelRestoreHash(r.OperationID, i.Receipt) {
		return errors.New("面板恢复独立记录与原批准不一致")
	}
	if r.Stage != "preparing" && r.Stage != "restoring" && r.Stage != "files_restored" || r.State != "running" && r.State != "recovery_required" && r.State != "succeeded" || (r.State == "succeeded") != (r.Stage == "files_restored") {
		return errors.New("面板恢复独立记录阶段无效")
	}
	if r.Stage == "preparing" {
		if len(i.Before) != 0 {
			return errors.New("准备阶段已有不匹配的恢复前清单")
		}
	} else if err := panelrecovery.ValidateOriginals(i.Before); err != nil {
		return err
	}
	return nil
}

func restoreFence(r Record) storage.WriterFence {
	return storage.WriterFence{Schema: 1, OperationID: r.OperationID, SnapshotID: r.PanelRestore.Receipt.Manifest.OperationID, MaintenanceID: r.PanelRestore.Receipt.Manifest.MaintenanceID, RequestSHA256: r.RequestHash}
}

// RestorePanelSnapshot installs data only. It does not start any process,
// choose a release or declare application readiness; the parent update worker
// must pair these files with the approved program and confirm health separately.
func RestorePanelSnapshot(ctx context.Context, data, id, snapshot, maintenanceID, epoch string) (Record, error) {
	var out Record
	if os.Geteuid() != 0 || !validID(id) || !validID(snapshot) || !validID(maintenanceID) || !validID(epoch) || id == maintenanceID {
		return out, errors.New("面板恢复须由 root 提供操作、快照和原维护授权")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	if _, err := panelruntime.Root(data); err != nil {
		return out, err
	}
	unlock, err := j.waitRootLock(ctx, ".panel-restore.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	// Closing after an Agent restart remains the same unreleased maintenance
	// grant. The caller must supply its current epoch, not the captured old epoch.
	if err = installGrant(j, maintenanceID, epoch, true); err != nil {
		return out, err
	}
	prior, err := panelRestoreRecord(data, id)
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		return out, err
	}
	if !fresh {
		if err = validPanelRestoreRecord(prior); err != nil {
			return out, err
		}
		m := prior.PanelRestore.Receipt.Manifest
		if m.DataDir != data || m.OperationID != snapshot || m.MaintenanceID != maintenanceID {
			return out, errors.New("恢复标识已有不同快照或维护授权")
		}
		out = prior
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
	uid, gid, err := panelSnapshotIdentity(data)
	if err != nil {
		return out, err
	}
	if !fresh && (out.PanelRestore.Receipt.Manifest.UID != uid || out.PanelRestore.Receipt.Manifest.GID != gid) {
		return out, errors.New("恢复批准账户已变化")
	}
	if !fresh && out.State == "succeeded" {
		present, err := storage.WriterFenced(data)
		if err != nil {
			return out, err
		}
		if !present {
			return out, nil
		}
		unlockWriter, err := storage.LockWriterForRecovery(data, gid)
		if err != nil {
			return out, err
		}
		defer unlockWriter()
		return out, storage.ClearWriterFence(data, restoreFence(out))
	}
	unlockWriter, err := storage.LockWriterForRecovery(data, gid)
	if err != nil {
		return out, err
	}
	defer unlockWriter()
	if fresh {
		fenced, err := storage.WriterFenced(data)
		if err != nil {
			return out, err
		}
		if fenced {
			return out, errors.New("恢复标记存在但原独立记录缺失，不能重建授权")
		}
		r, err := panelrecovery.Inspect(ctx, data, snapshot)
		if err != nil {
			return out, err
		}
		m := r.Receipt.Manifest
		if m.MaintenanceID != maintenanceID || m.UID != uid || m.GID != gid {
			return out, errors.New("快照不属于原维护会话或当前面板账户")
		}
		out = Record{OperationID: id, Kind: panelRestoreKind, State: "running", Stage: "preparing", MaintenanceEpoch: epoch, PanelRestore: &PanelRestoreIntent{Receipt: r.Receipt}, Deadline: time.Now().Unix() + 600}
		out.RequestHash = panelRestoreHash(id, r.Receipt)
		if err = j.Put(out); err != nil {
			return out, err
		}
	}
	if err = storage.BindWriterFence(data, restoreFence(out)); err != nil {
		return out, err
	}
	out.State, out.Error = "running", ""
	if err = j.Put(out); err == nil {
		err = runPanelRestore(ctx, j.Put, &out)
	}
	if err != nil {
		out.State, out.Error = "recovery_required", panelRestoreError(err)
		if save := j.Put(out); save != nil {
			return out, errors.Join(err, save)
		}
		return out, err
	}
	// Persist completed installation before removing the startup fence. A replay
	// after serve has restarted must never overwrite its new database again.
	out.State, out.Stage, out.Error = "succeeded", "files_restored", ""
	if err = j.Put(out); err != nil {
		return out, err
	}
	return out, storage.ClearWriterFence(data, restoreFence(out))
}

func runPanelRestore(ctx context.Context, save func(Record) error, r *Record) error {
	p, err := panelrecovery.PrepareApprovedRestore(ctx, r.PanelRestore.Receipt, r.OperationID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(p.Receipt)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(r.PanelRestore.Receipt)
	if err != nil || string(raw) != string(expected) {
		return errors.New("恢复暂存不属于原批准快照")
	}
	if r.Stage == "preparing" {
		before, err := panelrecovery.PreserveOriginals(ctx, p)
		if err != nil {
			return err
		}
		r.PanelRestore.Before, r.Stage = before, "restoring"
		if err = save(*r); err != nil {
			return err
		}
	}
	return panelrecovery.Install(ctx, p, r.PanelRestore.Before)
}

func panelRestoreRecord(data, id string) (Record, error) {
	var out Record
	raw, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).readOperationBytes(id, 64<<10)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || string(raw) != string(canonical) {
		return out, errors.New("恢复独立记录不是原始规范记录")
	}
	if err = validPanelRestoreRecord(out); err != nil {
		return out, err
	}
	if out.OperationID != id || out.PanelRestore.Receipt.Manifest.DataDir != data {
		return out, errors.New("恢复记录与当前节点不匹配")
	}
	return out, nil
}

func PanelRestoreStatus(data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("恢复记录查询需要 root 和原操作标识")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return Record{}, err
	}
	return panelRestoreRecord(data, id)
}

func panelRestoreError(err error) string {
	s := err.Error()
	if len(s) > 1024 {
		s = s[:1024]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
