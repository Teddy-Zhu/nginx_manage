package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/panelrecovery"
)

type snapshotHistoryTarget struct {
	Receipt panelrecovery.Receipt     `json:"receipt"`
	Cleanup panelrecovery.CleanupPlan `json:"cleanup"`
}

func snapshotHistoryPath(id string) string { return "agent/panel-recovery/" + id }

func snapshotHistoryEntries(s snapshotHistoryTarget) []runtimeHistoryEntry {
	out := make([]runtimeHistoryEntry, 0, len(s.Cleanup.Entries))
	for _, e := range s.Cleanup.Entries {
		path := snapshotHistoryPath(s.Receipt.Manifest.OperationID)
		if e.Path != "." {
			path += "/" + e.Path
		}
		mode := e.Mode
		if e.Directory {
			mode |= uint32(os.ModeDir)
		}
		out = append(out, runtimeHistoryEntry{Path: path, Directory: e.Directory, Device: e.Device, Inode: e.Inode, GID: e.GID, Mode: mode, Size: e.Size, Modified: e.ModifiedAt, Changed: e.ChangedAt, SHA256: e.SHA256})
	}
	return out
}

func validSnapshotHistoryPlan(p runtimeHistoryPlan) error {
	if p.Preview.Filter.Kind != "recovery_snapshot" {
		if len(p.Snapshots) != 0 {
			return errors.New("其他运行维护不能携带快照退役批准")
		}
		return nil
	}
	if len(p.Snapshots) != 1 || len(p.Preview.Targets) != 1 {
		return errors.New("快照退役每批须为一份原快照")
	}
	s := p.Snapshots[0]
	if s.Receipt.Manifest.ExpiresAt > s.Cleanup.CreatedAt || s.Receipt.Manifest.CreatedAt >= p.Preview.Filter.Before || s.Cleanup.Validate(s.Receipt, panelrecovery.AllRestores) != nil || p.Preview.Targets[0] != snapshotHistoryPath(s.Receipt.Manifest.OperationID) || !reflect.DeepEqual(p.Entries, snapshotHistoryEntries(s)) || p.Preview.Bytes != s.Cleanup.Bytes {
		return errors.New("快照退役清单与原批准不一致")
	}
	for _, e := range s.Cleanup.Entries {
		if e.Path == "snapshot.age" && (e.Size != s.Receipt.ArchiveSize || e.SHA256 != s.Receipt.ArchiveSHA256) || e.Path == "receipt.json" && (e.SHA256 != s.Cleanup.ReceiptSHA256 || e.Mode != 0400) {
			return errors.New("快照退役缺少原归档或原批准身份")
		}
	}
	return nil
}

func (n *Nginx) snapshotHistoryEligible(r panelrecovery.Receipt, records []Record) (bool, error) {
	if err := r.Validate(n.DataDir, r.Manifest.OperationID); err != nil {
		return false, err
	}
	if r.Manifest.ExpiresAt > time.Now().Unix() {
		return false, nil
	}
	for _, operation := range records {
		// Updates own their cleanup. Disaster originals retain their rollback
		// snapshot until those independent recovery anchors are retired.
		if operation.RestoreSnapshot == r.Manifest.OperationID || operation.PanelUpdate != nil && operation.PanelUpdate.Intent.SnapshotID == r.Manifest.OperationID {
			return false, nil
		}
	}
	grant, err := n.Journal.Get(r.Manifest.MaintenanceID)
	if err != nil {
		return false, err
	}
	return releasedMaintenance(grant), nil
}

func snapshotHistoryOwners(s snapshotHistoryTarget, records []Record) error {
	restores := map[string]bool{}
	for _, e := range s.Cleanup.Entries {
		parts := strings.Split(e.Path, "/")
		if len(parts) > 1 && parts[0] == "restores" {
			restores[parts[1]] = true
		}
	}
	for id := range restores {
		found := false
		for _, r := range records {
			if r.OperationID == id && r.State == "succeeded" && validPanelRestoreRecord(r) == nil && reflect.DeepEqual(r.PanelRestore.Receipt, s.Receipt) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("快照中存在未登记或未完成的恢复副本，须先处理原事务")
		}
	}
	return nil
}

func (n *Nginx) collectSnapshotHistory(ctx context.Context, f history.RuntimeFilter, records []Record) (runtimeHistoryPlan, error) {
	p := runtimeHistoryPlan{Preview: history.RuntimePreview{Filter: f, Active: "recovery", Targets: []string{}}, Entries: []runtimeHistoryEntry{}}
	receipts, err := panelrecovery.SnapshotReceipts(n.DataDir)
	if err != nil {
		return p, err
	}
	sort.Slice(receipts, func(i, j int) bool {
		a, b := receipts[i].Manifest, receipts[j].Manifest
		return a.CreatedAt > b.CreatedAt || a.CreatedAt == b.CreatedAt && a.OperationID > b.OperationID
	})
	eligible := []panelrecovery.Receipt{}
	for i, r := range receipts {
		if err = ctx.Err(); err != nil {
			return p, err
		}
		if i < f.Keep || r.Manifest.CreatedAt >= f.Before {
			continue
		}
		ok, err := n.snapshotHistoryEligible(r, records)
		if err != nil {
			return p, err
		}
		if ok {
			eligible = append(eligible, r)
		}
	}
	full := false
	for i := len(eligible) - 1; i >= 0; i-- {
		if len(p.Snapshots) != 0 {
			p.Preview.More = true
			break
		}
		r := eligible[i]
		if err = panelrecovery.CheckRetirement(n.DataDir, r.Manifest.OperationID); err != nil {
			return p, err
		}
		room, err := panelrecovery.RetirementRoom(r)
		if err != nil {
			return p, err
		}
		if !room {
			full, p.Preview.More = true, true
			continue
		}
		cleanup, err := panelrecovery.PrepareCleanup(ctx, r, panelrecovery.AllRestores)
		if err != nil {
			return p, err
		}
		s := snapshotHistoryTarget{Receipt: r, Cleanup: cleanup}
		if err = snapshotHistoryOwners(s, records); err != nil {
			return p, err
		}
		p.Snapshots = []snapshotHistoryTarget{s}
		p.Entries = snapshotHistoryEntries(s)
		p.Preview.Targets = []string{snapshotHistoryPath(r.Manifest.OperationID)}
		p.Preview.Bytes, p.Preview.Entries = cleanup.Bytes, len(p.Entries)
	}
	if full && len(p.Snapshots) == 0 {
		return p, fault.Conflict("快照退役凭据达到保留预算，原材料继续保留")
	}
	p.Preview.SHA256 = historyPlanHash(p)
	raw, _ := json.Marshal(p)
	if len(raw) > 192<<10 {
		return p, errors.New("快照退役清单超出保存预算")
	}
	return p, nil
}

func (n *Nginx) removeSnapshotHistory(ctx context.Context, p runtimeHistoryPlan, records []Record) error {
	if err := validSnapshotHistoryPlan(p); err != nil {
		return err
	}
	for _, s := range p.Snapshots {
		ok, err := n.snapshotHistoryEligible(s.Receipt, records)
		if err != nil {
			return err
		}
		if !ok {
			return fault.Conflict("原快照仍被维护或恢复材料引用")
		}
		if err = snapshotHistoryOwners(s, records); err != nil {
			return err
		}
		if err = panelrecovery.SaveRetirement(s.Receipt); err != nil {
			return err
		}
		if err = panelrecovery.RemoveApproved(ctx, s.Receipt, s.Cleanup); err != nil {
			return err
		}
	}
	return nil
}
