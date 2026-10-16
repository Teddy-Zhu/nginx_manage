package agent

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelupdates"
)

func validPanelUpdateCleanup(r Record) error {
	p := r.PanelUpdate
	if p.Cleanup == nil {
		return nil
	}
	c := p.Cleanup
	if !panelUpdateTerminal(r) || c.Status.State == "pending" {
		return errors.New("清理须在原更新与维护释放结束后开始")
	}
	if err := c.Status.Validate(true); err != nil {
		return err
	}
	if c.Plan == nil {
		if c.Status.Entries != 0 || c.Status.Bytes != 0 || c.Status.State == "running" || c.Status.State == "done" && p.Snapshot != nil {
			return errors.New("清理执行缺少原资源清单")
		}
		return nil
	}
	if p.Snapshot == nil {
		return errors.New("清理批准缺少原快照")
	}
	if err := c.Plan.Validate(*p.Snapshot, p.Intent.RestoreID); err != nil {
		return err
	}
	if c.Status.Entries != len(c.Plan.Entries) || c.Status.Bytes != c.Plan.Bytes {
		return errors.New("清理进度与批准清单不同")
	}
	return nil
}

// Caller holds the update lock. No live data, service, release or maintenance
// admission is changed here; interrupted deletion reuses its durable inventory.
func (w *panelUpdateWorker) cleanup(ctx context.Context) error {
	if !panelUpdateTerminal(w.r) {
		return errors.New("未完成事务的救援材料不能清理")
	}
	p := w.r.PanelUpdate
	if p.Cleanup != nil && p.Cleanup.Status.State == "done" {
		return nil
	}
	if p.Cleanup == nil {
		p.Cleanup = &PanelUpdateCleanup{}
	}
	c := p.Cleanup
	c.Status.AttemptedAt = time.Now().Unix()
	blocked := func(cause error) error {
		c.Status.State, c.Status.Error = "blocked", panelRestoreError(cause)
		if err := w.save(); err != nil {
			return errors.Join(cause, err)
		}
		return cause
	}
	grant, err := w.j.Get(p.Intent.Input.MaintenanceID)
	if err != nil {
		return blocked(err)
	}
	if grant.OperationID != p.Intent.Input.MaintenanceID || grant.Kind != "maintenance.lock" || grant.RequestHash != maintenanceHashForID(p.Intent.Input.MaintenanceID) || grant.State != "succeeded" || grant.Stage != "released" {
		return blocked(errors.New("原维护释放记录尚未确认，保留恢复材料"))
	}
	if p.Snapshot == nil {
		present, err := panelrecovery.MaterialPresent(p.Intent.Input.Stage.DataDir, p.Intent.SnapshotID)
		if err != nil {
			return blocked(err)
		}
		if !present {
			c.Status.State, c.Status.Error, c.Status.CompletedAt = "done", "", time.Now().Unix()
			return w.save()
		}
	}
	unlock, err := panelrecovery.LockCleanup(p.Intent.Input.Stage.DataDir)
	if err != nil {
		return blocked(err)
	}
	defer unlock()
	if p.Snapshot == nil {
		// Capture may have published its receipt before helper disposal failed.
		// Only that exact original approval can be adopted for later cleanup.
		receipt, err := panelrecovery.ReceiptFor(p.Intent.Input.Stage.DataDir, p.Intent.SnapshotID)
		if err != nil {
			return blocked(err)
		}
		m := receipt.Manifest
		i := p.Intent
		if m.MaintenanceID != i.Input.MaintenanceID || m.Epoch != i.SnapshotEpoch || m.UID != i.UID || m.GID != i.GID || m.Database.SchemaVersion != i.BeforeSchema {
			return blocked(errors.New("残留快照与原更新授权不同，须本机核对"))
		}
		p.Snapshot = &receipt
	}
	if c.Plan == nil {
		plan, err := panelrecovery.PrepareCleanup(ctx, *p.Snapshot, p.Intent.RestoreID)
		if err != nil {
			return blocked(err)
		}
		c.Plan = &plan
		c.Status.Entries = len(plan.Entries)
		c.Status.Bytes = plan.Bytes
	}
	c.Status.State, c.Status.Error = "running", ""
	if err = w.save(); err != nil {
		return err
	}
	if err = panelrecovery.RemoveApproved(ctx, *p.Snapshot, *c.Plan); err != nil {
		return blocked(err)
	}
	c.Status.State, c.Status.CompletedAt = "done", time.Now().Unix()
	return w.save()
}

// Cleanup failures do not reinterpret a committed or compensated update.
func (w *panelUpdateWorker) finishCleanup(ctx context.Context) (Record, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := w.cleanup(call); err != nil {
		return w.r, errors.Join(errors.New("更新结果已保存，恢复材料清理未完成"), err)
	}
	return panelUpdateResult(w.r)
}

func cleanupAttempt(r Record) int64 {
	if r.PanelUpdate.Cleanup == nil {
		return 0
	}
	return r.PanelUpdate.Cleanup.Status.AttemptedAt
}

func (s *Server) cleanupPanelUpdate(ctx context.Context) error {
	unlock, err := s.Journal.rootLock(".panel-update.lock")
	// The active updater owns all recovery material while this lock is held.
	if errors.Is(err, unix.EWOULDBLOCK) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	records, err := s.Journal.List()
	if err != nil {
		return err
	}
	candidates := []Record{}
	for _, r := range records {
		if !panelUpdateFinalized(r) {
			continue
		}
		r, err = panelUpdateRecord(s.DataDir, r.OperationID)
		if err != nil {
			return err
		}
		c := r.PanelUpdate.Cleanup
		if c != nil && (c.Status.State == "done" || c.Status.State == "blocked" && c.Status.AttemptedAt > time.Now().Add(-10*time.Minute).Unix()) {
			continue
		}
		candidates = append(candidates, r)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return cleanupAttempt(candidates[i]) < cleanupAttempt(candidates[j]) })
	for _, r := range candidates {
		w := &panelUpdateWorker{j: s.Journal, r: r}
		ack, err := w.acknowledgeRelease()
		if err != nil {
			return err
		}
		if !ack {
			continue
		}
		return w.cleanup(ctx)
	}
	return nil
}

func (s *Server) runPanelUpdateCleanup(ctx context.Context) {
	if s.panelUpdateScope() != nil {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := s.cleanupPanelUpdate(call)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("恢复材料清理待处理", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func panelUpdateCleanupStatus(p *PanelUpdateOperation) panelupdates.Cleanup {
	if p.Cleanup == nil {
		return panelupdates.Cleanup{State: "pending"}
	}
	return p.Cleanup.Status
}
