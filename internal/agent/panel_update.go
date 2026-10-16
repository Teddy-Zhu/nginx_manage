package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type panelUpdateWorker struct {
	j     *Journal
	r     Record
	epoch string
}

func panelUpdateAccess(ctx context.Context, j *Journal, id, maintenanceID, epoch string, closing bool) (func(), error) {
	unlock, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return nil, err
	}
	if err = installGrant(j, maintenanceID, epoch, closing); err != nil {
		unlock()
		return nil, err
	}
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		unlock()
		return nil, err
	}
	for _, r := range records {
		if r.OperationID == id || r.Kind == "maintenance.lock" && r.OperationID == maintenanceID {
			continue
		}
		if r.Kind == panelUpdateKind {
			if err := validPanelUpdate(r); err != nil {
				unlock()
				return nil, err
			}
			if r.PanelUpdate.Intent.Input.MaintenanceID == maintenanceID {
				unlock()
				return nil, errors.New("同一维护会话只允许一个独立更新事务")
			}
			if panelUpdateFinalized(r) {
				continue
			}
		}
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			unlock()
			return nil, errors.New("其他独立任务尚未结束或待恢复")
		}
	}
	return unlock, nil
}

func (w *panelUpdateWorker) access(ctx context.Context, closing bool) (func(), error) {
	i := w.r.PanelUpdate.Intent
	return panelUpdateAccess(ctx, w.j, w.r.OperationID, i.Input.MaintenanceID, w.epoch, closing)
}
func (w *panelUpdateWorker) save() error {
	if err := validPanelUpdate(w.r); err != nil {
		return err
	}
	return w.j.Put(w.r)
}
func (w *panelUpdateWorker) stage(stage string) error {
	w.r.Stage = stage
	if strings.HasPrefix(stage, "rollback_") || stage == "restoring" {
		w.r.State = "compensating"
	} else {
		w.r.State = "running"
	}
	w.r.Error = ""
	return w.save()
}
func (w *panelUpdateWorker) current() (panelruntime.Snapshot, error) {
	i := w.r.PanelUpdate.Intent
	s, err := panelruntime.Read(i.Input.Stage.DataDir)
	if err != nil {
		return s, err
	}
	if selectionValueHash(s.Deployment) != i.BindingSHA256 || s.Deployment.UID != i.UID || s.Deployment.GID != i.GID || s.Release.ID != i.BeforeID && s.Release.ID != i.TargetID {
		return s, errors.New("更新期间当前程序或固定部署已偏离")
	}
	return s, nil
}
func (w *panelUpdateWorker) approved(ctx context.Context) error {
	i := w.r.PanelUpdate.Intent
	s, err := panelruntime.Staged(ctx, i.Input.Stage)
	if err != nil {
		return err
	}
	if s.Release.ID != i.TargetID || selectionValueHash(s.Approval) != i.ApprovalSHA256 || s.Compatibility.DatabaseSchema != i.TargetSchema || !s.Compatibility.AutomaticRollback {
		return errors.New("原更新签名批准、schema 或自动回滚声明已变化")
	}
	return nil
}

// UpdatePanel is a fixed independent root workflow. No serve process or request
// can choose an executable, bypass the staged signature, or resume a released
// maintenance grant to overwrite later writes.
func UpdatePanel(ctx context.Context, in PanelUpdateInput, id, epoch string) (Record, error) {
	var zero Record
	if os.Geteuid() != 0 || !validID(id) || !validID(in.MaintenanceID) || id == in.MaintenanceID || !validID(epoch) {
		return zero, errors.New("独立更新需要 root、原操作和维护授权")
	}
	if _, err := panelruntime.Root(in.Stage.DataDir); err != nil {
		return zero, err
	}
	j := &Journal{Dir: filepath.Join(in.Stage.DataDir, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".panel-update.lock")
	if err != nil {
		return zero, err
	}
	defer unlock()
	service, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return zero, err
	}
	defer service()
	w := &panelUpdateWorker{j: j, epoch: epoch}
	w.r, err = panelUpdateRecord(in.Stage.DataDir, id)
	if err == nil {
		if w.r.PanelUpdate.Intent.Input != in {
			return w.r, errors.New("更新标识已有不同的目标或维护授权")
		}
		if panelUpdateTerminal(w.r) {
			return panelUpdateResult(w.r)
		}
		if panelUpdateFinalized(w.r) {
			return w.awaitRelease(ctx)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return zero, err
	} else {
		access, err := panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
		if err != nil {
			return zero, err
		}
		defer func() {
			if access != nil {
				access()
			}
		}()
		for _, check := range []func(string) (bool, error){storage.ServiceHeld, storage.WriterFenced} {
			present, e := check(in.Stage.DataDir)
			if e != nil {
				return zero, e
			}
			if present {
				return zero, errors.New("已有停机或恢复标记，须先继续原事务")
			}
		}
		before, err := panelruntime.Read(in.Stage.DataDir)
		if err != nil {
			return zero, err
		}
		uid, gid, err := panelSnapshotIdentity(in.Stage.DataDir)
		if err != nil {
			return zero, err
		}
		target, err := panelruntime.Staged(ctx, in.Stage)
		if err != nil {
			return zero, err
		}
		if !target.Compatibility.AutomaticRollback {
			return zero, errors.New("此发布未声明允许自动回滚，不能进入自动更新流程")
		}
		if target.Release.ID == before.Release.ID || target.Compatibility.DatabaseSchema < before.Release.DatabaseSchema {
			return zero, errors.New("目标已是当前版本或需要不受支持的数据库降级")
		}
		observed, err := observePanelService(ctx, before)
		if err != nil {
			return zero, err
		}
		if !validServiceObservation(observed) || observed.State != "running" {
			return zero, errors.New("原面板进程尚未稳定运行")
		}
		i := PanelUpdateIntent{Input: in, BeforeID: before.Release.ID, TargetID: target.Release.ID, BeforeSchema: before.Release.DatabaseSchema, TargetSchema: target.Compatibility.DatabaseSchema, BindingSHA256: selectionValueHash(before.Deployment), ApprovalSHA256: selectionValueHash(target.Approval), UID: uid, GID: gid, SnapshotEpoch: epoch, SnapshotID: secure.ID(), StopID: secure.ID(), SelectionID: secure.ID(), StartID: secure.ID(), RollbackStopID: secure.ID(), RollbackSelectionID: secure.ID(), RestoreID: secure.ID(), RollbackStartID: secure.ID(), Before: observed}
		w.r = Record{OperationID: id, Kind: panelUpdateKind, State: "running", Stage: "capturing", MaintenanceEpoch: epoch, Deadline: time.Now().Add(20 * time.Minute).Unix(), PanelUpdate: &PanelUpdateOperation{Intent: i}}
		w.r.RequestHash = panelUpdateHash(id, i)
		if err = w.save(); err != nil {
			return w.r, err
		}
		access()
		access = nil
	}
	if strings.HasPrefix(w.r.Stage, "rollback_") || w.r.Stage == "restoring" {
		return w.compensate(ctx)
	}
	if w.r.PanelUpdate.Failure != "" {
		if w.r.Stage == "capturing" {
			return w.abort(ctx)
		}
		if err = w.stage("rollback_stopping"); err != nil {
			return w.r, err
		}
		return w.compensate(ctx)
	}
	forward, cancel := context.WithDeadline(ctx, time.Unix(w.r.Deadline, 0))
	err = w.forward(forward)
	cancel()
	if err == nil {
		return w.awaitRelease(ctx)
	}
	// An uncertain commit must be queried by its original identity before any
	// compensation. A durable commit is a one-way boundary for future writes.
	persisted, load := panelUpdateRecord(in.Stage.DataDir, id)
	if load != nil {
		return w.r, errors.Join(err, load)
	}
	if panelUpdateFinalized(persisted) {
		w.r = persisted
		return w.awaitRelease(ctx)
	}
	w.r = persisted
	w.r.PanelUpdate.Failure = panelRestoreError(err)
	if w.r.Stage == "capturing" {
		return w.abort(ctx)
	}
	if e := w.stage("rollback_stopping"); e != nil {
		return w.r, errors.Join(err, e)
	}
	return w.compensate(ctx)
}

func (w *panelUpdateWorker) forward(ctx context.Context) error {
	p := w.r.PanelUpdate
	i := p.Intent
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch w.r.Stage {
		case "capturing":
			access, err := w.access(ctx, false)
			if err != nil {
				return err
			}
			captured, err := panelrecovery.Capture(ctx, panelrecovery.Input{DataDir: i.Input.Stage.DataDir, OperationID: i.SnapshotID, MaintenanceID: i.Input.MaintenanceID, Epoch: i.SnapshotEpoch, UID: i.UID, GID: i.GID})
			if err == nil && captured.Expired {
				err = errors.New("原更新快照已过期，尚未停机的更新中止")
			}
			if err == nil {
				p.Snapshot = &captured.Receipt
				err = w.stage("stopping")
			}
			access()
			if err != nil {
				return err
			}
		case "stopping":
			s, err := w.current()
			if err != nil {
				return err
			}
			if s.Release.ID != i.BeforeID {
				return errors.New("停机前原版本已变化")
			}
			if err = w.service(ctx, &p.Stop, i.StopID, "stop", s, nil); err != nil {
				return err
			}
			if err = w.stage("selecting"); err != nil {
				return err
			}
		case "selecting":
			if err := w.selectVersion(ctx, false); err != nil {
				return err
			}
			if err := w.stage("starting"); err != nil {
				return err
			}
		case "starting":
			if err := w.approved(ctx); err != nil {
				return err
			}
			s, err := w.current()
			if err != nil {
				return err
			}
			if s.Release.ID != i.TargetID {
				return errors.New("启动前目标版本已变化")
			}
			if err = w.service(ctx, &p.Start, i.StartID, "start", s, p.Stop); err != nil {
				return err
			}
			if err = w.stage("checking"); err != nil {
				return err
			}
		case "checking":
			s, err := w.current()
			if err != nil {
				return err
			}
			ready, err := observePanelReadiness(ctx, w.j, s, *p.Start, *p.Snapshot, w.epoch)
			if err != nil {
				return err
			}
			access, err := w.access(ctx, false)
			if err != nil {
				return err
			}
			err = w.approved(ctx)
			if err == nil {
				p.Ready = &ready
				w.r.State, w.r.Stage, w.r.Error = "waiting_confirmation", "committed", ""
				err = w.save()
			}
			access()
			return err
		default:
			return errors.New("未知更新执行阶段")
		}
	}
}

func (w *panelUpdateWorker) awaitRelease(ctx context.Context) (Record, error) {
	if panelUpdateTerminal(w.r) {
		return panelUpdateResult(w.r)
	}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	i := w.r.PanelUpdate.Intent
	for {
		r, err := w.j.Get(i.Input.MaintenanceID)
		if err != nil {
			return w.r, err
		}
		if r.Kind != "maintenance.lock" || r.RequestHash != maintenanceHashForID(i.Input.MaintenanceID) {
			return w.r, errors.New("原维护记录身份已偏离")
		}
		if r.State == "succeeded" && r.Stage == "released" {
			w.r.PanelUpdate.ReleaseAcknowledged = true
			w.r.State = panelUpdateOutcome(w.r)
			if err = w.save(); err != nil {
				return w.r, err
			}
			result, err := panelUpdateRecord(i.Input.Stage.DataDir, w.r.OperationID)
			if err != nil {
				return w.r, err
			}
			return panelUpdateResult(result)
		}
		select {
		case <-wait.Done():
			return w.r, errors.New("更新结果已持久提交，等待应用维护服务确认原会话释放；应查询或续行原更新，不执行回滚")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func maintenanceHashForID(id string) string {
	return maintenanceHash(maintenance.RootRequest{Protocol: Protocol, OperationID: id})
}

func panelUpdateResult(r Record) (Record, error) {
	if r.State == "rolled_back" || r.State == "failed" {
		return r, errors.New("更新未成功，原事务已完成补偿或无副作用中止：" + r.PanelUpdate.Failure)
	}
	return r, nil
}
