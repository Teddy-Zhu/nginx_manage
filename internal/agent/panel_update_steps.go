package agent

import (
	"context"
	"errors"
	"os"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

func (w *panelUpdateWorker) childSaver(slot **Record) func(Record) error {
	return func(r Record) error { r.UpdatedAt = time.Now().Unix(); *slot = &r; return w.save() }
}

func (w *panelUpdateWorker) service(ctx context.Context, slot **Record, id, action string, s panelruntime.Snapshot, stop *Record) error {
	call, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	access, err := w.access(call, true)
	if err != nil {
		return err
	}
	defer access()
	i := w.r.PanelUpdate.Intent
	fresh := *slot == nil
	if fresh {
		before, err := observePanelService(call, s)
		if err != nil {
			return err
		}
		if !validServiceObservation(before) || action == "start" && before.State != "stopped" {
			return errors.New("更新面板进程尚未处于可控制的稳定状态")
		}
		in := PanelServiceIntent{Input: PanelServiceInput{DataDir: i.Input.Stage.DataDir, Action: action, MaintenanceID: i.Input.MaintenanceID}, ReleaseID: s.Release.ID, BindingSHA256: i.BindingSHA256, Before: before}
		in.LauncherProtocol, err = panelServiceProtocol(s)
		if err != nil {
			return err
		}
		if action == "start" {
			if stop == nil || stop.State != "succeeded" {
				return errors.New("更新启动缺少已完成的原停机记录")
			}
			in.Input.StopID, in.StopSHA256 = stop.OperationID, stop.RequestHash
		}
		child := Record{OperationID: id, Kind: panelServiceKind, State: "running", Stage: "controlling", MaintenanceEpoch: w.epoch, Deadline: time.Now().Add(3 * time.Minute).Unix(), PanelService: &PanelServiceOperation{Intent: in}}
		child.RequestHash = panelServiceHash(id, in)
		if err = w.childSaver(slot)(child); err != nil {
			return err
		}
	}
	child := **slot
	if child.State == "succeeded" {
		observed, err := observePanelService(call, s)
		if err != nil {
			return err
		}
		if action == "start" {
			if observed != *child.PanelService.After {
				return errors.New("原更新启动实例已变化")
			}
			return nil
		}
		if observed.State != "stopped" {
			return errors.New("原更新停机后出现其他进程，须本机核对")
		}
		release, err := storage.LockWriterForMaintenance(i.Input.Stage.DataDir, i.GID)
		if err != nil {
			return err
		}
		release()
		return nil
	}
	if err = call.Err(); err != nil {
		return err
	}
	if action == "stop" {
		err = storage.BindServiceHold(i.Input.Stage.DataDir, panelStopHold(child))
	} else {
		fenced, e := storage.WriterFenced(i.Input.Stage.DataDir)
		err = e
		if err == nil && fenced {
			err = errors.New("恢复标记未解除，禁止更新启动")
		}
		if err == nil {
			hold, e := storage.ReadServiceHold(i.Input.Stage.DataDir)
			if e == nil {
				if hold != panelStopHold(*stop) {
					err = errors.New("更新启动的停机标记不属于原事务")
				} else {
					release, e := storage.LockWriterForMaintenance(i.Input.Stage.DataDir, i.GID)
					err = e
					if err == nil {
						err = storage.ClearServiceHold(i.Input.Stage.DataDir, panelStopHold(*stop))
						release()
					}
				}
			} else if !errors.Is(e, os.ErrNotExist) || fresh {
				err = errors.Join(e, errors.New("更新启动的原停机标记缺失"))
			}
		}
	}
	if err == nil {
		var after PanelServiceObservation
		after, err = runPanelService(call, w.childSaver(slot), &child, s)
		if err == nil {
			var release func()
			if action == "stop" {
				release, err = storage.LockWriterForMaintenance(i.Input.Stage.DataDir, i.GID)
				if err == nil {
					defer release()
				}
			}
			if err == nil {
				child.State = "succeeded"
				if action == "stop" {
					child.Stage = "stopped"
				} else {
					child.Stage = "started"
				}
				child.Error = ""
				child.PanelService.After = &after
				return w.childSaver(slot)(child)
			}
		}
	}
	child.State, child.Error = "recovery_required", panelRestoreError(err)
	return errors.Join(err, w.childSaver(slot)(child))
}

func (w *panelUpdateWorker) holdStop() *Record {
	if w.r.PanelUpdate.RollbackStop != nil {
		return w.r.PanelUpdate.RollbackStop
	}
	return w.r.PanelUpdate.Stop
}

func (w *panelUpdateWorker) requireHold() error {
	stop := w.holdStop()
	if stop == nil || stop.State != "succeeded" {
		return errors.New("更新缺少完整停机证据")
	}
	hold, err := storage.ReadServiceHold(w.r.PanelUpdate.Intent.Input.Stage.DataDir)
	if err != nil {
		return err
	}
	if hold != panelStopHold(*stop) {
		return errors.New("持久停机标记不属于原更新事务")
	}
	return nil
}

func (w *panelUpdateWorker) selectVersion(ctx context.Context, rollback bool) error {
	access, err := w.access(ctx, true)
	if err != nil {
		return err
	}
	defer access()
	i := w.r.PanelUpdate.Intent
	if err = w.requireHold(); err != nil {
		return err
	}
	release, err := storage.LockWriterForMaintenance(i.Input.Stage.DataDir, i.GID)
	if err != nil {
		return err
	}
	defer release()
	s, err := w.current()
	if err != nil {
		return err
	}
	o, err := observePanelService(ctx, s)
	if err != nil {
		return err
	}
	if o.State != "stopped" {
		return errors.New("版本选择前面板进程仍未停止")
	}
	from, to, id := i.BeforeID, i.TargetID, i.SelectionID
	if rollback {
		original, e := panelruntime.ReadVersion(i.Input.Stage.DataDir, i.BeforeID)
		if e != nil {
			return e
		}
		if original.Release.DatabaseSchema != i.BeforeSchema || selectionValueHash(original.Deployment) != i.BindingSHA256 {
			return errors.New("原回滚程序或部署绑定已变化")
		}
		from, to, id = i.TargetID, i.BeforeID, i.RollbackSelectionID
	} else if err = w.approved(ctx); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = panelruntime.SwitchCurrent(i.Input.Stage.DataDir, from, to, id); err != nil {
		return err
	}
	if rollback {
		w.r.PanelUpdate.RollbackSelected = true
	} else {
		w.r.PanelUpdate.Selected = true
	}
	return w.save()
}

func (w *panelUpdateWorker) restore(ctx context.Context) error {
	call, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	access, err := w.access(call, true)
	if err != nil {
		return err
	}
	defer access()
	i := w.r.PanelUpdate.Intent
	p := w.r.PanelUpdate
	if err = w.requireHold(); err != nil {
		return err
	}
	s, err := w.current()
	if err != nil {
		return err
	}
	if s.Release.ID != i.BeforeID {
		return errors.New("数据恢复前未选择原匹配程序")
	}
	o, err := observePanelService(call, s)
	if err != nil {
		return err
	}
	if o.State != "stopped" {
		return errors.New("数据恢复前面板进程仍未停止")
	}
	release, err := storage.LockWriterForRecovery(i.Input.Stage.DataDir, i.GID)
	if err != nil {
		return err
	}
	defer release()
	if p.Restore == nil {
		fenced, e := storage.WriterFenced(i.Input.Stage.DataDir)
		if e != nil {
			return e
		}
		if fenced {
			return errors.New("恢复标记存在但原更新子意图缺失")
		}
		child := Record{OperationID: i.RestoreID, Kind: panelRestoreKind, State: "running", Stage: "preparing", MaintenanceEpoch: w.epoch, Deadline: time.Now().Add(10 * time.Minute).Unix(), PanelRestore: &PanelRestoreIntent{Receipt: *p.Snapshot}}
		child.RequestHash = panelRestoreHash(i.RestoreID, *p.Snapshot)
		if err = w.childSaver(&p.Restore)(child); err != nil {
			return err
		}
	}
	child := *p.Restore
	if child.State == "succeeded" {
		return storage.ClearWriterFence(i.Input.Stage.DataDir, restoreFence(child))
	}
	if err = storage.BindWriterFence(i.Input.Stage.DataDir, restoreFence(child)); err != nil {
		return err
	}
	if err = runPanelRestore(call, w.childSaver(&p.Restore), &child); err != nil {
		child.State, child.Error = "recovery_required", panelRestoreError(err)
		return errors.Join(err, w.childSaver(&p.Restore)(child))
	}
	child.State, child.Stage, child.Error = "succeeded", "files_restored", ""
	if err = w.childSaver(&p.Restore)(child); err != nil {
		return err
	}
	return storage.ClearWriterFence(i.Input.Stage.DataDir, restoreFence(child))
}

func (w *panelUpdateWorker) pending(err error) (Record, error) {
	failure := w.r.PanelUpdate.Failure
	persisted, load := panelUpdateRecord(w.r.PanelUpdate.Intent.Input.Stage.DataDir, w.r.OperationID)
	if load != nil {
		return w.r, errors.Join(err, load)
	}
	w.r = persisted
	if panelUpdateFinalized(w.r) {
		return w.r, errors.Join(err, errors.New("更新提交点已持久化，应继续查询原事务的维护释放结果"))
	}
	if w.r.PanelUpdate.Failure == "" {
		w.r.PanelUpdate.Failure = failure
	}
	w.r.State, w.r.Error = "recovery_required", panelRestoreError(err)
	return w.r, errors.Join(err, w.save())
}

func (w *panelUpdateWorker) abort(ctx context.Context) (Record, error) {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()
	access, err := w.access(call, true)
	if err != nil {
		return w.pending(err)
	}
	s, err := w.current()
	if err == nil && s.Release.ID != w.r.PanelUpdate.Intent.BeforeID {
		err = errors.New("无副作用中止前原程序已变化")
	}
	for _, check := range []func(string) (bool, error){storage.ServiceHeld, storage.WriterFenced} {
		if err != nil {
			break
		}
		present, e := check(s.Deployment.DataDir)
		err = e
		if err == nil && present {
			err = errors.New("中止前出现停机或恢复标记")
		}
	}
	var o PanelServiceObservation
	if err == nil {
		o, err = observePanelService(call, s)
	}
	if err == nil && (!validServiceObservation(o) || o.State != "running") {
		err = errors.New("中止前原面板运行状态未确认")
	}
	if err == nil {
		err = w.checkCoordinatedAbort(call)
	}
	if err == nil {
		w.r.PanelUpdate.AbortObservation = &o
		w.r.State, w.r.Stage, w.r.Error = "waiting_confirmation", "aborted", w.r.PanelUpdate.Failure
		err = w.save()
	}
	access()
	if err != nil {
		return w.pending(err)
	}
	return w.awaitRelease(call)
}

func (w *panelUpdateWorker) compensate(ctx context.Context) (Record, error) {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()
	p := w.r.PanelUpdate
	i := p.Intent
	for {
		if err := call.Err(); err != nil {
			return w.pending(err)
		}
		switch w.r.Stage {
		case "rollback_stopping":
			s, err := w.current()
			if err != nil {
				return w.pending(err)
			}
			hold, e := storage.ReadServiceHold(i.Input.Stage.DataDir)
			if e == nil && p.Stop != nil && hold == panelStopHold(*p.Stop) && p.RollbackStop == nil {
				err = w.service(call, &p.Stop, i.StopID, "stop", s, nil)
			} else if e == nil && p.RollbackStop != nil && hold == panelStopHold(*p.RollbackStop) || errors.Is(e, os.ErrNotExist) {
				err = w.service(call, &p.RollbackStop, i.RollbackStopID, "stop", s, nil)
			} else {
				err = errors.Join(e, errors.New("补偿停机标记不属于原更新事务"))
			}
			if err != nil {
				return w.pending(err)
			}
			if err = w.stage("rollback_selecting"); err != nil {
				return w.pending(err)
			}
		case "rollback_selecting":
			if err := w.coordinateAgent(call, true); err != nil {
				return w.pending(err)
			}
			if err := w.selectVersion(call, true); err != nil {
				return w.pending(err)
			}
			if err := w.stage("restoring"); err != nil {
				return w.pending(err)
			}
		case "restoring":
			if err := w.restore(call); err != nil {
				return w.pending(err)
			}
			if err := w.stage("rollback_starting"); err != nil {
				return w.pending(err)
			}
		case "rollback_starting":
			s, err := w.current()
			if err != nil {
				return w.pending(err)
			}
			if s.Release.ID != i.BeforeID {
				return w.pending(errors.New("补偿启动前原程序已变化"))
			}
			if err = w.service(call, &p.RollbackStart, i.RollbackStartID, "start", s, w.holdStop()); err != nil {
				return w.pending(err)
			}
			if err = w.stage("rollback_checking"); err != nil {
				return w.pending(err)
			}
		case "rollback_checking":
			s, err := w.current()
			if err != nil {
				return w.pending(err)
			}
			ready, err := observePanelReadiness(call, w.j, s, *p.RollbackStart, *p.Snapshot, w.epoch)
			if err != nil {
				return w.pending(err)
			}
			if err = w.checkCoordinatedReady(call, true); err != nil {
				return w.pending(err)
			}
			access, err := w.access(call, false)
			if err != nil {
				return w.pending(err)
			}
			p.RollbackReady = &ready
			w.r.State, w.r.Stage, w.r.Error = "waiting_confirmation", "compensated", p.Failure
			err = w.save()
			access()
			if err != nil {
				return w.r, err
			}
			return w.awaitRelease(call)
		default:
			return w.pending(errors.New("未知更新补偿阶段"))
		}
	}
}
