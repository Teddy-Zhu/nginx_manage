package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

type DisasterActivationOperation struct {
	ActivationSHA256    string                    `json:"activation_sha256"`
	Start               *Record                   `json:"start,omitempty"`
	Ready               *PanelReadiness           `json:"ready,omitempty"`
	ReleaseAcknowledged bool                      `json:"release_acknowledged"`
	Release             *panelready.ReleaseStatus `json:"release,omitempty"`
	ReleaseProcess      *PanelServiceObservation  `json:"release_process,omitempty"`
}

func disasterActivationCommitted(r Record) bool { return r.DisasterActivation != nil }
func disasterActivationFinalized(r Record) bool {
	return r.DisasterActivation != nil && r.Stage == "committed"
}

func validDisasterActivation(i panelrecovery.DisasterIntent, r Record) error {
	p := r.DisasterActivation
	if p == nil {
		return errors.New("恢复激活缺少原独立提交记录")
	}
	a, err := panelrecovery.ReadDisasterActivation(i)
	if err != nil {
		return err
	}
	if _, err = panelrecovery.ReadDisasterActivationProof(i, a); err != nil {
		return err
	}
	reconciled, err := panelrecovery.ReadDisasterReconciliation(i)
	if err != nil {
		return err
	}
	if _, err = panelrecovery.ReadDisasterReconciliationProof(i, reconciled); err != nil {
		return err
	}
	if p.ActivationSHA256 != a.SHA256() {
		return errors.New("恢复激活提交引用了其他批准")
	}
	if p.Start != nil {
		c := p.Start
		if c.DisasterActivation != nil || c.DisasterRestoreID != "" || c.PanelUpdate != nil || c.PanelRestore != nil || c.PanelSelection != nil || c.NginxInstall != nil || c.NginxSwitch != nil || c.RemoteListener != nil || c.LogPolicy != nil {
			return errors.New("恢复启动包含无关子操作")
		}
		if err = validPanelService(*c); err != nil {
			return err
		}
		s := c.PanelService.Intent
		if c.OperationID != a.StartID || s.Input.DataDir != i.DataDir || s.Input.Action != "start" || s.Input.StopID != i.Stop.OperationID || s.Input.MaintenanceID != i.Stop.MaintenanceID || s.Input.SelectionID != "" || s.StopSHA256 != i.Stop.RequestSHA256 || s.ReleaseID != i.ReleaseID || s.BindingSHA256 != i.Stop.BindingSHA256 {
			return errors.New("恢复启动与原停机、程序不一致")
		}
	}
	if p.Ready != nil {
		v := p.Ready
		if p.Start == nil || p.Start.State != "succeeded" || v.StartID != a.StartID || v.StartSHA256 != p.Start.RequestHash || v.SnapshotID != "" || v.SnapshotSHA256 != "" || v.BindingSHA256 != i.Stop.BindingSHA256 || v.CheckedAt < a.PreparedAt || v.CheckedAt > time.Now().Unix()+300 || v.Process != *p.Start.PanelService.After || v.HTTPS.FrontendFiles <= 0 || !panelSelectionDigest.MatchString(v.HTTPS.CertificateSHA256) {
			return errors.New("恢复就绪证明与原启动不一致")
		}
		app := v.Application
		c, m := app.Configuration, app.Maintenance
		db := reconciled.Database
		if err = app.Validate(); err != nil {
			return err
		}
		if app.PID != v.Process.PID || app.Mode != v.Process.Mode || app.ReleaseID != i.ReleaseID || app.DatabaseSchema != db.SchemaVersion || app.NodeID != db.NodeID || c.DesiredRevision != db.DesiredRevision || c.AppliedRevision != db.AppliedRevision || c.HeadVersion != db.HeadVersion || !c.Available || !c.Integrity || !c.Running || c.ExternalChange || c.RevisionID != i.PlanID || c.DeploymentID != i.PlanID || m.ID != i.Stop.MaintenanceID || m.Epoch != r.MaintenanceEpoch {
			return errors.New("恢复就绪数据库、运行修订或维护身份不一致")
		}
	}
	if p.ReleaseAcknowledged {
		if p.Release == nil || p.ReleaseProcess == nil {
			return errors.New("恢复成功缺少应用持久释放证明")
		}
		if err = p.Release.Validate(); err != nil {
			return err
		}
		v, process := p.Release, *p.ReleaseProcess
		if !validServiceObservation(process) || process.State != "running" || process.ReleaseID != i.ReleaseID || v.PID != process.PID || v.Mode != process.Mode || v.ReleaseID != i.ReleaseID || v.NodeID != reconciled.Database.NodeID || v.RestoreID != i.OperationID || v.MaintenanceID != i.Stop.MaintenanceID || v.ReleasedAt < a.PreparedAt {
			return errors.New("恢复释放证明与原恢复、当前受信程序不一致")
		}
	} else if p.Release != nil || p.ReleaseProcess != nil {
		return errors.New("恢复释放证明缺少独立确认")
	}
	switch r.Stage {
	case "activation_committed":
		if p.Start != nil || p.Ready != nil || p.ReleaseAcknowledged || r.State != "recovery_required" {
			return errors.New("恢复激活安装阶段无效")
		}
	case "activation_starting":
		if p.Start == nil || p.Ready != nil || p.ReleaseAcknowledged || r.State != "recovery_required" {
			return errors.New("恢复激活启动阶段无效")
		}
	case "activation_checking":
		if p.Start == nil || p.Start.State != "succeeded" || p.Ready != nil || p.ReleaseAcknowledged || r.State != "recovery_required" {
			return errors.New("恢复激活就绪阶段无效")
		}
	case "committed":
		if p.Ready == nil || p.ReleaseAcknowledged && r.State != "succeeded" || !p.ReleaseAcknowledged && r.State != "waiting_confirmation" {
			return errors.New("恢复最终提交或维护回执无效")
		}
	default:
		return errors.New("未知恢复激活阶段")
	}
	return nil
}

// Activation commits before the first writable open of the completed database.
// After that point retries may only finish the same start/readiness/release;
// an old snapshot must never overwrite data written by the activated process.
func ActivateDisaster(ctx context.Context, data, id, epoch string, prepare func(context.Context, panelrecovery.DisasterIntent) error) (out Record, err error) {
	if os.Geteuid() != 0 || !validID(id) || !validID(epoch) || prepare == nil {
		return out, errors.New("恢复激活需要本机 root、原操作和当前维护授权")
	}
	call, cancel := context.WithTimeout(ctx, 18*time.Minute)
	defer cancel()
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(call, ".disaster-restore.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	service, err := j.waitRootLock(call, ".panel-service.lock")
	if err != nil {
		return out, err
	}
	defer service()
	out, err = readDisasterRestore(data, id)
	if err != nil {
		return out, err
	}
	save := func() error {
		if _, e := validDisasterRestore(data, out); e != nil {
			return e
		}
		return j.Put(out)
	}
	acknowledge := func() (bool, error) {
		if !disasterActivationFinalized(out) {
			return false, nil
		}
		if out.DisasterActivation.ReleaseAcknowledged {
			return true, nil
		}
		m, e := j.Get(i.Stop.MaintenanceID)
		if e != nil {
			return false, e
		}
		if m.Kind != "maintenance.lock" || m.RequestHash != maintenanceHashForID(i.Stop.MaintenanceID) {
			return false, errors.New("原恢复维护记录身份已变化")
		}
		if m.State != "succeeded" || m.Stage != "released" {
			return false, nil
		}
		if e = checkDisasterProgram(data, i); e != nil {
			return false, e
		}
		s, e := panelruntime.Read(data)
		if e != nil {
			return false, e
		}
		process, e := observePanelService(call, s)
		if e != nil {
			return false, e
		}
		if process.State != "running" || !validServiceObservation(process) {
			return false, nil
		}
		parent, e := panelReadinessParent(call, s, process)
		if e != nil {
			return false, e
		}
		proof, e := panelready.ReadRelease(call, s, process.PID, parent, i.OperationID, i.Stop.MaintenanceID)
		if e != nil {
			if errors.Is(e, panelready.ErrNotReady) || errors.Is(e, os.ErrNotExist) {
				return false, nil
			}
			return false, e
		}
		after, e := observePanelService(call, s)
		if e != nil {
			return false, e
		}
		if after != process {
			return false, errors.New("应用维护释放核对期间进程实例变化")
		}
		if e = checkDisasterProgram(data, i); e != nil {
			return false, e
		}
		out.DisasterActivation.Release = &proof
		out.DisasterActivation.ReleaseProcess = &process
		out.DisasterActivation.ReleaseAcknowledged = true
		out.State = "succeeded"
		out.Error = ""
		return true, save()
	}
	awaitRelease := func() error {
		wait, cancel := context.WithTimeout(call, 90*time.Second)
		defer cancel()
		for {
			ok, e := acknowledge()
			if e != nil {
				return e
			}
			if ok {
				return nil
			}
			select {
			case <-wait.Done():
				return errors.New("恢复已通过就绪并提交，等待原维护会话及应用持久释放；请查询或续办原激活，禁止回滚")
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	if disasterActivationFinalized(out) {
		err = awaitRelease()
		return out, err
	}

	access := func() (func(), error) {
		release, e := j.waitRootLock(call, ".maintenance-access.lock")
		if e != nil {
			return nil, e
		}
		if e = installGrant(j, i.Stop.MaintenanceID, epoch, true); e == nil {
			e = checkDisasterRecords(j, i, true)
		}
		if e == nil {
			e = checkDisasterProgram(data, i)
		}
		if e != nil {
			release()
			return nil, e
		}
		if _, e = panelrecovery.ReadDisasterRuntimeApproval(i, true); e == nil {
			release()
			return nil, errors.New("原恢复已选择补偿，禁止激活")
		} else if !os.IsNotExist(e) {
			release()
			return nil, e
		}
		return release, nil
	}
	if !disasterActivationCommitted(out) {
		if out.Stage != "data_reconciled" {
			return out, errors.New("恢复激活须先完成运行确认和数据对账")
		}
		release, e := access()
		if e != nil {
			return out, e
		}
		err = func() error {
			defer release()
			if e = checkDisasterRuntime(data, i); e != nil {
				return e
			}
			writer, e := storage.LockWriterForRecovery(data, i.Rollback.Manifest.GID)
			if e != nil {
				return e
			}
			defer writer()
			fence, e := storage.ReadWriterFence(data)
			if e != nil || fence != i.Fence() {
				return errors.Join(e, errors.New("恢复激活缺少原写入屏障"))
			}
			if e = panelrecovery.CheckDisasterTarget(call, i, true); e != nil {
				return e
			}
			if e = prepare(call, i); e != nil {
				return e
			}
			a, e := panelrecovery.ReadDisasterActivation(i)
			if e != nil {
				return e
			}
			if _, e = panelrecovery.ReadDisasterActivationProof(i, a); e != nil {
				return e
			}
			out.DisasterActivation = &DisasterActivationOperation{ActivationSHA256: a.SHA256()}
			out.State, out.Stage, out.Error, out.MaintenanceEpoch = "recovery_required", "activation_committed", "", epoch
			return save()
		}()
		if err != nil {
			return out, err
		}
	}
	defer func() {
		if err != nil && !disasterActivationFinalized(out) {
			out.Error = panelRestoreError(err)
			err = errors.Join(err, save())
		}
	}()
	a, err := panelrecovery.ReadDisasterActivation(i)
	if err != nil {
		return out, err
	}
	if out.Stage == "activation_committed" {
		release, e := access()
		if e != nil {
			return out, e
		}
		err = func() error {
			defer release()
			if e = checkDisasterRuntime(data, i); e != nil {
				return e
			}
			writer, e := storage.LockWriterForRecovery(data, i.Rollback.Manifest.GID)
			if e != nil {
				return e
			}
			defer writer()
			fence, e := storage.ReadWriterFence(data)
			if e != nil || fence != i.Fence() {
				return errors.Join(e, errors.New("激活安装缺少原恢复屏障"))
			}
			if e = panelrecovery.InstallDisasterActivated(call, i); e != nil {
				return e
			}
			s, e := panelruntime.Read(data)
			if e != nil {
				return e
			}
			before, e := observePanelService(call, s)
			if e != nil {
				return e
			}
			if !validServiceObservation(before) || before.State != "stopped" {
				return errors.New("激活前面板不处于原停机边界")
			}
			intent := PanelServiceIntent{Input: PanelServiceInput{DataDir: data, Action: "start", MaintenanceID: i.Stop.MaintenanceID, StopID: i.Stop.OperationID}, ReleaseID: i.ReleaseID, BindingSHA256: i.Stop.BindingSHA256, StopSHA256: i.Stop.RequestSHA256, Before: before}
			child := Record{OperationID: a.StartID, Kind: panelServiceKind, State: "running", Stage: "controlling", RequestHash: panelServiceHash(a.StartID, intent), MaintenanceEpoch: epoch, Deadline: time.Now().Add(3 * time.Minute).Unix(), PanelService: &PanelServiceOperation{Intent: intent}}
			out.DisasterActivation.Start = &child
			out.Stage, out.MaintenanceEpoch = "activation_starting", epoch
			return save()
		}()
		if err != nil {
			return out, err
		}
	}
	if out.Stage == "activation_starting" {
		release, e := access()
		if e != nil {
			return out, e
		}
		err = func() error {
			defer release()
			if held, e := storage.ReadServiceHold(data); e == nil {
				if held != i.Stop {
					return errors.New("激活原停机标记已变化")
				}
			} else if !os.IsNotExist(e) {
				return e
			}
			// A replay with both markers absent may already have a live writer;
			// never reacquire its lifetime lock or reinstall database bytes.
			held, e := storage.ServiceHeld(data)
			if e != nil {
				return e
			}
			fenced, e := storage.WriterFenced(data)
			if e != nil {
				return e
			}
			if held || fenced {
				writer, e := storage.LockWriterForRecovery(data, i.Rollback.Manifest.GID)
				if e != nil {
					return e
				}
				defer writer()
				if e = panelrecovery.CheckDisasterActivatedTarget(call, i); e != nil {
					return e
				}
				if e = storage.ClearWriterFence(data, i.Fence()); e != nil {
					return e
				}
				if e = storage.ClearServiceHold(data, i.Stop); e != nil {
					return e
				}
			}
			out.MaintenanceEpoch = epoch
			return save()
		}()
		if err != nil {
			return out, err
		}
		if e = checkDisasterProgram(data, i); e != nil {
			return out, e
		}
		s, e := panelruntime.Read(data)
		if e != nil {
			return out, e
		}
		child := *out.DisasterActivation.Start
		saveChild := func(c Record) error { out.DisasterActivation.Start = &c; return save() }
		start, cancel := context.WithTimeout(call, 3*time.Minute)
		after, e := runPanelService(start, saveChild, &child, s)
		cancel()
		if e != nil {
			child.State, child.Error = "recovery_required", panelRestoreError(e)
			err = errors.Join(e, saveChild(child))
			return out, err
		}
		child.State, child.Stage, child.Error = "succeeded", "started", ""
		child.PanelService.After = &after
		out.DisasterActivation.Start = &child
		out.Stage = "activation_checking"
		if err = save(); err != nil {
			return out, err
		}
	}
	if out.Stage == "activation_checking" {
		if e := checkDisasterProgram(data, i); e != nil {
			return out, e
		}
		s, e := panelruntime.Read(data)
		if e != nil {
			return out, e
		}
		r, e := panelrecovery.ReadDisasterReconciliation(i)
		if e != nil {
			return out, e
		}
		ready, e := observePanelReadinessDatabase(call, j, s, *out.DisasterActivation.Start, r.Database, func(ctx context.Context) error { return panelrecovery.CheckDisasterActiveMaterial(ctx, i) }, epoch)
		if e != nil {
			return out, e
		}
		release, e := access()
		if e != nil {
			return out, e
		}
		out.DisasterActivation.Ready = &ready
		out.State, out.Stage, out.Error, out.MaintenanceEpoch = "waiting_confirmation", "committed", "", epoch
		err = save()
		release()
		if err != nil {
			return out, err
		}
	}
	// Releasing root admission and the application's own session are different
	// durable steps. Completion authorizes only that original session to release.
	err = awaitRelease()
	return out, err
}
