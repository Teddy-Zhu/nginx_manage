package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/launcher"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const panelServiceKind = "panel.service"

type PanelServiceInput struct {
	DataDir       string `json:"data_dir"`
	Action        string `json:"action"`
	MaintenanceID string `json:"maintenance_id"`
	StopID        string `json:"stop_id"`
	SelectionID   string `json:"selection_id"`
}
type PanelServiceIntent struct {
	Input         PanelServiceInput       `json:"input"`
	ReleaseID     string                  `json:"release_id"`
	BindingSHA256 string                  `json:"binding_sha256"`
	StopSHA256    string                  `json:"stop_sha256"`
	Before        PanelServiceObservation `json:"before"`
}
type PanelServiceOperation struct {
	Intent     PanelServiceIntent       `json:"intent"`
	Dispatches []launcher.Request       `json:"dispatches,omitempty"`
	After      *PanelServiceObservation `json:"after,omitempty"`
}

func panelServiceHash(id string, in PanelServiceIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int                `json:"protocol"`
		ID       string             `json:"operation_id"`
		Intent   PanelServiceIntent `json:"intent"`
	}{Protocol, id, in})
	return secure.Hash(raw)
}
func validServiceObservation(o PanelServiceObservation) bool {
	if (o.Mode != "native" && o.Mode != "docker") || !validID(o.BootID) || !panelSelectionDigest.MatchString(o.ReleaseID) {
		return false
	}
	if o.State == "stopped" {
		return o.PID == 0 && o.InstanceID == "" && o.StartTicks == 0
	}
	return o.State == "running" && o.PID > 1 && validID(o.InstanceID) && (o.Mode == "docker" && o.StartTicks == 0 || o.Mode == "native" && o.StartTicks > 0)
}
func validPanelService(r Record) error {
	if r.Kind != panelServiceKind || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) || r.PanelService == nil {
		return errors.New("面板进程独立记录身份无效")
	}
	p := r.PanelService
	i := p.Intent
	if _, err := panelruntime.Root(i.Input.DataDir); err != nil {
		return err
	}
	if !validID(i.Input.MaintenanceID) || !validServiceObservation(i.Before) || !panelSelectionDigest.MatchString(i.ReleaseID) || !panelSelectionDigest.MatchString(i.BindingSHA256) || r.RequestHash != panelServiceHash(r.OperationID, i) || len(p.Dispatches) > 4 {
		return errors.New("面板进程独立记录与原授权不一致")
	}
	if i.Input.Action == "stop" {
		if i.Input.StopID != "" || i.Input.SelectionID != "" || i.StopSHA256 != "" || i.Before.State == "running" && i.Before.ReleaseID != i.ReleaseID {
			return errors.New("面板停机授权无效")
		}
	} else if i.Input.Action == "start" {
		if !validID(i.Input.StopID) || !panelSelectionDigest.MatchString(i.StopSHA256) || i.Input.SelectionID != "" && !validID(i.Input.SelectionID) || i.Before.State != "stopped" {
			return errors.New("面板启动须关联原停机记录")
		}
	} else {
		return errors.New("面板进程动作无效")
	}
	for n, req := range p.Dispatches {
		if i.Before.Mode != "docker" || req.Protocol != launcher.Protocol || req.OperationID != r.OperationID || !validID(req.BootID) || req.Action != i.Input.Action || req.ReleaseID != i.ReleaseID || req.Action == "start" && req.InstanceID != "" || req.Action == "stop" && req.InstanceID != i.Before.InstanceID {
			return errors.New("面板 launcher 派发身份无效")
		}
		for k := 0; k < n; k++ {
			if p.Dispatches[k].BootID == req.BootID {
				return errors.New("面板 launcher 启动标识重复")
			}
		}
	}
	if r.State == "succeeded" {
		if p.After == nil || !validServiceObservation(*p.After) || p.After.Mode != i.Before.Mode || i.Input.Action == "stop" && (r.Stage != "stopped" || p.After.State != "stopped") || i.Input.Action == "start" && (r.Stage != "started" || p.After.State != "running" || p.After.ReleaseID != i.ReleaseID) {
			return errors.New("面板进程完成记录无效")
		}
	} else if (r.State != "running" && r.State != "recovery_required") || r.Stage != "controlling" || p.After != nil {
		return errors.New("面板进程独立记录阶段无效")
	}
	return nil
}
func panelStopHold(r Record) storage.ServiceHold {
	i := r.PanelService.Intent
	return storage.ServiceHold{Schema: 1, OperationID: r.OperationID, MaintenanceID: i.Input.MaintenanceID, RequestSHA256: r.RequestHash, ReleaseID: i.ReleaseID, BindingSHA256: i.BindingSHA256}
}

// ControlPanelService stops or starts only the bound management process. It
// keeps maintenance held and never reports application readiness or upgrade
// success. Nginx and Fail2ban are outside this operation's control boundary.
func ControlPanelService(ctx context.Context, in PanelServiceInput, id, epoch string) (Record, error) {
	var out Record
	if os.Geteuid() != 0 || !validID(id) || !validID(in.MaintenanceID) || !validID(epoch) || id == in.MaintenanceID || (in.Action != "stop" && in.Action != "start") || in.Action == "stop" && (in.StopID != "" || in.SelectionID != "") || in.Action == "start" && (!validID(in.StopID) || in.StopID == id || in.SelectionID != "" && !validID(in.SelectionID)) {
		return out, errors.New("面板进程操作需要 root 和有效的维护身份")
	}
	if _, err := panelruntime.Root(in.DataDir); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	if err = installGrant(j, in.MaintenanceID, epoch, true); err != nil {
		return out, err
	}
	prior, err := panelServiceRecord(in.DataDir, id)
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		return out, err
	}
	if !fresh {
		if prior.PanelService.Intent.Input != in {
			return out, errors.New("操作标识已有不同的面板进程授权")
		}
		out = prior
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
			if r.State != "succeeded" && r.OperationID != in.MaintenanceID {
				return out, errors.New("存在其他未结束的维护会话")
			}
			continue
		}
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return out, errors.New("其他独立任务仍在执行或待恢复")
		}
	}
	uid, gid, err := panelSnapshotIdentity(in.DataDir)
	if err != nil {
		return out, err
	}
	s, err := panelruntime.Read(in.DataDir)
	if err != nil {
		return out, err
	}
	if s.Deployment.UID != uid || s.Deployment.GID != gid {
		return out, errors.New("面板运行账户已变化")
	}
	var stop Record
	if in.Action == "start" {
		stop, err = panelServiceRecord(in.DataDir, in.StopID)
		if err != nil {
			return out, err
		}
		if stop.State != "succeeded" || stop.PanelService.Intent.Input.Action != "stop" || stop.PanelService.Intent.Input.MaintenanceID != in.MaintenanceID || stop.PanelService.Intent.BindingSHA256 != selectionValueHash(s.Deployment) {
			return out, errors.New("启动不属于原维护会话的已完成停机")
		}
		if s.Release.ID != stop.PanelService.Intent.ReleaseID {
			if !validID(in.SelectionID) {
				return out, errors.New("启动新版本须关联原版本选择记录")
			}
			selected, e := panelSelectionRecord(in.DataDir, in.SelectionID)
			if e != nil {
				return out, e
			}
			i := selected.PanelSelection
			if selected.State != "succeeded" || i.MaintenanceID != in.MaintenanceID || i.BeforeID != stop.PanelService.Intent.ReleaseID || i.TargetID != s.Release.ID || i.BindingSHA256 != selectionValueHash(s.Deployment) {
				return out, errors.New("启动版本不属于原停机后的批准选择")
			}
			approved, e := panelruntime.Staged(ctx, i.Stage)
			if e != nil {
				return out, e
			}
			if approved.Release.ID != i.TargetID || selectionValueHash(approved.Approval) != i.ApprovalSHA256 {
				return out, errors.New("启动版本的当前签名批准已变化")
			}
		} else if in.SelectionID != "" {
			return out, errors.New("原版本启动不应关联其他版本选择")
		}
	}
	if fresh {
		fenced, e := storage.WriterFenced(in.DataDir)
		if e != nil {
			return out, e
		}
		if fenced {
			return out, errors.New("数据恢复标记尚未解除，须先完成原恢复操作")
		}
		hold, e := storage.ReadServiceHold(in.DataDir)
		if in.Action == "stop" {
			if e == nil {
				return out, errors.New("已有持久停机标记，须继续原操作")
			}
			if !errors.Is(e, os.ErrNotExist) {
				return out, e
			}
		} else if e != nil {
			return out, e
		} else if hold != panelStopHold(stop) {
			return out, errors.New("停机标记不属于原启动授权")
		}
		before, e := observePanelService(ctx, s)
		if e != nil {
			return out, e
		}
		if !validServiceObservation(before) || in.Action == "start" && before.State != "stopped" {
			return out, errors.New("面板进程尚未处于可控制的稳定状态")
		}
		i := PanelServiceIntent{Input: in, ReleaseID: s.Release.ID, BindingSHA256: selectionValueHash(s.Deployment), Before: before}
		if in.Action == "start" {
			i.StopSHA256 = stop.RequestHash
		}
		out = Record{OperationID: id, Kind: panelServiceKind, State: "running", Stage: "controlling", MaintenanceEpoch: epoch, PanelService: &PanelServiceOperation{Intent: i}, Deadline: time.Now().Unix() + 180}
		out.RequestHash = panelServiceHash(id, i)
	}
	i := out.PanelService.Intent
	if i.ReleaseID != s.Release.ID || i.BindingSHA256 != selectionValueHash(s.Deployment) || in.Action == "start" && i.StopSHA256 != stop.RequestHash {
		return out, errors.New("原面板进程操作的程序或运行绑定已偏离")
	}
	out.State, out.Error = "running", ""
	if err = j.Put(out); err != nil {
		return out, err
	}
	var after PanelServiceObservation
	if err = ctx.Err(); err != nil {
		// Keep the original hold when cancellation precedes the live step.
	} else if in.Action == "stop" {
		err = storage.BindServiceHold(in.DataDir, panelStopHold(out))
	} else {
		var fenced bool
		fenced, err = storage.WriterFenced(in.DataDir)
		if err == nil && fenced {
			err = errors.New("数据恢复标记尚未解除，不能启动面板")
		}
		if err == nil {
			_, holdErr := storage.ReadServiceHold(in.DataDir)
			if holdErr == nil {
				var releaseWriter func()
				releaseWriter, err = storage.LockWriterForMaintenance(in.DataDir, gid)
				if err == nil {
					err = storage.ClearServiceHold(in.DataDir, panelStopHold(stop))
					releaseWriter()
				}
			} else if !errors.Is(holdErr, os.ErrNotExist) {
				err = holdErr
			}
		}
	}
	if err == nil {
		after, err = runPanelService(ctx, j, &out, s)
	}
	if err == nil && in.Action == "stop" {
		var releaseWriter func()
		releaseWriter, err = storage.LockWriterForMaintenance(in.DataDir, gid)
		if err == nil {
			defer releaseWriter()
		}
	}
	if err != nil {
		out.State, out.Error = "recovery_required", panelRestoreError(err)
		if save := j.Put(out); save != nil {
			return out, errors.Join(err, save)
		}
		return out, err
	}
	out.State = "succeeded"
	if in.Action == "stop" {
		out.Stage = "stopped"
	} else {
		out.Stage = "started"
	}
	out.PanelService.After = &after
	if err = j.Put(out); err != nil {
		return out, err
	}
	return panelServiceRecord(in.DataDir, id)
}

func panelServiceRecord(data, id string) (Record, error) {
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
		return out, errors.New("面板进程记录不是原始规范记录")
	}
	if err = validPanelService(out); err != nil {
		return out, err
	}
	if out.OperationID != id || out.PanelService.Intent.Input.DataDir != data {
		return out, errors.New("面板进程记录不属于当前节点")
	}
	return out, nil
}
func PanelServiceOperationStatus(data, id string) (Record, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return Record{}, errors.New("面板进程记录查询需要 root 和原操作标识")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return Record{}, err
	}
	return panelServiceRecord(data, id)
}

func runPanelService(ctx context.Context, j *Journal, r *Record, s panelruntime.Snapshot) (PanelServiceObservation, error) {
	i := r.PanelService.Intent
	nativeIssued := false
	for {
		if err := ctx.Err(); err != nil {
			return PanelServiceObservation{}, err
		}
		o, err := observePanelService(ctx, s)
		if err != nil {
			return o, err
		}
		if i.Input.Action == "stop" && o.State == "stopped" && validServiceObservation(o) {
			return o, nil
		}
		if i.Input.Action == "start" && o.State == "running" && o.ReleaseID == i.ReleaseID && validServiceObservation(o) {
			return o, nil
		}
		if i.Input.Action == "stop" && (o.BootID != i.Before.BootID || o.InstanceID != i.Before.InstanceID || o.PID != i.Before.PID || o.StartTicks != i.Before.StartTicks) {
			return o, errors.New("原面板进程实例已变化，停止操作须本机核对")
		}
		if s.Deployment.Mode == "native" {
			if nativeIssued && i.Input.Action == "start" && o.State == "stopped" {
				return o, errors.New("原生面板启动后已退出，须核对服务日志")
			}
			if !nativeIssued {
				if i.Input.Action == "start" && o.State == "stopped" {
					if _, err = installationSystemctl(ctx, "reset-failed", "nginxpanel.service"); err != nil {
						return o, err
					}
					_, err = installationSystemctl(ctx, "start", "nginxpanel.service")
				} else if i.Input.Action == "stop" {
					_, err = installationSystemctl(ctx, "stop", "nginxpanel.service")
				}
				if err != nil {
					return o, err
				}
				nativeIssued = true
			}
		} else {
			var req *launcher.Request
			for n := range r.PanelService.Dispatches {
				if r.PanelService.Dispatches[n].BootID == o.BootID {
					req = &r.PanelService.Dispatches[n]
					break
				}
			}
			if req == nil {
				if len(r.PanelService.Dispatches) >= 4 {
					return o, errors.New("launcher 重启次数超过原操作续行上限，须本机处理")
				}
				request := launcher.Request{Protocol: launcher.Protocol, Action: i.Input.Action, OperationID: r.OperationID, BootID: o.BootID, ReleaseID: i.ReleaseID}
				if request.Action == "stop" {
					request.InstanceID = i.Before.InstanceID
				}
				r.PanelService.Dispatches = append(r.PanelService.Dispatches, request)
				if err = j.Put(*r); err != nil {
					return o, err
				}
				req = &r.PanelService.Dispatches[len(r.PanelService.Dispatches)-1]
			}
			c := launcher.Client{DataDir: i.Input.DataDir}
			op, err := c.Operation(ctx, r.OperationID)
			if errors.Is(err, launcher.ErrOperationNotFound) {
				op, err = c.Control(ctx, *req)
			}
			if err != nil {
				return o, err
			}
			if op.Request != *req {
				return o, errors.New("launcher 原操作回执身份已偏离")
			}
			if op.State == "failed" {
				return o, errors.New("launcher 原操作失败：" + op.Error)
			}
		}
		select {
		case <-ctx.Done():
			return o, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
