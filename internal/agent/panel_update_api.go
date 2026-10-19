package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/panelupdates"
)

func hostedPanelUpdate(r Record, active bool) (panelupdates.Operation, error) {
	if err := validPanelUpdate(r); err != nil {
		return panelupdates.Operation{}, err
	}
	p := r.PanelUpdate
	if len(p.Authorizations) == 0 {
		return panelupdates.Operation{}, fault.Conflict("此更新不是托管 API 原操作")
	}
	i, a := p.Intent, p.Authorizations[len(p.Authorizations)-1].Request
	in := panelUpdateAPIInput(i.Input)
	o := panelupdates.Operation{Authorization: a, Protocol: Protocol, ID: r.OperationID, Input: in, RequestHash: panelupdates.Hash(r.OperationID, in), IntentSHA256: r.RequestHash, Sequence: a.Sequence, Command: a.Command, State: r.State, Stage: r.Stage, Error: r.Error, Failure: p.Failure, BeforeID: i.BeforeID, TargetID: i.TargetID, SnapshotID: i.SnapshotID, BeforeSchema: i.BeforeSchema, TargetSchema: i.TargetSchema, Deadline: r.Deadline, UpdatedAt: r.UpdatedAt, Active: active, Finalized: panelUpdateFinalized(r), ReleaseAcknowledged: p.ReleaseAcknowledged}
	o.Cleanup = panelUpdateCleanupStatus(p)
	return o, o.Validate(r.OperationID, in)
}

func (s *Server) panelUpdateScope() error {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return fault.Unavailable("独立更新的宿主机管理范围未确认")
	}
	return nil
}

func (s *Server) readPanelUpdate(ctx context.Context, id string) (panelupdates.Operation, error) {
	var zero panelupdates.Operation
	if err := s.panelUpdateScope(); err != nil {
		return zero, err
	}
	if !validID(id) {
		return zero, fault.Invalid("更新操作标识无效")
	}
	r, err := panelUpdateRecord(s.DataDir, id)
	if os.IsNotExist(err) {
		return zero, fault.NotFound("更新操作不存在")
	}
	if err != nil {
		return zero, err
	}
	if _, err = hostedPanelUpdate(r, false); err != nil {
		return zero, err
	}
	active, failed, err := panelUpdateHost(ctx, s.DataDir, id)
	if err != nil {
		return zero, err
	}
	if !active && !panelUpdateTerminal(r) {
		unlock, e := s.Journal.rootLock(".panel-update.lock")
		if e == nil {
			defer unlock()
			r, e = panelUpdateRecord(s.DataDir, id)
			if e != nil {
				return zero, e
			}
			if _, e = hostedPanelUpdate(r, false); e != nil {
				return zero, e
			}
			w := &panelUpdateWorker{j: s.Journal, r: r}
			if panelUpdateFinalized(r) {
				if _, e = w.acknowledgeRelease(); e != nil {
					return zero, e
				}
			} else {
				a := r.PanelUpdate.Authorizations[len(r.PanelUpdate.Authorizations)-1].Request
				grant, e := s.Journal.Get(a.Input.MaintenanceID)
				if e != nil {
					return zero, e
				}
				if grant.Kind != "maintenance.lock" || grant.RequestHash != maintenanceHashForID(a.Input.MaintenanceID) {
					return zero, fault.Conflict("原维护记录身份无效")
				}
				if r.State != "queued" || r.PanelUpdate.Authorizations[len(r.PanelUpdate.Authorizations)-1].ClaimedAt != 0 || failed || a.AuthorizationUntil <= time.Now().Unix() || grant.MaintenanceEpoch != a.Epoch {
					w.r.State, w.r.Error = "recovery_required", "独立更新未完成且服务已停止，须在原维护会话中显式续办"
					if r.State != w.r.State || r.Error != w.r.Error {
						if e = w.save(); e != nil {
							return zero, e
						}
					}
				}
			}
			r, err = panelUpdateRecord(s.DataDir, id)
			if err != nil {
				return zero, err
			}
		} else if !errors.Is(e, unix.EWOULDBLOCK) {
			return zero, e
		}
	}
	return hostedPanelUpdate(r, active)
}

func (s *Server) queuePanelUpdate(ctx context.Context, req panelupdates.Request, rootRecovery bool) (panelupdates.Operation, error) {
	var zero panelupdates.Operation
	if rootRecovery && (os.Geteuid() != 0 || !req.Input.CoordinateAgent || req.Command != "resume") {
		return zero, fault.Invalid("协调更新本机恢复入口无效")
	}
	if err := req.Validate(); err != nil {
		return zero, err
	}
	if err := s.panelUpdateScope(); err != nil {
		return zero, err
	}
	active, failed, err := panelUpdateHost(ctx, s.DataDir, req.OperationID)
	if err != nil {
		return zero, err
	}
	// Exact historical requests only query; they never repeat a service start.
	r, err := panelUpdateRecord(s.DataDir, req.OperationID)
	if err == nil {
		if _, err = hostedPanelUpdate(r, active); err != nil {
			return zero, err
		}
		if req.Sequence <= len(r.PanelUpdate.Authorizations) {
			if r.PanelUpdate.Authorizations[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原更新授权不能改变")
			}
			return s.readPanelUpdate(ctx, req.OperationID)
		}
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	unlock, err := s.Journal.rootLock(".panel-update.lock")
	if errors.Is(err, unix.EWOULDBLOCK) {
		return zero, fault.Conflict("独立更新服务仍在执行，请查询原操作")
	}
	if err != nil {
		return zero, err
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	service, err := s.Journal.rootLock(".panel-service.lock")
	if err != nil {
		return zero, err
	}
	defer func() {
		if service != nil {
			service()
		}
	}()
	// Re-read both sources after acquiring the worker's locks.
	active, failed, err = panelUpdateHost(ctx, s.DataDir, req.OperationID)
	if err != nil {
		return zero, err
	}
	r, err = panelUpdateRecord(s.DataDir, req.OperationID)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return zero, err
	}
	if !fresh {
		o, e := hostedPanelUpdate(r, active)
		if e != nil {
			return zero, e
		}
		if o.Input != req.Input {
			return zero, fault.Conflict("原更新目标和维护会话不能改变")
		}
		a := r.PanelUpdate.Authorizations
		if req.Sequence <= len(a) {
			if a[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原更新授权不能改变")
			}
			return o, nil
		}
		if req.Sequence != len(a)+1 {
			return zero, fault.Conflict("更新续办授权必须使用下一个连续序号")
		}
		if panelUpdateFinalized(r) {
			return o, nil
		}
	} else if req.Sequence != 1 || req.Command != "update" {
		return zero, fault.NotFound("续办的原更新不存在")
	}
	if active {
		return zero, fault.Conflict("原独立更新服务尚未停止")
	}
	now := time.Now().Unix()
	if req.AuthorizationUntil <= now || req.AuthorizationUntil > now+305 {
		if fresh {
			return zero, fault.New(http.StatusConflict, "PANEL_UPDATE_REJECTED", "更新启动授权已过期或超过五分钟，尚未创建独立事务")
		}
		return zero, fault.Conflict("更新启动授权已过期或超过五分钟")
	}
	access, err := panelUpdateAccess(ctx, s.Journal, req.OperationID, req.Input.MaintenanceID, req.Epoch, rootRecovery)
	if err != nil {
		if fresh {
			return zero, fault.New(http.StatusConflict, "PANEL_UPDATE_REJECTED", panelRestoreError(err))
		}
		return zero, err
	}
	defer func() {
		if access != nil {
			access()
		}
	}()
	if fresh {
		in := PanelUpdateInput{CoordinateAgent: req.Input.CoordinateAgent, AllowDowntime: req.Input.AllowDowntime, MaintenanceID: req.Input.MaintenanceID, Stage: panelruntime.StageInput{DataDir: s.DataDir, PlanID: req.Input.PlanID, TrustPath: s.ReleaseTrust, AllowPrerelease: req.Input.Prerelease}}
		r, err = preparePanelUpdate(ctx, in, req.OperationID, req.Epoch)
		if err != nil {
			// The worker locks still prove the original parent did not exist; no
			// snapshot, service action or journal publication has occurred yet.
			return zero, fault.New(http.StatusConflict, "PANEL_UPDATE_REJECTED", panelRestoreError(err))
		}
		r.State = "queued"
	} else if r.PanelUpdate.Intent.Input.Stage.TrustPath != s.ReleaseTrust {
		return zero, fault.Conflict("本机更新信任登记与原操作不同")
	}
	if rootRecovery {
		if err = registerCoordinatedBootRescue(ctx, s.DataDir, &r); err != nil {
			return zero, err
		}
	}
	now = time.Now().Unix()
	if req.AuthorizationUntil <= now {
		if fresh {
			return zero, fault.New(http.StatusConflict, "PANEL_UPDATE_REJECTED", "更新准备期间启动授权已过期，尚未创建独立事务")
		}
		return zero, fault.Conflict("更新准备期间启动授权已过期，须重新授权")
	}
	r.PanelUpdate.Authorizations = append(r.PanelUpdate.Authorizations, PanelUpdateAuthorization{Request: req, AcceptedAt: now})
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = (&panelUpdateWorker{j: s.Journal, r: r}).save(); err != nil {
		return zero, err
	}
	access()
	access = nil
	service()
	service = nil
	unlock()
	unlock = nil
	if failed {
		if _, err = installationSystemctl(ctx, "reset-failed", panelUpdateUnit(req.OperationID)); err != nil {
			return zero, fault.Unavailable("更新授权已保存，服务复位结果未确认，请查询原操作")
		}
	}
	if _, err = installationSystemctl(ctx, "start", "--no-block", panelUpdateUnit(req.OperationID)); err != nil {
		return zero, fault.Unavailable("更新授权已保存，独立服务启动结果未确认，请查询原操作")
	}
	return s.readPanelUpdate(ctx, req.OperationID)
}

func (s *Server) panelUpdateHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/panel/updates/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, err := s.readPanelUpdate(r.Context(), r.PathValue("id"))
		componentReply(w, o, err)
	})
	mux.HandleFunc("POST /v1/panel/updates", func(w http.ResponseWriter, r *http.Request) {
		var req panelupdates.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("独立更新请求无效"))
			return
		}
		o, err := s.queuePanelUpdate(r.Context(), req, false)
		componentReply(w, o, err)
	})
}

func (c *Client) PanelUpdate(ctx context.Context, id string) (panelupdates.Operation, error) {
	var out panelupdates.Operation
	if !validID(id) {
		return out, fault.Invalid("更新操作标识无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/panel/updates/"+id, nil, &out)
	if err == nil {
		err = out.Validate(id, out.Input)
	}
	return out, err
}

func (c *Client) SubmitPanelUpdate(ctx context.Context, in panelupdates.Request) (panelupdates.Operation, error) {
	var out panelupdates.Operation
	if err := in.Validate(); err != nil {
		return out, err
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/panel/updates", in, &out)
	if err == nil {
		err = out.Validate(in.OperationID, in.Input)
	}
	return out, err
}
