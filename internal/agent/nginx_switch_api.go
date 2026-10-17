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
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/nginxswitch"
	"nginxpanel/internal/secure"
)

func switchJobChild(data string, r Record) (*Record, error) {
	j := r.NginxSwitchJob
	c, err := ReadNginxSwitch(data, j.ChildID)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	i := c.NginxSwitch
	if i.Input != j.Source || i.Before.SHA256 != j.Input.ExpectedSHA256 || i.RevisionID != j.Input.ExpectedRevision || i.Directory != revisionDir(j.Input.ExpectedDeployment) || i.Candidate.Signed == nil || i.Candidate.Signed.ManifestSHA256 != j.Input.ManifestSHA256 || i.Candidate.Signed.TrustSHA256 != j.Input.TrustSHA256 {
		return nil, errors.New("切换子操作与原 API 批准不一致")
	}
	return &c, nil
}

func switchJobOperation(data string, r Record, active bool) (nginxswitch.Operation, error) {
	var out nginxswitch.Operation
	if err := validSwitchJob(r); err != nil {
		return out, err
	}
	j := r.NginxSwitchJob
	a := j.Authorizations[len(j.Authorizations)-1].Request
	out = nginxswitch.Operation{Protocol: Protocol, ID: r.OperationID, RequestHash: nginxswitch.Hash(r.OperationID, j.Input), Input: j.Input, Authorization: a, Sequence: a.Sequence, Command: a.Command, State: r.State, Stage: r.Stage, Error: r.Error, Active: active, UpdatedAt: r.UpdatedAt, ChildID: j.ChildID}
	c, err := switchJobChild(data, r)
	if err != nil {
		return out, err
	}
	if c != nil {
		i := c.NginxSwitch
		out.IntentSHA256, out.Deadline = c.RequestHash, c.Deadline
		out.Before = &nginxswitch.Component{Owner: i.Before.Owner, SHA256: i.Before.SHA256, Version: i.Before.Version}
		out.Candidate = &nginxswitch.Component{Owner: i.Candidate.Owner, SHA256: i.Candidate.SHA256, Version: i.Candidate.Version}
		if p := i.Confirmation; p != nil {
			out.Confirmation = &nginxswitch.Confirmation{ConfirmedAt: p.ConfirmedAt, SHA256: p.BinarySHA256, Version: p.Version, RevisionID: p.Runtime.RevisionID, DeploymentID: p.Runtime.DeploymentID, AgentPID: p.AgentPID, NginxPID: p.NginxPID}
		}
		if r.State == "running" {
			out.Stage, out.Error = c.Stage, c.Error
			if c.State == "compensating" {
				out.State = "compensating"
			}
		}
		if nginxswitch.Terminal(r.State) && r.State != c.State {
			return out, errors.New("切换派发终态与子操作不一致")
		}
	}
	return out, out.Validate(r.OperationID, j.Input)
}

func (s *Server) switchScope() error {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return fault.Unavailable("原生组件切换的宿主机范围未确认")
	}
	return nil
}

func (s *Server) readNginxSwitch(ctx context.Context, id string) (nginxswitch.Operation, error) {
	var empty nginxswitch.Operation
	if err := s.switchScope(); err != nil {
		return empty, err
	}
	r, err := switchJobRecord(s.DataDir, id)
	if os.IsNotExist(err) {
		return empty, fault.NotFound("切换操作不存在")
	}
	if err != nil {
		return empty, err
	}
	active, failed, err := switchJobHost(ctx, s.DataDir, id)
	if err != nil {
		return empty, err
	}
	if !active && !nginxswitch.Terminal(r.State) {
		unlock, e := s.Journal.rootLock(".nginx-switch-api.lock")
		if e == nil {
			defer unlock()
			r, e = switchJobRecord(s.DataDir, id)
			if e != nil {
				return empty, e
			}
			beforeState, beforeStage, beforeError := r.State, r.Stage, r.Error
			child, e := switchJobChild(s.DataDir, r)
			if e != nil {
				return empty, e
			}
			if child != nil && nginxswitch.Terminal(child.State) {
				r.State, r.Stage, r.Error = child.State, child.Stage, child.Error
			} else {
				a := r.NginxSwitchJob.Authorizations[len(r.NginxSwitchJob.Authorizations)-1]
				grant, e := s.Journal.Get(a.Request.Input.MaintenanceID)
				if e != nil {
					return empty, e
				}
				if grant.Kind != "maintenance.lock" || grant.RequestHash != maintenanceHashForID(a.Request.Input.MaintenanceID) {
					return empty, errors.New("切换原维护记录无效")
				}
				if r.State != "queued" || a.ClaimedAt != 0 || failed || a.Request.AuthorizationUntil <= time.Now().Unix() || grant.MaintenanceEpoch != a.Request.Epoch {
					r.State, r.Error = "recovery_required", "独立切换服务已停止，须在原维护会话中显式续办或补偿"
				}
			}
			if r.State != beforeState || r.Stage != beforeStage || r.Error != beforeError {
				if e = s.Journal.Put(r); e != nil {
					return empty, e
				}
			}
			r, e = switchJobRecord(s.DataDir, id)
			if e != nil {
				return empty, e
			}
		} else if !errors.Is(e, unix.EWOULDBLOCK) {
			return empty, e
		}
	}
	return switchJobOperation(s.DataDir, r, active)
}

func (s *Server) queueNginxSwitch(ctx context.Context, req nginxswitch.Request) (nginxswitch.Operation, error) {
	var empty nginxswitch.Operation
	if err := req.Validate(); err != nil {
		return empty, err
	}
	if err := s.switchScope(); err != nil {
		return empty, err
	}
	r, err := switchJobRecord(s.DataDir, req.OperationID)
	if err == nil && req.Sequence <= r.NginxSwitchJob.Authorizations[len(r.NginxSwitchJob.Authorizations)-1].Request.Sequence {
		if prior, ok := switchJobRequest(r, req.Sequence); !ok || prior != req {
			return empty, fault.Conflict("原切换授权不能改变")
		}
		return s.dispatchNginxSwitch(ctx, req)
	}
	if err != nil && !os.IsNotExist(err) {
		return empty, err
	}
	unlock, err := s.Journal.rootLock(".nginx-switch-api.lock")
	if err != nil {
		return empty, fault.Conflict("独立切换执行器仍忙，请查询原任务")
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	active, failed, err := switchJobHost(ctx, s.DataDir, req.OperationID)
	if err != nil {
		return empty, err
	}
	if active {
		return empty, fault.Conflict("原切换服务尚未停止")
	}
	access, err := s.Journal.maintenanceLock()
	if err != nil {
		return empty, err
	}
	defer func() {
		if access != nil {
			access()
		}
	}()
	r, err = switchJobRecord(s.DataDir, req.OperationID)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return empty, err
	}
	if !fresh {
		j := r.NginxSwitchJob
		if j.Input != req.Input {
			return empty, fault.Conflict("切换目标、原发布和维护会话不能改变")
		}
		if req.Sequence <= j.Authorizations[len(j.Authorizations)-1].Request.Sequence {
			if prior, ok := switchJobRequest(r, req.Sequence); !ok || prior != req {
				return empty, fault.Conflict("原切换授权不能改变")
			}
			return switchJobOperation(s.DataDir, r, false)
		}
		if req.Sequence <= j.Authorizations[len(j.Authorizations)-1].Request.Sequence || req.Command == "switch" {
			return empty, fault.Conflict("切换续办须使用更高的授权序号")
		}
		if nginxswitch.Terminal(r.State) {
			return switchJobOperation(s.DataDir, r, false)
		}
		child, e := switchJobChild(s.DataDir, r)
		if e != nil {
			return empty, e
		}
		if child != nil && nginxswitch.Terminal(child.State) {
			r.State, r.Stage, r.Error = child.State, child.Stage, child.Error
			if e = s.Journal.Put(r); e != nil {
				return empty, e
			}
			r, e = switchJobRecord(s.DataDir, req.OperationID)
			if e != nil {
				return empty, e
			}
			return switchJobOperation(s.DataDir, r, false)
		}
	} else if req.Sequence != 1 || req.Command != "switch" {
		return empty, fault.NotFound("原切换记录不存在，不能重建")
	}
	if err = installGrant(s.Journal, req.Input.MaintenanceID, req.Epoch, false); err != nil {
		return empty, fault.Conflict("须确认原维护会话已进入 held")
	}
	now := time.Now().Unix()
	if req.AuthorizationUntil <= now || req.AuthorizationUntil > now+305 {
		return empty, fault.Conflict("切换启动授权已过期或超过五分钟")
	}
	if failed {
		if fresh {
			return empty, fault.Conflict("切换服务存在无法关联的失败实例，须本机核对")
		}
		// Only a new explicit grant may clear an earlier unit failure. Status
		// queries and retries of a claimed grant never restart the worker.
		if _, err = installationSystemctl(ctx, "reset-failed", switchJobUnit(req.OperationID)); err != nil {
			return empty, err
		}
		active, failed, err = switchJobHost(ctx, s.DataDir, req.OperationID)
		if err != nil {
			return empty, err
		}
		if active || failed {
			return empty, fault.Conflict("原切换服务尚未恢复到可启动状态")
		}
	}
	if fresh {
		records, e := (&maintenanceGate{journal: s.Journal}).records()
		if e != nil {
			return empty, e
		}
		for _, p := range records {
			if p.Kind == "maintenance.lock" {
				continue
			}
			if p.Kind == panelUpdateKind {
				settled, e := settledPanelUpdate(p, req.Input.MaintenanceID)
				if e != nil {
					return empty, e
				}
				if settled {
					continue
				}
			}
			if !nginxswitch.Terminal(p.State) && p.State != "cancelled" {
				return empty, fault.Conflict("其他副作用操作尚未结束")
			}
		}
		if s.Installation == nil || s.Installation.SHA256 != req.Input.ExpectedSHA256 || s.Nginx == nil || s.Nginx.Container != nil {
			return empty, fault.Conflict("原生 Nginx 安装来源已变化")
		}
		state := s.Nginx.State(ctx)
		if !state.Available || !state.Integrity || !state.Running || state.ExternalChange || state.RevisionID != req.Input.ExpectedRevision || state.DeploymentID != req.Input.ExpectedDeployment {
			return empty, fault.Conflict("当前运行发布与原切换批准不一致")
		}
		source := NginxSwitchInput{MaintenanceID: req.Input.MaintenanceID, AllowDowntime: true, Source: nginxruntime.Input{DataDir: s.DataDir, PlanID: req.Input.PlanID, AssetID: req.Input.AssetID, TrustPath: s.ReleaseTrust, Prerelease: req.Input.Prerelease}}
		if e = source.Source.Validate(); e != nil {
			return empty, e
		}
		job := &nginxSwitchJob{Input: req.Input, Source: source, ChildID: secure.ID()}
		r = Record{OperationID: req.OperationID, Kind: nginxSwitchJobKind, NginxSwitchJob: job, RequestHash: switchJobHash(req.OperationID, *job)}
	}
	r.NginxSwitchJob.Authorizations = append(r.NginxSwitchJob.Authorizations, nginxSwitchAuthorization{Request: req})
	r.MaintenanceEpoch, r.Deadline, r.State, r.Stage, r.Error = req.Epoch, req.AuthorizationUntil, "queued", "queued", ""
	if err = validSwitchJob(r); err != nil {
		return empty, err
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	if err = s.Journal.Put(r); err != nil {
		return empty, err
	}
	access()
	access = nil
	unlock()
	unlock = nil
	return s.dispatchNginxSwitch(ctx, req)
}

func (s *Server) dispatchNginxSwitch(ctx context.Context, req nginxswitch.Request) (nginxswitch.Operation, error) {
	op, err := s.readNginxSwitch(ctx, req.OperationID)
	if err != nil || op.State != "queued" || op.Active || op.Authorization != req {
		return op, err
	}
	unlock, err := s.Journal.rootLock(".nginx-switch-api.lock")
	if errors.Is(err, unix.EWOULDBLOCK) {
		return op, nil
	}
	if err != nil {
		return op, err
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	access, err := s.Journal.maintenanceLock()
	if err != nil {
		return op, err
	}
	defer func() {
		if access != nil {
			access()
		}
	}()
	r, err := switchJobRecord(s.DataDir, req.OperationID)
	if err != nil {
		return op, err
	}
	a := r.NginxSwitchJob.Authorizations[len(r.NginxSwitchJob.Authorizations)-1]
	active, failed, err := switchJobHost(ctx, s.DataDir, req.OperationID)
	if err != nil {
		return op, err
	}
	if r.State != "queued" || a.Request != req || a.ClaimedAt != 0 || active || failed || req.AuthorizationUntil <= time.Now().Unix() {
		return switchJobOperation(s.DataDir, r, active)
	}
	if err = installGrant(s.Journal, req.Input.MaintenanceID, req.Epoch, false); err != nil {
		return op, fault.Conflict("原切换派发维护授权已变化")
	}
	access()
	access = nil
	unlock()
	unlock = nil
	if _, err = installationSystemctl(ctx, "start", "--no-block", switchJobUnit(req.OperationID)); err != nil {
		return op, fault.Unavailable("切换派发已保存，服务启动结果未确认，请查询原操作")
	}
	return s.readNginxSwitch(ctx, req.OperationID)
}

func (s *Server) nginxSwitchHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/components/nginx-switches/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.readNginxSwitch(r.Context(), r.PathValue("id"))
		componentReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/components/nginx-switches", func(w http.ResponseWriter, r *http.Request) {
		var req nginxswitch.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("组件切换请求无效"))
			return
		}
		out, err := s.queueNginxSwitch(r.Context(), req)
		componentReply(w, out, err)
	})
}
func (c *Client) NginxSwitch(ctx context.Context, id string) (nginxswitch.Operation, error) {
	var out nginxswitch.Operation
	if !validID(id) {
		return out, fault.Invalid("切换操作标识无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components/nginx-switches/"+id, nil, &out)
	return out, err
}
func (c *Client) SubmitNginxSwitch(ctx context.Context, in nginxswitch.Request) (nginxswitch.Operation, error) {
	var out nginxswitch.Operation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/components/nginx-switches", in, &out)
	return out, err
}
