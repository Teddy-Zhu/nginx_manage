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
	"nginxpanel/internal/agentupdates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
)

func agentUpgradeHost(ctx context.Context, data, id string) (active, failed bool, err error) {
	if !validID(id) {
		return false, false, fault.Invalid("Agent 升级操作标识无效")
	}
	if _, _, _, err = agentUpgradeUnits(ctx, data, id); err != nil {
		return
	}
	v, err := agentUpgradeProperties(ctx, agentUpgradeUnit(id), "ActiveState,SubState,MainPID,ControlPID")
	if err != nil {
		return false, false, err
	}
	switch v["ActiveState"] {
	case "active", "activating", "deactivating", "reloading":
		return true, false, nil
	case "inactive", "failed":
		if v["MainPID"] != "0" || v["ControlPID"] != "0" || v["ActiveState"] == "inactive" && v["SubState"] != "dead" || v["ActiveState"] == "failed" && v["SubState"] != "failed" {
			return false, false, errors.New("Agent 独立升级服务尚未停止")
		}
		return false, v["ActiveState"] == "failed", nil
	default:
		return false, false, errors.New("Agent 独立升级服务状态无法核实")
	}
}

func hostedAgentUpgrade(r Record, active bool) (agentupdates.Operation, error) {
	var zero agentupdates.Operation
	if err := validAgentUpgrade(r); err != nil {
		return zero, err
	}
	p := r.AgentUpgrade
	if len(p.Authorizations) == 0 {
		return zero, fault.Conflict("此 Agent 升级不是托管 API 原操作")
	}
	i, a := p.Intent, p.Authorizations[len(p.Authorizations)-1].Request
	in := agentUpgradeAPIInput(i.Input)
	o := agentupdates.Operation{Authorization: a, Protocol: Protocol, ID: r.OperationID, Input: in, RequestHash: agentupdates.Hash(r.OperationID, in), IntentSHA256: r.RequestHash, Sequence: a.Sequence, Command: a.Command, State: r.State, Stage: r.Stage, Error: r.Error, Failure: p.Failure, BeforeSHA256: i.Before.BinarySHA256, TargetSHA256: i.Target.BinarySHA256, TargetVersion: i.TargetVersion, PanelID: i.PanelID, ReadyEpoch: p.ReadyEpoch, Deadline: i.Deadline, UpdatedAt: r.UpdatedAt, Active: active, Finalized: agentUpgradeTerminal(r)}
	// A stopped worker never restarts from a status read. Its original root
	// record and compensation direction remain authoritative for explicit resume.
	if !active && !o.Finalized {
		o.State = "recovery_required"
		if o.Error == "" {
			o.Error = "独立升级服务未运行，须显式续办原操作"
		}
	}
	return o, o.Validate(r.OperationID, in)
}

func (s *Server) agentUpgradeScope() error {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" || s.ReleaseTrust == "" {
		return fault.Unavailable("Agent 独立升级的宿主机范围或发布信任未配置")
	}
	return nil
}

func (s *Server) readAgentUpgrade(ctx context.Context, id string) (agentupdates.Operation, error) {
	var zero agentupdates.Operation
	if err := s.agentUpgradeScope(); err != nil {
		return zero, err
	}
	if !validID(id) {
		return zero, fault.Invalid("Agent 升级操作标识无效")
	}
	r, err := AgentUpgradeStatus(s.DataDir, id)
	if os.IsNotExist(err) {
		return zero, fault.NotFound("Agent 升级操作不存在")
	}
	if err != nil {
		return zero, err
	}
	active, _, err := agentUpgradeHost(ctx, s.DataDir, id)
	if err != nil {
		return zero, err
	}
	return hostedAgentUpgrade(r, active)
}

func (s *Server) queueAgentUpgrade(ctx context.Context, req agentupdates.Request) (agentupdates.Operation, error) {
	var zero agentupdates.Operation
	if err := req.Validate(); err != nil {
		return zero, err
	}
	if err := s.agentUpgradeScope(); err != nil {
		return zero, err
	}
	// Historical authorizations only observe; even a lost start response must
	// not be turned into another dispatch by an HTTP retry.
	r, err := AgentUpgradeStatus(s.DataDir, req.OperationID)
	if err == nil {
		if _, err = hostedAgentUpgrade(r, false); err != nil {
			return zero, err
		}
		if req.Sequence <= len(r.AgentUpgrade.Authorizations) {
			if r.AgentUpgrade.Authorizations[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原 Agent 升级授权不能改变")
			}
			return s.readAgentUpgrade(ctx, req.OperationID)
		}
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	unlock, err := s.Journal.rootLock(".agent-upgrade.lock")
	if errors.Is(err, unix.EWOULDBLOCK) {
		return zero, fault.Conflict("Agent 独立升级仍在执行，请查询原操作")
	}
	if err != nil {
		return zero, err
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	installation, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		return zero, err
	}
	defer func() {
		if installation != nil {
			installation()
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
	r, err = AgentUpgradeStatus(s.DataDir, req.OperationID)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return zero, err
	}
	active, failed, err := agentUpgradeHost(ctx, s.DataDir, req.OperationID)
	if err != nil {
		// The worker locks are held and no transaction has been published.
		// Report a definite rejection so its task can finish and release admission.
		if fresh {
			return zero, fault.New(http.StatusConflict, "AGENT_UPGRADE_REJECTED", panelRestoreError(err))
		}
		return zero, err
	}
	if !fresh {
		o, e := hostedAgentUpgrade(r, active)
		if e != nil {
			return zero, e
		}
		if o.Input != req.Input || r.AgentUpgrade.Intent.Input.Stage.TrustPath != s.ReleaseTrust {
			return zero, fault.Conflict("原 Agent 升级目标、维护会话或发布信任不能改变")
		}
		a := r.AgentUpgrade.Authorizations
		if req.Sequence <= len(a) {
			if a[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原 Agent 升级授权不能改变")
			}
			return o, nil
		}
		if req.Sequence != len(a)+1 {
			return zero, fault.Conflict("Agent 升级续办须使用下一个连续授权序号")
		}
		if o.Finalized {
			return o, nil
		}
		agentHash, workerHash, _, e := agentUpgradeUnits(ctx, s.DataDir, req.OperationID)
		if e != nil {
			return zero, e
		}
		if agentHash != r.AgentUpgrade.Intent.AgentUnit || workerHash != r.AgentUpgrade.Intent.WorkerUnit {
			return zero, fault.Conflict("Agent 升级服务已偏离原登记，须本机恢复")
		}
	} else if req.Sequence != 1 || req.Command != "upgrade" {
		return zero, fault.NotFound("续办的原 Agent 升级不存在")
	}
	if active {
		return zero, fault.Conflict("原 Agent 独立升级服务尚未停止")
	}
	now := time.Now().Unix()
	if req.AuthorizationUntil <= now || req.AuthorizationUntil > now+305 {
		if fresh {
			return zero, fault.New(http.StatusConflict, "AGENT_UPGRADE_REJECTED", "Agent 升级启动授权已过期或超过五分钟，尚未创建独立事务")
		}
		return zero, fault.Conflict("Agent 升级启动授权已过期或超过五分钟")
	}
	access, err := panelUpdateAccess(ctx, s.Journal, req.OperationID, req.Input.MaintenanceID, req.Epoch, false)
	if err != nil {
		if fresh {
			return zero, fault.New(http.StatusConflict, "AGENT_UPGRADE_REJECTED", panelRestoreError(err))
		}
		return zero, err
	}
	defer func() {
		if access != nil {
			access()
		}
	}()
	if fresh {
		in := AgentUpgradeInput{MaintenanceID: req.Input.MaintenanceID, Stage: panelruntime.StageInput{DataDir: s.DataDir, PlanID: req.Input.PlanID, TrustPath: s.ReleaseTrust, AllowPrerelease: req.Input.Prerelease}}
		r, err = prepareAgentUpgrade(ctx, in, req.OperationID, req.Epoch)
		if err != nil {
			return zero, fault.New(http.StatusConflict, "AGENT_UPGRADE_REJECTED", panelRestoreError(err))
		}
	}
	now = time.Now().Unix()
	if req.AuthorizationUntil <= now {
		if fresh {
			return zero, fault.New(http.StatusConflict, "AGENT_UPGRADE_REJECTED", "Agent 升级准备期间授权已过期，尚未创建独立事务")
		}
		return zero, fault.Conflict("Agent 升级准备期间授权已过期，须重新授权")
	}
	r.AgentUpgrade.Authorizations = append(r.AgentUpgrade.Authorizations, AgentUpgradeAuthorization{Request: req, AcceptedAt: now})
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = (&agentUpgradeWorker{j: s.Journal, r: r}).save(); err != nil {
		return zero, err
	}
	access()
	access = nil
	service()
	service = nil
	installation()
	installation = nil
	unlock()
	unlock = nil
	if failed {
		if _, err = installationSystemctl(ctx, "reset-failed", agentUpgradeUnit(req.OperationID)); err != nil {
			return zero, fault.Unavailable("Agent 升级授权已保存，服务复位尚未确认，请查询原操作")
		}
	}
	if _, err = installationSystemctl(ctx, "start", "--no-block", agentUpgradeUnit(req.OperationID)); err != nil {
		return zero, fault.Unavailable("Agent 升级授权已保存，独立服务启动尚未确认，请查询原操作")
	}
	return s.readAgentUpgrade(ctx, req.OperationID)
}

func (s *Server) agentUpgradeHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agent/upgrades/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, err := s.readAgentUpgrade(r.Context(), r.PathValue("id"))
		componentReply(w, o, err)
	})
	mux.HandleFunc("POST /v1/agent/upgrades", func(w http.ResponseWriter, r *http.Request) {
		var req agentupdates.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("Agent 独立升级请求无效"))
			return
		}
		o, err := s.queueAgentUpgrade(r.Context(), req)
		componentReply(w, o, err)
	})
}

func (c *Client) AgentUpgrade(ctx context.Context, id string) (agentupdates.Operation, error) {
	var out agentupdates.Operation
	if !validID(id) {
		return out, fault.Invalid("Agent 升级操作标识无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/agent/upgrades/"+id, nil, &out)
	if err == nil {
		err = out.Validate(id, out.Input)
	}
	return out, err
}

func (c *Client) SubmitAgentUpgrade(ctx context.Context, in agentupdates.Request) (agentupdates.Operation, error) {
	var out agentupdates.Operation
	if err := in.Validate(); err != nil {
		return out, err
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/agent/upgrades", in, &out)
	if err == nil {
		err = out.Validate(in.OperationID, in.Input)
	}
	return out, err
}
