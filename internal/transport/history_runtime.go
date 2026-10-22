package transport

import (
	"context"
	"net/http"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) runtimeHistoryContext(w http.ResponseWriter, r *http.Request, kind string) (context.Context, context.CancelFunc, bool) {
	if kind != "recovery_snapshot" {
		return r.Context(), func() {}, true
	}
	ctx, cancel := context.WithTimeout(r.Context(), history.SnapshotRequestTimeout+10*time.Second)
	deadline, _ := ctx.Deadline()
	if err := http.NewResponseController(w).SetWriteDeadline(deadline.Add(5 * time.Second)); err != nil {
		cancel()
		s.fail(w, r, fault.Unavailable("快照维护连接无法设置响应时限"))
		return nil, nil, false
	}
	return ctx, cancel, true
}

func (s *Server) ListRuntimeHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read", "system.write", "config.secrets"); !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("运行材料 Agent 未配置"))
		return
	}
	out, err := s.Agent.RuntimeHistory(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) PreviewRuntimeHistory(w http.ResponseWriter, r *http.Request, _ apigen.PreviewRuntimeHistoryParams) {
	p, ok := s.authorize(w, r, true, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	var filter history.RuntimeFilter
	if err := decodeLimit(w, r, &filter, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := filter.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if filter.Kind == "agent_program" {
		if err := p.Require("components.manage"); err != nil {
			s.fail(w, r, err)
			return
		}
	} else if filter.Kind == "recovery_snapshot" {
		if err := p.Require("backup.restore"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("运行材料 Agent 未配置"))
		return
	}
	root, done, err := s.Maintenance.Held(filter.MaintenanceID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer done()
	ctx, cancel, ok := s.runtimeHistoryContext(w, r, filter.Kind)
	if !ok {
		return
	}
	defer cancel()
	out, err := s.Agent.PreviewRuntimeHistory(ctx, history.RuntimeRequest{Protocol: agent.Protocol, Epoch: root.Epoch, Input: history.RuntimeExecuteInput{Filter: filter}})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ExecuteRuntimeHistory(w http.ResponseWriter, r *http.Request, params apigen.ExecuteRuntimeHistoryParams) {
	p, ok := s.authorize(w, r, true, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	var in history.RuntimeExecuteInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Filter.Kind == "agent_program" {
		if err := p.Require("components.manage"); err != nil {
			s.fail(w, r, err)
			return
		}
	} else if in.Filter.Kind == "recovery_snapshot" {
		if err := p.Require("backup.restore"); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if in.OperationID == "" || params.IdempotencyKey != in.OperationID {
		s.fail(w, r, fault.Invalid("幂等键必须使用本次运行清理的操作 UUID"))
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("运行材料 Agent 未配置"))
		return
	}
	root, done, err := s.Maintenance.Held(in.Filter.MaintenanceID)
	if err != nil {
		prior, e := s.Agent.RuntimeHistoryOperation(r.Context(), in.OperationID)
		if e == nil && prior.OperationID == in.OperationID && prior.State == "succeeded" && prior.Preview.Filter == in.Filter && prior.Preview.SHA256 == in.SHA256 {
			if e = s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "succeeded"); e != nil {
				s.fail(w, r, e)
				return
			}
			s.ok(w, r, prior)
			return
		}
		s.fail(w, r, err)
		return
	}
	defer done()
	ctx, cancel, ok := s.runtimeHistoryContext(w, r, in.Filter.Kind)
	if !ok {
		return
	}
	defer cancel()
	if err = s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "prepared"); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Agent.ExecuteRuntimeHistory(ctx, history.RuntimeRequest{Protocol: agent.Protocol, Epoch: root.Epoch, Input: in})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out.OperationID != in.OperationID || out.State != "succeeded" || out.Preview.SHA256 != in.SHA256 {
		s.fail(w, r, fault.Unavailable("运行清理结果尚未确认，请核对原操作"))
		return
	}
	if err = s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
