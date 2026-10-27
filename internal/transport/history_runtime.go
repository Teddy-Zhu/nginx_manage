package transport

import (
	"net/http"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListRuntimeHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read", "system.write", "config.secrets"); !ok {
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
	for i := range out {
		out[i].Preview.Filter.MaintenanceID = ""
	}
	s.ok(w, r, out)
}

func runtimeFilter(in apigen.RuntimeHistoryFilter) history.RuntimeFilter {
	return history.RuntimeFilter{Kind: in.Kind, Before: in.Before, Keep: in.Keep}
}

func (s *Server) PreviewRuntimeHistory(w http.ResponseWriter, r *http.Request, _ apigen.PreviewRuntimeHistoryParams) {
	p, ok := s.authorize(w, r, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	var body apigen.RuntimeHistoryFilter
	if err := decodeLimit(w, r, &body, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	filter := runtimeFilter(body)
	if err := filter.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("运行材料 Agent 未配置"))
		return
	}
	var out history.RuntimePreview
	err := s.Maintenance.Temporary(r.Context(), p, r.Context().Value(requestIDKey).(string), "", func(root maintenance.RootStatus) error {
		filter.MaintenanceID = root.ID
		var err error
		out, err = s.Agent.PreviewRuntimeHistory(r.Context(), history.RuntimeRequest{Protocol: agent.Protocol, Epoch: root.Epoch, Input: history.RuntimeExecuteInput{Filter: filter}})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Filter.MaintenanceID = ""
	s.ok(w, r, out)
}

func (s *Server) ExecuteRuntimeHistory(w http.ResponseWriter, r *http.Request, params apigen.ExecuteRuntimeHistoryParams) {
	p, ok := s.authorize(w, r, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	var body apigen.RuntimeHistoryExecuteInput
	if err := decodeLimit(w, r, &body, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if !components.ValidID(body.OperationId) || params.IdempotencyKey != body.OperationId {
		s.fail(w, r, fault.Invalid("幂等键必须使用本次清理的操作标识"))
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("运行材料 Agent 未配置"))
		return
	}
	in := history.RuntimeExecuteInput{OperationID: body.OperationId, Filter: runtimeFilter(body.Filter), SHA256: body.Sha256}
	sessionID := ""
	records, err := s.Agent.RuntimeHistory(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, prior := range records {
		if prior.OperationID != in.OperationID {
			continue
		}
		previous := prior.Preview.Filter
		sessionID = previous.MaintenanceID
		previous.MaintenanceID = ""
		if previous != in.Filter || prior.Preview.SHA256 != in.SHA256 {
			s.fail(w, r, fault.Conflict("原清理标识已用于不同请求"))
			return
		}
		if prior.State == "succeeded" {
			if err = s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "succeeded"); err != nil {
				s.fail(w, r, err)
				return
			}
			prior.Preview.Filter.MaintenanceID = ""
			s.ok(w, r, prior)
			return
		}
		break
	}
	var out history.RuntimeStatus
	err = s.Maintenance.Temporary(r.Context(), p, r.Context().Value(requestIDKey).(string), sessionID, func(root maintenance.RootStatus) error {
		in.Filter.MaintenanceID = root.ID
		if err := s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "prepared"); err != nil {
			return err
		}
		var err error
		out, err = s.Agent.ExecuteRuntimeHistory(r.Context(), history.RuntimeRequest{Protocol: agent.Protocol, Epoch: root.Epoch, Input: in})
		if err != nil {
			return err
		}
		if out.OperationID != in.OperationID || out.State != "succeeded" || out.Preview.SHA256 != in.SHA256 {
			return fault.Unavailable("清理结果尚未确认，请继续核对原操作")
		}
		return s.audit(r, p.ID, "history.runtime.cleanup", in.OperationID, "succeeded")
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Preview.Filter.MaintenanceID = ""
	s.ok(w, r, out)
}
