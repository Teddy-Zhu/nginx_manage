package transport

import (
	"net/http"

	"nginxpanel/internal/agentupdates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) agentUpgradesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.AgentUpgrades == nil {
		s.fail(w, r, fault.Unavailable("Agent 升级服务未配置"))
		return false
	}
	return true
}

func (s *Server) ListAgentUpgrades(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.agentUpgradesReady(w, r) {
		return
	}
	out, err := s.AgentUpgrades.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetAgentUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.agentUpgradesReady(w, r) {
		return
	}
	out, err := s.AgentUpgrades.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CreateAgentUpgrade(w http.ResponseWriter, r *http.Request, params apigen.CreateAgentUpgradeParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.agentUpgradesReady(w, r) {
		return
	}
	var in agentupdates.CreateInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.AgentUpgrades.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "Agent 升级任务已受理", out)
}

func (s *Server) ResumeAgentUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumeAgentUpgradeParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.agentUpgradesReady(w, r) {
		return
	}
	out, err := s.AgentUpgrades.Resume(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原 Agent 升级续办请求已受理", out)
}
