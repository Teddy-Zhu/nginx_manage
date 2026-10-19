package transport

import (
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) imageUpgradesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.PanelImageUpgrades == nil {
		s.fail(w, r, fault.Unavailable("面板镜像替换服务未配置"))
		return false
	}
	return true
}

func (s *Server) ListPanelImageUpgrades(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.PanelImageUpgrades.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetPanelImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.PanelImageUpgrades.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CreatePanelImageUpgrade(w http.ResponseWriter, r *http.Request, params apigen.CreatePanelImageUpgradeParams) {
	p, ok := s.authorize(w, r, true, "components.manage", "system.write")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	var in imageupdates.CreateInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.PanelImageUpgrades.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "面板镜像替换任务已受理", out)
}

func (s *Server) ResumePanelImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumePanelImageUpgradeParams) {
	p, ok := s.authorize(w, r, true, "components.manage", "system.write")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.PanelImageUpgrades.Resume(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原面板镜像替换续办请求已受理", out)
}
