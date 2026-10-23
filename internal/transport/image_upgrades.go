package transport

import (
	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) imageUpgradesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.ImageUpgrades == nil {
		s.fail(w, r, fault.Unavailable("镜像替换服务未配置"))
		return false
	}
	return true
}
func (s *Server) listImageUpgrades(w http.ResponseWriter, r *http.Request, component string) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.ImageUpgrades.List(r.Context(), p, component)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) getImageUpgrade(w http.ResponseWriter, r *http.Request, component, id string) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.ImageUpgrades.Get(r.Context(), p, component, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) createImageUpgrade(w http.ResponseWriter, r *http.Request, component, key string) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	var in imageupdates.CreateInput
	if component == imageupdates.Panel {
		var body apigen.PanelImageUpgradeCreateInput
		if err := decodeLimit(w, r, &body, 4096); err != nil {
			s.fail(w, r, err)
			return
		}
		in.MaintenanceID, in.PrepareTaskID = body.MaintenanceId, body.PrepareTaskId
		in.AllowDowntime = body.AllowDowntime != nil && *body.AllowDowntime
	} else if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ImageUpgrades.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), key, component, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "镜像替换任务已受理", out)
}
func (s *Server) resumeImageUpgrade(w http.ResponseWriter, r *http.Request, component, id, key string) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.imageUpgradesReady(w, r) {
		return
	}
	out, err := s.ImageUpgrades.Resume(r.Context(), p, r.Context().Value(requestIDKey).(string), key, component, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原镜像替换续办请求已受理", out)
}
func (s *Server) ListPanelImageUpgrades(w http.ResponseWriter, r *http.Request) {
	s.listImageUpgrades(w, r, imageupdates.Panel)
}
func (s *Server) GetPanelImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	s.getImageUpgrade(w, r, imageupdates.Panel, id)
}
func (s *Server) CreatePanelImageUpgrade(w http.ResponseWriter, r *http.Request, p apigen.CreatePanelImageUpgradeParams) {
	s.createImageUpgrade(w, r, imageupdates.Panel, p.IdempotencyKey)
}
func (s *Server) ResumePanelImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID, p apigen.ResumePanelImageUpgradeParams) {
	s.resumeImageUpgrade(w, r, imageupdates.Panel, id, p.IdempotencyKey)
}
func (s *Server) ListNginxImageUpgrades(w http.ResponseWriter, r *http.Request) {
	s.listImageUpgrades(w, r, imageupdates.Nginx)
}
func (s *Server) GetNginxImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	s.getImageUpgrade(w, r, imageupdates.Nginx, id)
}
func (s *Server) CreateNginxImageUpgrade(w http.ResponseWriter, r *http.Request, p apigen.CreateNginxImageUpgradeParams) {
	s.createImageUpgrade(w, r, imageupdates.Nginx, p.IdempotencyKey)
}
func (s *Server) ResumeNginxImageUpgrade(w http.ResponseWriter, r *http.Request, id apigen.ID, p apigen.ResumeNginxImageUpgradeParams) {
	s.resumeImageUpgrade(w, r, imageupdates.Nginx, id, p.IdempotencyKey)
}
