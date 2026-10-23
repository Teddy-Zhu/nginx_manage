package transport

import (
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelupdates"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) updatesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Updates == nil {
		s.fail(w, r, fault.Unavailable("面板更新服务未配置"))
		return false
	}
	return true
}

func (s *Server) ListPanelUpdates(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.updatesReady(w, r) {
		return
	}
	out, err := s.Updates.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetPanelUpdate(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.updatesReady(w, r) {
		return
	}
	out, err := s.Updates.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CreatePanelUpdate(w http.ResponseWriter, r *http.Request, params apigen.CreatePanelUpdateParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.updatesReady(w, r) {
		return
	}
	var in panelupdates.CreateInput
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Updates.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "面板更新任务已受理", out)
}

func (s *Server) ResumePanelUpdate(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumePanelUpdateParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.updatesReady(w, r) {
		return
	}
	out, err := s.Updates.Resume(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原面板更新续办请求已受理", out)
}
