package transport

import (
	"net/http"

	"nginxpanel/internal/acme"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListACMEProfiles(w http.ResponseWriter, r *http.Request, params apigen.ListACMEProfilesParams) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	limit, offset, err := pagination(params.Limit, params.Offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.Profiles(r.Context(), limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ListACMEOrders(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.ACME.Orders(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateACMEProfile(w http.ResponseWriter, r *http.Request, params apigen.CreateACMEProfileParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.ProfileInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.CreateProfile(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "签发配置已创建", out)
}
func (s *Server) IssueACMEProfile(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.IssueACMEProfileParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.IssueInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.QueueIssue(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "签发任务已排队", out)
}
func (s *Server) ArchiveACMEProfile(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ArchiveACMEProfileParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.ArchiveInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.ArchiveProfile(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
