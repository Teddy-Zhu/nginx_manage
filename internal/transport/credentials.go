package transport

import (
	"net/http"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListCredentials(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "auth.manage")
	if !ok {
		return
	}
	data, err := s.Auth.ListCredentials(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}

func (s *Server) CreateCredential(w http.ResponseWriter, r *http.Request, _ apigen.CreateCredentialParams) {
	p, ok := s.authorize(w, r, "auth.manage")
	if !ok {
		return
	}
	var in auth.CredentialInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	id, token, err := s.Auth.CreateCredential(r.Context(), p, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(r, p.ID, "auth.create_credential", id, "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "凭据仅展示一次，请妥善保存", map[string]string{"id": id, "token": token})
}
func (s *Server) RevokeCredential(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.RevokeCredentialParams) {
	p, ok := s.authorize(w, r, "auth.manage")
	if !ok {
		return
	}
	if err := s.Auth.RevokeCredential(r.Context(), p, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.audit(r, p.ID, "auth.revoke_credential", id, "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
