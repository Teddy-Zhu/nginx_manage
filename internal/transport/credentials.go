package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/transport/apigen"
)

type credentialView struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedSources []string `json:"allowed_sources"`
	ExpiresAt      int64    `json:"expires_at"`
	Revoked        bool     `json:"revoked"`
}

func (s *Server) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "auth.manage"); !ok {
		return
	}
	data, err := s.credentials(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, data)
}

func (s *Server) credentials(ctx context.Context) ([]credentialView, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,scopes,allowed_sources,expires_at,revoked_at IS NOT NULL FROM api_credentials WHERE revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 100", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := []credentialView{}
	for rows.Next() {
		var v credentialView
		var scopes, sources string
		if err := rows.Scan(&v.ID, &v.Name, &scopes, &sources, &v.ExpiresAt, &v.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &v.Scopes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(sources), &v.AllowedSources); err != nil {
			return nil, err
		}
		data = append(data, v)
	}
	return data, rows.Err()
}
func (s *Server) CreateCredential(w http.ResponseWriter, r *http.Request, _ apigen.CreateCredentialParams) {
	p, ok := s.authorize(w, r, true, "auth.manage")
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
	p, ok := s.authorize(w, r, true, "auth.manage")
	if !ok {
		return
	}
	res, err := s.DB.ExecContext(r.Context(), "UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", time.Now().Unix(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n == 0 {
		s.respond(w, r, 404, "NOT_FOUND", "凭据不存在", nil)
		return
	}
	if err := s.audit(r, p.ID, "auth.revoke_credential", id, "succeeded"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nil)
}
