package transport

import (
	"net/http"

	"nginxpanel/internal/acme"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListACMEAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.ACME.Accounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CreateACMEAccount(w http.ResponseWriter, r *http.Request, params apigen.CreateACMEAccountParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.AccountInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.CreateAccount(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "账户注册任务已排队", out)
}

func (s *Server) RegisterACMEAccount(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.RegisterACMEAccountParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.AccountAction
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.AccountAction(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, "register", in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "账户核对任务已排队", out)
}

func (s *Server) DeleteACMEAccount(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteACMEAccountParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.ResourceActionRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.AccountAction(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, "delete", acme.AccountAction{BaseVersion: in.BaseVersion})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ListDNSProviders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	s.ok(w, r, acme.DNSProviders())
}

func (s *Server) ListDNSCredentials(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.ACME.Credentials(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CreateDNSCredential(w http.ResponseWriter, r *http.Request, params apigen.CreateDNSCredentialParams) {
	s.writeDNSCredential(w, r, "", "create", params.IdempotencyKey)
}

func (s *Server) UpdateDNSCredential(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.UpdateDNSCredentialParams) {
	s.writeDNSCredential(w, r, id, "update", params.IdempotencyKey)
}

func (s *Server) DeleteDNSCredential(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteDNSCredentialParams) {
	s.writeDNSCredential(w, r, id, "delete", params.IdempotencyKey)
}

func (s *Server) writeDNSCredential(w http.ResponseWriter, r *http.Request, id, action, key string) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in acme.DNSInput
	if action == "delete" {
		var body nginxconfig.ResourceActionRequest
		if err := decode(w, r, &body); err != nil {
			s.fail(w, r, err)
			return
		}
		in.BaseVersion = body.BaseVersion
	} else if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.ACME.WriteCredential(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, action, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 200
	if action == "create" {
		status = 201
	}
	s.respond(w, r, status, "OK", "DNS 凭据资源已保存", out)
}
