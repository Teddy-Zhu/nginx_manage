package transport

import (
	"net/http"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.Config.Certificates.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetCertificate(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.Config.Certificates.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PreviewCertificateDeploy(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, false, "config.write", "config.secrets")
	if !ok {
		return
	}
	out, err := s.Config.PreviewCertificateDeploy(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ListCertificateDeployments(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	out, err := s.Config.CertificateDeployments(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) DeployCertificate(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeployCertificateParams) {
	p, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.CertificateDeployInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.DeployCertificate(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id, in, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "证书部署任务已排队", out)
}
func (s *Server) ImportCertificate(w http.ResponseWriter, r *http.Request, params apigen.ImportCertificateParams) {
	s.writeCertificate(w, r, "", "create", params.IdempotencyKey)
}
func (s *Server) ReplaceCertificate(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ReplaceCertificateParams) {
	s.writeCertificate(w, r, id, "replace", params.IdempotencyKey)
}
func (s *Server) DeleteCertificate(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteCertificateParams) {
	s.writeCertificate(w, r, id, "delete", params.IdempotencyKey)
}
func (s *Server) writeCertificate(w http.ResponseWriter, r *http.Request, id, action, key string) {
	principal, ok := s.authorize(w, r, true, "config.write", "config.secrets")
	if !ok {
		return
	}
	var input certificates.Input
	if action == "delete" {
		var body nginxconfig.ResourceActionRequest
		if err := decode(w, r, &body); err != nil {
			s.fail(w, r, err)
			return
		}
		input.BaseVersion = body.BaseVersion
	} else if err := decode(w, r, &input); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.Certificates.Write(r.Context(), principal, r.Context().Value(requestIDKey).(string), key, id, action, input)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := 201
	if action == "delete" {
		status = 200
	}
	s.respond(w, r, status, "OK", "证书资源已保存", out)
}
