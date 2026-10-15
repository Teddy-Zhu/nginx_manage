package transport

import (
	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) dnsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.HostDNS == nil {
		s.fail(w, r, fault.Unavailable("主机 DNS 服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetHostDNS(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.dnsReady(w, r) {
		return
	}
	out, err := s.HostDNS.Overview(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateHostDNSPlan(w http.ResponseWriter, r *http.Request, params apigen.CreateHostDNSPlanParams) {
	p, ok := s.authorize(w, r, true, "host.dns.write")
	if !ok || !s.dnsReady(w, r) {
		return
	}
	var in hostdns.PlanInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.HostDNS.CreatePlan(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ApplyHostDNS(w http.ResponseWriter, r *http.Request, params apigen.ApplyHostDNSParams) {
	p, ok := s.authorize(w, r, true, "host.dns.write")
	if !ok || !s.dnsReady(w, r) {
		return
	}
	var in struct {
		PlanID string `json:"plan_id"`
	}
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.HostDNS.Apply(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in.PlanID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ConfirmHostDNS(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ConfirmHostDNSParams) {
	s.decideHostDNS(w, r, id, params.IdempotencyKey, "confirm")
}
func (s *Server) RollbackHostDNS(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.RollbackHostDNSParams) {
	s.decideHostDNS(w, r, id, params.IdempotencyKey, "rollback")
}
func (s *Server) decideHostDNS(w http.ResponseWriter, r *http.Request, id, key, action string) {
	p, ok := s.authorize(w, r, true, "host.dns.write")
	if !ok || !s.dnsReady(w, r) {
		return
	}
	out, err := s.HostDNS.Decide(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, action)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
