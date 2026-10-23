package transport

import (
	"context"
	"net/http"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) GetFirewall(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	if s.Agent == nil {
		out := firewall.Empty("unconfirmed", "未连接宿主机 Agent")
		out.Source = "unavailable"
		s.ok(w, r, out)
		return
	}
	if s.firewallReads.Add(1) > 4 {
		s.firewallReads.Add(-1)
		s.fail(w, r, fault.New(429, "FIREWALL_READ_BUSY", "防火墙读取请求较多，请稍后刷新"))
		return
	}
	defer s.firewallReads.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, e := s.Agent.ReadFirewall(ctx)
	if e != nil {
		s.fail(w, r, fault.Unavailable("宿主机防火墙诊断暂不可用"))
		return
	}
	s.ok(w, r, out)
}

func (s *Server) firewallReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Firewall == nil {
		s.fail(w, r, fault.Unavailable("防火墙策略服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetFirewallPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.firewallReady(w, r) {
		return
	}
	out, e := s.Firewall.Policy(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetFirewallPolicy(w http.ResponseWriter, r *http.Request, params apigen.SetFirewallPolicyParams) {
	p, ok := s.authorize(w, r, "security.write")
	if !ok || !s.firewallReady(w, r) {
		return
	}
	var in firewall.PolicyInput
	if e := decodeLimit(w, r, &in, firewall.PolicyBytes+4096); e != nil {
		s.fail(w, r, e)
		return
	}
	out, e := s.Firewall.Save(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PreviewFirewall(w http.ResponseWriter, r *http.Request, _ apigen.PreviewFirewallParams) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.firewallReady(w, r) {
		return
	}
	var in firewall.PreviewInput
	if e := decodeLimit(w, r, &in, 1024); e != nil {
		s.fail(w, r, e)
		return
	}
	out, e := s.Firewall.Preview(r.Context(), in.Version)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
