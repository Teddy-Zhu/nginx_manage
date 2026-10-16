package transport

import (
	"context"
	"net/http"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

func (s *Server) GetFirewall(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
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
