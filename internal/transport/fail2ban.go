package transport

import (
	"context"
	"net/http"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

func (s *Server) GetFail2ban(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	if s.Agent == nil {
		out := fail2ban.Empty("unconfirmed", "未连接宿主机 Agent")
		out.Source = "unavailable"
		s.ok(w, r, out)
		return
	}
	if s.fail2banReads.Add(1) > 4 {
		s.fail2banReads.Add(-1)
		s.fail(w, r, fault.New(429, "FAIL2BAN_READ_BUSY", "Fail2ban 读取请求较多，请稍后刷新"))
		return
	}
	defer s.fail2banReads.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, err := s.Agent.ReadFail2ban(ctx)
	if err != nil {
		s.fail(w, r, fault.Unavailable("宿主机 Fail2ban 诊断暂不可用"))
		return
	}
	s.ok(w, r, out)
}
