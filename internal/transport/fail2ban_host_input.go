package transport

import (
	"net/http"
	"nginxpanel/internal/fail2ban"
)

func (s *Server) GetFail2banHostInput(w http.ResponseWriter, r *http.Request) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if s.Agent == nil {
		s.ok(w, r, fail2ban.EmptyHostInput("unconfirmed", "未连接宿主机 Agent"))
		return
	}
	out, err := s.Agent.ReadFail2banHostInput(ctx)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}
