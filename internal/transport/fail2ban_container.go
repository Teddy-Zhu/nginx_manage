package transport

import (
	"net/http"
	"nginxpanel/internal/fault"
)

func (s *Server) GetFail2banContainer(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorize(w, r, "read")
	if !ok {
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("登录防护服务未连接"))
		return
	}
	out, err := s.Agent.ReadFail2banContainer(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
