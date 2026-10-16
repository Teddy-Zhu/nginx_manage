package transport

import (
	"context"
	"errors"
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

func (s *Server) fail2banReadContext(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return nil, nil, false
	}
	if s.fail2banReads.Add(1) > 4 {
		s.fail2banReads.Add(-1)
		s.fail(w, r, fault.New(429, "FAIL2BAN_READ_BUSY", "Fail2ban 读取请求较多，请稍后刷新"))
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
	return ctx, func() { cancel(); s.fail2banReads.Add(-1) }, true
}
func (s *Server) GetFail2banInstance(w http.ResponseWriter, r *http.Request) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if s.Agent == nil {
		out := fail2ban.EmptyInstance("unconfirmed", "未连接宿主机 Agent")
		out.Source = "unavailable"
		s.ok(w, r, out)
		return
	}
	out, err := s.Agent.ReadFail2banInstance(ctx)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetFail2banJail(w http.ResponseWriter, r *http.Request, name string) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("未连接宿主机 Agent"))
		return
	}
	out, err := s.Agent.ReadFail2banJail(ctx, name)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) fail2banReadError(w http.ResponseWriter, r *http.Request, err error) {
	var known *fault.Error
	if errors.As(err, &known) {
		s.fail(w, r, known)
		return
	}
	s.fail(w, r, fault.Unavailable("宿主机 Fail2ban 实例暂不可读取"))
}
