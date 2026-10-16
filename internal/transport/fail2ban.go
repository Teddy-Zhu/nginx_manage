package transport

import (
	"context"
	"errors"
	"net/http"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/transport/apigen"
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

func (s *Server) fail2banReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Fail2ban == nil {
		s.fail(w, r, fault.Unavailable("jail 配置服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetFail2banPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, e := s.Fail2ban.Policy(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetFail2banPolicy(w http.ResponseWriter, r *http.Request, params apigen.SetFail2banPolicyParams) {
	p, ok := s.authorize(w, r, true, "security.write")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.PolicyInput
	if e := decodeLimit(w, r, &in, fail2ban.PolicyBytes+4096); e != nil {
		s.fail(w, r, e)
		return
	}
	out, e := s.Fail2ban.Save(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) PreviewFail2ban(w http.ResponseWriter, r *http.Request, _ apigen.PreviewFail2banParams) {
	if !s.fail2banReady(w, r) {
		return
	}
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	var in fail2ban.PreviewInput
	if e := decodeLimit(w, r, &in, 1024); e != nil {
		s.fail(w, r, e)
		return
	}
	out, e := s.Fail2ban.Preview(ctx, in.Version)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetFail2banTemplates(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok {
		return
	}
	s.ok(w, r, fail2ban.Templates())
}

func (s *Server) CheckFail2banTemplates(w http.ResponseWriter, r *http.Request, _ apigen.CheckFail2banTemplatesParams) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	var in fail2ban.TemplateCheckInput
	if err := decodeLimit(w, r, &in, 1024); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("未连接宿主机 Agent"))
		return
	}
	out, err := s.Agent.CheckFail2banTemplates(ctx, in)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetFail2banRuntime(w http.ResponseWriter, r *http.Request) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.Runtime(ctx)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ApplyFail2ban(w http.ResponseWriter, r *http.Request, params apigen.ApplyFail2banParams) {
	p, ok := s.authorize(w, r, true, "security.write")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.ApplyInput
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.Apply(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "jail 应用任务已创建", out)
}

func (s *Server) GetFail2banTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.ApplyTasks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
