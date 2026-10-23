package transport

import (
	"net/http"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) GetFail2banExistingResources(w http.ResponseWriter, r *http.Request) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.ExistingResources(ctx)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetFail2banExistingResource(w http.ResponseWriter, r *http.Request, name string) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.ExistingResource(ctx, name)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ChangeFail2banExistingPolicy(w http.ResponseWriter, r *http.Request, params apigen.ChangeFail2banExistingPolicyParams) {
	p, ok := s.authorize(w, r, "security.write")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.ExistingPolicyInput
	if err := decodeLimit(w, r, &in, 16384); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.ChangeExistingPolicy(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "参数操作任务已创建", out)
}

func (s *Server) GetFail2banExistingTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.ExistingTasks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) GetFail2banExistingTask(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.ExistingTask(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) CancelFail2banExistingPolicy(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.CancelFail2banExistingPolicyParams) {
	p, ok := s.authorize(w, r, "security.write")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.CancelExistingPolicy(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "取消申请已保存", out)
}
