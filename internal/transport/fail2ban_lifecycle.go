package transport

import (
	"net/http"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) PreviewFail2banLifecycle(w http.ResponseWriter, r *http.Request, _ apigen.PreviewFail2banLifecycleParams) {
	p, ok := s.authorize(w, r, false, "read")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.LifecyclePreviewInput
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	// The service enforces the action's explicit scopes as well as the read scope.
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	out, err := s.Fail2ban.PreviewLifecycle(ctx, p, in)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ChangeFail2banLifecycle(w http.ResponseWriter, r *http.Request, params apigen.ChangeFail2banLifecycleParams) {
	p, ok := s.authorize(w, r, true)
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.LifecycleInput
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.ChangeLifecycle(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "Fail2ban 实例操作任务已创建", out)
}
func (s *Server) GetFail2banLifecycleTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.LifecycleTasks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
