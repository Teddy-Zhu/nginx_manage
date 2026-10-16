package transport

import (
	"net/http"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ChangeFail2banPython(w http.ResponseWriter, r *http.Request, params apigen.ChangeFail2banPythonParams) {
	p, ok := s.authorize(w, r, true, "components.manage")
	if !ok || !s.fail2banReady(w, r) {
		return
	}
	var in fail2ban.PythonTaskInput
	if err := decodeLimit(w, r, &in, 2048); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Fail2ban.ChangePython(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "Python 依赖任务已创建", out)
}
func (s *Server) GetFail2banPythonTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.fail2banReady(w, r) {
		return
	}
	out, err := s.Fail2ban.PythonTasks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
