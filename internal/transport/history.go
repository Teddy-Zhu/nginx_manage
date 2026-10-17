package transport

import (
	"context"
	"errors"
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/history"
	"nginxpanel/internal/transport/apigen"
)

func historyError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fault.New(504, "HISTORY_TIMEOUT", "历史维护超时，请核对原操作结果或调整截止时间")
	}
	return err
}

func (s *Server) PreviewHistory(w http.ResponseWriter, r *http.Request, _ apigen.PreviewHistoryParams) {
	p, ok := s.authorize(w, r, true, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	if s.History == nil {
		s.fail(w, r, fault.Unavailable("历史维护服务未配置"))
		return
	}
	var in history.Filter
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.History.Preview(r.Context(), p, in)
	if err != nil {
		s.fail(w, r, historyError(err))
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ExecuteHistory(w http.ResponseWriter, r *http.Request, params apigen.ExecuteHistoryParams) {
	p, ok := s.authorize(w, r, true, "system.write", "config.write", "config.secrets")
	if !ok {
		return
	}
	if s.History == nil {
		s.fail(w, r, fault.Unavailable("历史维护服务未配置"))
		return
	}
	var in history.ExecuteInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.History.Execute(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, historyError(err))
		return
	}
	s.ok(w, r, out)
}
