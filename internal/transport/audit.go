package transport

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"nginxpanel/internal/auditlog"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/transport/apigen"
)

func auditReadError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fault.New(504, "AUDIT_READ_TIMEOUT", "审计读取超时，请缩小时间范围")
	}
	return err
}

func (s *Server) ListAudit(w http.ResponseWriter, r *http.Request, params apigen.ListAuditParams) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	if s.Audit == nil {
		s.fail(w, r, fault.Unavailable("审计查询服务未配置"))
		return
	}
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	limit := 30
	if params.Limit != nil {
		limit = int(*params.Limit)
	}
	q := auditlog.Query{Filter: auditlog.Filter{From: params.From, Until: params.Until, Principal: value(params.Principal), Action: value(params.Action), ResourceID: value(params.ResourceId), Outcome: value(params.Outcome), RequestID: value(params.RequestId)}, Limit: limit, Cursor: value(params.Cursor)}
	out, err := s.Audit.Query(r.Context(), q)
	if err != nil {
		s.fail(w, r, auditReadError(err))
		return
	}
	s.ok(w, r, out)
}

func (s *Server) ExportAudit(w http.ResponseWriter, r *http.Request, _ apigen.ExportAuditParams) {
	p, ok := s.authorize(w, r, "read")
	if !ok {
		return
	}
	if s.Audit == nil {
		s.fail(w, r, fault.Unavailable("审计查询服务未配置"))
		return
	}
	var in auditlog.Filter
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Audit.Export(r.Context(), in)
	if err != nil {
		s.fail(w, r, auditReadError(err))
		return
	}
	// The audit describes archive preparation, not successful client delivery.
	if err = s.audit(r, p.ID, "audit.export", out.Manifest.ID, "prepared"); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-`+out.Manifest.ID+`.jsonl"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(out.Bytes)))
	w.Header().Set("X-Archive-SHA256", secure.Hash(out.Bytes))
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write(out.Bytes); err != nil {
		slog.Warn("审计归档发送未完成", "request_id", r.Context().Value(requestIDKey), "archive_id", out.Manifest.ID, "error", err)
	}
}
