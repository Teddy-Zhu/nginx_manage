package transport

import (
	"context"
	"net/http"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) monitoringReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Monitoring == nil {
		s.fail(w, r, fault.Unavailable("监控服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetMonitoringLatest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.monitoringReady(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := s.Monitoring.Latest(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetMonitoringSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.monitoringReady(w, r) {
		return
	}
	out, err := s.Monitoring.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetMonitoringSettings(w http.ResponseWriter, r *http.Request, params apigen.SetMonitoringSettingsParams) {
	p, ok := s.authorize(w, r, true, "monitoring.write")
	if !ok || !s.monitoringReady(w, r) {
		return
	}
	var in monitoring.SettingsInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Monitoring.SetSettings(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetMonitoringHistory(w http.ResponseWriter, r *http.Request, params apigen.GetMonitoringHistoryParams) {
	if _, ok := s.authorize(w, r, false, "read"); !ok || !s.monitoringReady(w, r) {
		return
	}
	if s.metricReads.Add(1) > 2 {
		s.metricReads.Add(-1)
		s.fail(w, r, fault.New(429, "MONITORING_BUSY", "趋势查询繁忙，请稍后重试"))
		return
	}
	defer s.metricReads.Add(-1)
	q := monitoring.HistoryQuery{Kind: params.Kind, ID: params.Id, Value: params.Value, From: params.From, Until: params.Until, Points: 180}
	if params.Points != nil {
		q.Points = *params.Points
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := s.Monitoring.History(ctx, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
