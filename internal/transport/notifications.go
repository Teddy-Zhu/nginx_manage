package transport

import (
	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) notificationsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Notifications == nil {
		s.fail(w, r, fault.Unavailable("通知服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetNotifications(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.notificationsReady(w, r) {
		return
	}
	out, err := s.Notifications.Overview(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetNotificationPolicy(w http.ResponseWriter, r *http.Request, params apigen.SetNotificationPolicyParams) {
	p, ok := s.authorize(w, r, "notifications.write")
	if !ok || !s.notificationsReady(w, r) {
		return
	}
	var in notifications.PolicyInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Notifications.SetPolicy(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateNotificationChannel(w http.ResponseWriter, r *http.Request, params apigen.CreateNotificationChannelParams) {
	s.saveNotificationChannel(w, r, "", params.IdempotencyKey)
}
func (s *Server) UpdateNotificationChannel(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.UpdateNotificationChannelParams) {
	s.saveNotificationChannel(w, r, id, params.IdempotencyKey)
}
func (s *Server) saveNotificationChannel(w http.ResponseWriter, r *http.Request, id, key string) {
	p, ok := s.authorize(w, r, "notifications.write")
	if !ok || !s.notificationsReady(w, r) {
		return
	}
	var in notifications.ChannelInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Notifications.SaveChannel(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) DeleteNotificationChannel(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteNotificationChannelParams) {
	s.notificationChannelAction(w, r, id, params.IdempotencyKey, false)
}
func (s *Server) TestNotificationChannel(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.TestNotificationChannelParams) {
	s.notificationChannelAction(w, r, id, params.IdempotencyKey, true)
}
func (s *Server) notificationChannelAction(w http.ResponseWriter, r *http.Request, id, key string, test bool) {
	p, ok := s.authorize(w, r, "notifications.write")
	if !ok || !s.notificationsReady(w, r) {
		return
	}
	var in struct {
		BaseVersion int64 `json:"base_version"`
	}
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.BaseVersion < 1 {
		s.fail(w, r, fault.Invalid("渠道版本无效"))
		return
	}
	var out notifications.Change
	var err error
	if test {
		out, err = s.Notifications.Test(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, in.BaseVersion)
	} else {
		out, err = s.Notifications.DeleteChannel(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, in.BaseVersion)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func notificationPage(limit, offset *int) (int, int) {
	size, start := 30, 0
	if limit != nil {
		size = *limit
	}
	if offset != nil {
		start = *offset
	}
	return size, start
}
func (s *Server) ListNotificationEvents(w http.ResponseWriter, r *http.Request, params apigen.ListNotificationEventsParams) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.notificationsReady(w, r) {
		return
	}
	limit, offset := notificationPage(params.Limit, params.Offset)
	out, err := s.Notifications.Events(r.Context(), limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ListNotificationDeliveries(w http.ResponseWriter, r *http.Request, params apigen.ListNotificationDeliveriesParams) {
	if _, ok := s.authorize(w, r, "read"); !ok || !s.notificationsReady(w, r) {
		return
	}
	limit, offset := notificationPage(params.Limit, params.Offset)
	channel := ""
	if params.ChannelId != nil {
		channel = *params.ChannelId
	}
	out, err := s.Notifications.Deliveries(r.Context(), channel, limit, offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) RetryNotificationDelivery(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.RetryNotificationDeliveryParams) {
	p, ok := s.authorize(w, r, "notifications.write")
	if !ok || !s.notificationsReady(w, r) {
		return
	}
	out, err := s.Notifications.Retry(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
