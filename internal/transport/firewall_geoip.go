package transport

import (
	"context"
	"net/http"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/transport/apigen"
	"time"
)

func (s *Server) GetFirewallGeoIP(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, false, "security.write"); !ok || !s.firewallReady(w, r) {
		return
	}
	out, err := s.Firewall.GeoIP(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) SetFirewallGeoIP(w http.ResponseWriter, r *http.Request, params apigen.SetFirewallGeoIPParams) {
	p, ok := s.authorize(w, r, true, "security.write")
	if !ok || !s.firewallReady(w, r) {
		return
	}
	var in firewall.GeoIPSourceInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Firewall.SaveGeoIPSource(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) UpdateFirewallGeoIP(w http.ResponseWriter, r *http.Request, params apigen.UpdateFirewallGeoIPParams) {
	p, ok := s.authorize(w, r, true, "security.write")
	if !ok || !s.firewallReady(w, r) {
		return
	}
	var in firewall.GeoIPUpdateInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(125 * time.Second)); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, err := s.Firewall.UpdateGeoIP(ctx, p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ResolveFirewallGeoIP(w http.ResponseWriter, r *http.Request, _ apigen.ResolveFirewallGeoIPParams) {
	if _, ok := s.authorize(w, r, false, "security.write"); !ok || !s.firewallReady(w, r) {
		return
	}
	var in firewall.GeoIPResolveInput
	if err := decodeLimit(w, r, &in, 8192); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Firewall.ResolveGeoIP(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
