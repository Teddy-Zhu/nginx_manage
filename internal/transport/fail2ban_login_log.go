package transport

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/protocol"
)

// Credential rejection remains the login result even when its supplementary
// security log is unavailable. Never replay an uncertain append.
func (s *Server) recordPanelLoginFailure(r *http.Request) {
	if s.Dev {
		return
	}
	requestID := r.Context().Value(requestIDKey).(string)
	ip, err := netip.ParseAddr(auth.ClientIP(r))
	if err == nil && ip.Zone() == "" && s.Agent != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
		defer cancel()
		err = s.Agent.RecordPanelLogin(ctx, fail2ban.PanelLoginInput{Protocol: protocol.Agent, PeerAddr: ip.Unmap().String(), RequestID: requestID})
	} else {
		s.warnPanelLoginLog(requestID)
		return
	}
	if err != nil {
		s.warnPanelLoginLog(requestID)
	}
}
func (s *Server) warnPanelLoginLog(requestID string) {
	now := time.Now().Unix()
	prior := s.loginLogWarn.Load()
	if now-prior >= 30 && s.loginLogWarn.CompareAndSwap(prior, now) {
		slog.Warn("Panel login failure log delivery unconfirmed", "request_id", requestID)
	}
}
func (s *Server) GetFail2banPanelLogin(w http.ResponseWriter, r *http.Request) {
	ctx, done, ok := s.fail2banReadContext(w, r)
	if !ok {
		return
	}
	defer done()
	if s.Agent == nil {
		s.ok(w, r, fail2ban.EmptyPanelLogin("unconfirmed", "未连接宿主机 Agent"))
		return
	}
	out, err := s.Agent.ReadPanelLogin(ctx)
	if err != nil {
		s.fail2banReadError(w, r, err)
		return
	}
	s.ok(w, r, out)
}
