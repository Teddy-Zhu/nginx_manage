package fail2ban

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"nginxpanel/internal/protocol"
)

const PanelLoginTemplate = "panel-login-failure"
const PanelLoginFormat = "nginxpanel_auth"
const PanelLoginSource = "panel:login"
const PanelLoginFileBytes int64 = 4 << 20

type PanelLoginEvent struct {
	Time      string `json:"time_iso8601"`
	Event     string `json:"event"`
	PeerAddr  string `json:"peer_addr"`
	Source    string `json:"source"`
	RequestID string `json:"request_id"`
}

func (e PanelLoginEvent) Valid() bool {
	at, err := time.Parse(time.RFC3339, e.Time)
	ip, ipErr := netip.ParseAddr(e.PeerAddr)
	return err == nil && at.Unix() > 0 && at.UTC().Format("2006-01-02T15:04:05-07:00") == e.Time && ipErr == nil && ip.Zone() == "" && ip.Unmap().String() == e.PeerAddr && e.Event == "login_failed" && e.Source == "tcp_peer" && policyID.MatchString(e.RequestID)
}
func (e PanelLoginEvent) Line() string { raw, _ := json.Marshal(e); return string(raw) }

type PanelLoginInput struct {
	Protocol  int    `json:"protocol"`
	PeerAddr  string `json:"peer_addr"`
	RequestID string `json:"request_id"`
}

func (in PanelLoginInput) Valid() bool {
	ip, err := netip.ParseAddr(in.PeerAddr)
	return in.Protocol == protocol.Agent && err == nil && ip.Zone() == "" && ip.Unmap().String() == in.PeerAddr && policyID.MatchString(in.RequestID)
}

type PanelLoginStatus struct {
	At         int64             `json:"at"`
	Available  bool              `json:"available"`
	SourceID   string            `json:"source_id"`
	Format     string            `json:"format"`
	Scope      string            `json:"scope"`
	Reason     string            `json:"reason"`
	Bytes      int64             `json:"bytes"`
	LimitBytes int64             `json:"limit_bytes"`
	Events     []PanelLoginEvent `json:"events"`
}

func EmptyPanelLogin(scope, reason string) PanelLoginStatus {
	return PanelLoginStatus{At: time.Now().Unix(), SourceID: PanelLoginSource, Format: PanelLoginFormat, Scope: scope, Reason: reason, LimitBytes: 2 * PanelLoginFileBytes, Events: []PanelLoginEvent{}}
}
func (s PanelLoginStatus) Valid() bool {
	if s.At <= 0 || s.SourceID != PanelLoginSource || s.Format != PanelLoginFormat || s.Bytes < 0 || s.Bytes > 2*PanelLoginFileBytes || s.LimitBytes != 2*PanelLoginFileBytes || s.Events == nil || len(s.Events) > 20 || s.Available && (s.Scope != "host" || s.Reason != "") || !s.Available && s.Reason == "" {
		return false
	}
	for _, event := range s.Events {
		if !event.Valid() {
			return false
		}
	}
	return true
}

type PanelLoginReader interface {
	ReadPanelLogin(context.Context) (PanelLoginStatus, error)
}

func (s *PolicyService) PanelLogin(ctx context.Context) (PanelLoginStatus, error) {
	reader, ok := s.Agent.(PanelLoginReader)
	if !ok {
		return EmptyPanelLogin("unconfirmed", "未连接面板登录日志来源"), nil
	}
	return reader.ReadPanelLogin(ctx)
}
