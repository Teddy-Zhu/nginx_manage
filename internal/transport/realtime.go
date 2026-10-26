package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/remoteapi"
)

var realtimeScopes = map[string][]string{
	"tasks": {"read"}, "monitoring": {"read"}, "notifications": {"read"},
	"maintenance": {"read", "system.write"}, "backups": {"read", "backup.export"},
	"firewall": {"read", "security.write"}, "listener": {"read", "system.write"}, "version": {"read"},
}

// Fingerprints contain no credentials and never leave this process. Clients
// receive invalidations and read through the existing, permission-checked API.
func (s *Server) realtimeFingerprint(ctx context.Context, topic string) (string, error) {
	var value any
	var err error
	switch topic {
	case "tasks":
		rows, e := s.DB.QueryContext(ctx, `SELECT id,kind,state,stage,last_error,observed_revision,updated_at FROM tasks ORDER BY id`)
		if e != nil {
			return "", e
		}
		defer rows.Close()
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		for rows.Next() {
			var id, kind, state, stage, lastError, revision string
			var updated int64
			if e = rows.Scan(&id, &kind, &state, &stage, &lastError, &revision, &updated); e != nil {
				return "", e
			}
			if e = encoder.Encode([]any{id, kind, state, stage, lastError, revision, updated}); e != nil {
				return "", e
			}
		}
		return hex.EncodeToString(hash.Sum(nil)), rows.Err()
	case "monitoring":
		if s.Monitoring == nil {
			return "", errors.New("monitoring unavailable")
		}
		value, err = s.Monitoring.Latest(ctx)
	case "notifications":
		// Delivery changes may leave aggregate health counts unchanged.
		rows, e := s.DB.QueryContext(ctx, `SELECT 'delivery:'||id,state,json_array(last_error,attempts,next_attempt_at),completed_at FROM notification_deliveries UNION ALL SELECT 'event:'||id,state,json_array(summary,occurrences),last_seen_at FROM notification_events ORDER BY 1`)
		if e != nil {
			return "", e
		}
		defer rows.Close()
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		for rows.Next() {
			var id, state, lastError string
			var completed any
			if e = rows.Scan(&id, &state, &lastError, &completed); e != nil {
				return "", e
			}
			if e = encoder.Encode([]any{id, state, lastError, completed}); e != nil {
				return "", e
			}
		}
		if e = rows.Err(); e != nil {
			return "", e
		}
		rows.Close()
		if s.Notifications == nil {
			return "", errors.New("notifications unavailable")
		}
		value, err = s.Notifications.Overview(ctx)
		if err == nil {
			err = encoder.Encode(value)
		}
		return hex.EncodeToString(hash.Sum(nil)), err
	case "maintenance":
		if s.Maintenance == nil {
			return "", errors.New("maintenance unavailable")
		}
		value = s.Maintenance.View()
	case "backups":
		// Policy and file cleanup do not always transition the generic task.
		rows, e := s.DB.QueryContext(ctx, `SELECT b.task_id,t.state,t.stage,b.archive_size,b.deleted_at,t.last_error FROM backup_records b JOIN tasks t ON t.id=b.task_id ORDER BY b.task_id`)
		if e != nil {
			return "", e
		}
		defer rows.Close()
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		for rows.Next() {
			var id, state, stage, message string
			var size int64
			var deleted any
			if e = rows.Scan(&id, &state, &stage, &size, &deleted, &message); e != nil {
				return "", e
			}
			if e = encoder.Encode([]any{id, state, stage, size, deleted, message}); e != nil {
				return "", e
			}
		}
		if e = rows.Err(); e != nil {
			return "", e
		}
		rows.Close()
		var version, nextRun int64
		var message string
		if e = s.DB.QueryRowContext(ctx, "SELECT version,next_run_at,last_error FROM backup_policy WHERE id=1").Scan(&version, &nextRun, &message); e != nil {
			return "", e
		}
		if e = encoder.Encode([]any{version, nextRun, message}); e != nil {
			return "", e
		}
		return hex.EncodeToString(hash.Sum(nil)), nil
	case "firewall":
		if s.Agent == nil {
			return "", errors.New("agent unavailable")
		}
		var runtime firewall.RuntimeView
		runtime, err = s.Agent.FirewallRuntime(ctx)
		runtime.Kernel.ObservedAt = 0
		runtime.ProtectionObservation.ObservedAt = 0
		value = runtime
	case "listener":
		if s.Agent == nil {
			return "", errors.New("agent unavailable")
		}
		value, err = s.Agent.ManagementListener(ctx)
	case "version":
		if s.FrontendVersion != nil {
			var id string
			id, _, err = s.FrontendVersion()
			value = id
		}
	default:
		return "", errors.New("unknown topic")
	}
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(value)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), err
}

func (s *Server) realtime(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "read")
	if !ok {
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		s.fail(w, r, fault.Invalid("需要 WebSocket 连接"))
		return
	}
	// Cookie-authenticated sockets require an exact same-origin browser handshake.
	origin := r.Header.Get("Origin")
	if !p.Machine || origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if err != nil || u.Scheme != scheme || !strings.EqualFold(u.Host, r.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			s.fail(w, r, fault.New(403, "ORIGIN_REJECTED", "实时连接来源未获授权"))
			return
		}
	}
	topics := strings.Split(r.URL.Query().Get("topics"), ",")
	if len(topics) == 0 || len(topics) > len(realtimeScopes) {
		s.fail(w, r, fault.Invalid("实时订阅无效"))
		return
	}
	for _, topic := range topics {
		scopes, exists := realtimeScopes[topic]
		if !exists {
			s.fail(w, r, fault.Invalid("实时订阅类型无效"))
			return
		}
		if err := p.Require(scopes...); err != nil {
			s.fail(w, r, err)
			return
		}
		if r.Header.Get(remoteapi.HopHeader) != "" && slices.Contains([]string{"firewall", "listener", "backups"}, topic) {
			s.fail(w, r, auth.ErrForbidden)
			return
		}
	}
	if s.realtimeStreams.Add(1) > 32 {
		s.realtimeStreams.Add(-1)
		s.fail(w, r, fault.New(429, "REALTIME_BUSY", "实时连接数量已达上限"))
		return
	}
	defer s.realtimeStreams.Add(-1)
	var upstream *websocket.Conn
	connection := r.URL.Query().Get("connection")
	node := s.NodeID
	if connection != "" {
		if p.Machine || r.Header.Get(remoteapi.HopHeader) != "" || s.Nodes == nil {
			s.fail(w, r, auth.ErrForbidden)
			return
		}
		var err error
		upstream, node, err = s.Nodes.OpenRealtime(r.Context(), p, connection, topics)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		defer upstream.Close()
	}
	upgrader := websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024, HandshakeTimeout: 5 * time.Second, CheckOrigin: func(*http.Request) bool { return true }, Error: func(w http.ResponseWriter, r *http.Request, _ int, _ error) {
		s.fail(w, r, fault.Invalid("实时连接握手失败"))
	}}
	// No session mutation is performed during the read-only handshake.
	conn, err := upgrader.Upgrade(w, r, w.Header())
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(1024)
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(45 * time.Second)) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	write := func(payload any) error {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(payload)
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	var wake <-chan struct{}
	var take func() []string
	var incoming chan json.RawMessage
	if upstream == nil {
		sub := s.Realtime.Subscribe(topics)
		defer sub.Close()
		wake = sub.Wake
		take = sub.Take
	} else {
		incoming = make(chan json.RawMessage, 1)
		upstream.SetReadLimit(64 << 10)
		upstream.SetReadDeadline(time.Now().Add(45 * time.Second))
		upstream.SetPongHandler(func(string) error { return upstream.SetReadDeadline(time.Now().Add(45 * time.Second)) })
		go func() {
			defer close(incoming)
			for {
				_, raw, e := upstream.ReadMessage()
				if e != nil {
					return
				}
				select {
				case incoming <- raw:
				case <-done:
					return
				}
			}
		}()
	}
	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case <-wake:
			if !s.realtimeAlive(r, p) {
				write(Response{Code: "UNAUTHENTICATED", Message: "会话或授权已失效", NodeID: s.NodeID, RequestID: r.Context().Value(requestIDKey).(string)})
				return
			}
			if err = write(Response{Code: "OK", Message: "状态已更新", Data: map[string]any{"topics": take()}, RequestID: r.Context().Value(requestIDKey).(string), NodeID: node}); err != nil {
				return
			}
		case raw, open := <-incoming:
			if !open {
				return
			}
			if !s.realtimeAlive(r, p) {
				return
			}
			if !validRemoteEnvelope(raw, node, 200) {
				return
			}
			var frame struct {
				Data struct {
					Topics []string `json:"topics"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &frame) != nil {
				return
			}
			for _, topic := range frame.Data.Topics {
				if !slices.Contains(topics, topic) {
					return
				}
			}
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err = conn.WriteMessage(websocket.TextMessage, raw); err != nil {
				return
			}
		case <-heartbeat.C:
			if !s.realtimeAlive(r, p) {
				write(Response{Code: "UNAUTHENTICATED", Message: "会话或授权已失效", NodeID: s.NodeID, RequestID: r.Context().Value(requestIDKey).(string)})
				return
			}
			if upstream != nil {
				if err = s.Nodes.RealtimeAlive(r.Context(), p, connection, node); err != nil {
					return
				}
				if err = upstream.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			}
			if err = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		}
	}
}
func (s *Server) realtimeAlive(r *http.Request, p auth.Principal) bool {
	current, err := s.Auth.Authenticate(r)
	if err != nil || current.ID != p.ID || current.Machine != p.Machine || current.Require(p.Scopes...) != nil {
		return false
	}
	if !current.Machine {
		alive, e := s.Auth.SessionAlive(r.Context())
		return e == nil && alive
	}
	return true
}
