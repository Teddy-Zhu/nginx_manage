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
	"dns": {"read"}, "fail2ban": {"read"}, "logs": {"read"}, "nginx": {"read"}, "nodes": {"read", "nodes.manage"},
	"software": {"read", "components.manage"},
}

// Fingerprints select changed resources; only authorized snapshots leave the server.
func (s *Server) realtimeFingerprint(ctx context.Context, topic string) (string, error) {
	var value any
	var err error
	switch topic {
	case "software":
		if s.Agent == nil {
			return "", errors.New("agent unavailable")
		}
		value, err = s.Agent.ReadComponents(ctx)
	case "nginx":
		if s.Agent == nil {
			return "", errors.New("agent unavailable")
		}
		value, err = s.Agent.NginxState(ctx)
	case "nodes":
		rows, e := s.DB.QueryContext(ctx, `SELECT 'node:'||id,state,json_array(version,updated_at,removed_at,last_error,expires_at>0 AND expires_at<=unixepoch()) FROM nodes UNION ALL SELECT 'pair:'||id,state,json_array(expires_at<=unixepoch()) FROM node_pairings UNION ALL SELECT 'job:'||id,state,json_array(stage,last_error,updated_at) FROM node_pairing_jobs ORDER BY 1`)
		if e != nil {
			return "", e
		}
		defer rows.Close()
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		for rows.Next() {
			var id, state, details string
			if e = rows.Scan(&id, &state, &details); e != nil {
				return "", e
			}
			if e = encoder.Encode([]string{id, state, details}); e != nil {
				return "", e
			}
		}
		return hex.EncodeToString(hash.Sum(nil)), rows.Err()
	case "logs":
		// Log cursors must advance independently of task state transitions.
		return time.Now().UTC().Format("20060102150405"), nil
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
	case "fail2ban":
		if s.Agent == nil {
			return "", errors.New("agent unavailable")
		}
		value, err = s.Agent.ReadFail2banContainer(ctx)
	case "dns":
		if s.HostDNS == nil {
			return "", errors.New("DNS unavailable")
		}
		var enabled bool
		if err = s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='host-dns'").Scan(&enabled); err != nil {
			return "", err
		}
		dns, e := s.HostDNS.Overview(ctx)
		value, err = []any{enabled, dns}, e
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
	// Machine streams feed the browser broker and cannot recursively forward.
	if p.Machine {
		topics := strings.Split(r.URL.Query().Get("topics"), ",")
		if r.URL.Query().Get("connection") != "" {
			s.fail(w, r, auth.ErrForbidden)
			return
		}
		if err := realtimeTopics(p, topics, r.Header.Get(remoteapi.HopHeader) != ""); err != nil {
			s.fail(w, r, err)
			return
		}
		var resources []string
		if len(r.URL.RawQuery) > 128<<10 || json.Unmarshal([]byte(r.URL.Query().Get("resources")), &resources) != nil {
			s.fail(w, r, fault.Invalid("实时资源无效"))
			return
		}
		if err := validateRealtimeResources(topics, resources); err != nil {
			s.fail(w, r, err)
			return
		}
	} else if r.URL.RawQuery != "" {
		s.fail(w, r, fault.Invalid("请在实时连接内提交订阅"))
		return
	}
	if s.realtimeStreams.Add(1) > 32 {
		s.realtimeStreams.Add(-1)
		s.fail(w, r, fault.New(429, "REALTIME_BUSY", "实时连接数量已达上限"))
		return
	}
	defer s.realtimeStreams.Add(-1)
	upgrader := websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024, HandshakeTimeout: 5 * time.Second, CheckOrigin: func(*http.Request) bool { return true }, Error: func(w http.ResponseWriter, r *http.Request, _ int, _ error) {
		s.fail(w, r, fault.Invalid("实时连接握手失败"))
	}}
	conn, err := upgrader.Upgrade(w, r, w.Header())
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(45 * time.Second)) })
	if p.Machine {
		s.realtimeSource(r, p, conn)
		return
	}
	s.realtimeBrowser(r, p, conn)
}

func realtimeTopics(p auth.Principal, topics []string, forwarded bool) error {
	if len(topics) == 0 || len(topics) > len(realtimeScopes) {
		return fault.Invalid("实时订阅无效")
	}
	seen := map[string]bool{}
	for _, topic := range topics {
		scopes, exists := realtimeScopes[topic]
		if !exists || seen[topic] {
			return fault.Invalid("实时订阅类型无效或重复")
		}
		seen[topic] = true
		if err := p.Require(scopes...); err != nil {
			return err
		}
		if forwarded && slices.Contains([]string{"firewall", "listener", "backups"}, topic) {
			return auth.ErrForbidden
		}
	}
	return nil
}

func (s *Server) realtimeSource(r *http.Request, p auth.Principal, conn *websocket.Conn) {
	conn.SetReadLimit(1024)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	var resources []string
	json.Unmarshal([]byte(r.URL.Query().Get("resources")), &resources)
	state := s.realtimeResources(r)
	defer state.Close()
	sub := s.Realtime.Subscribe(strings.Split(r.URL.Query().Get("topics"), ","))
	defer sub.Close()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	write := func(message realtimeMessage) error {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(message)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.Wake:
			if !s.realtimeAlive(r, p) {
				write(realtimeMessage{realtimeValue: realtimeValue{Code: "UNAUTHENTICATED", Message: "会话或授权已失效"}})
				return
			}
			topics := sub.Take()
			if len(topics) == 0 {
				continue
			}
			values := state.Read(ctx, topics, resources)
			for _, resource := range resources {
				if value, exists := values[resource]; exists {
					if err := write(realtimeMessage{realtimeValue: value, Resource: resource}); err != nil {
						return
					}
				}
			}
		case <-heartbeat.C:
			if !s.realtimeAlive(r, p) {
				write(realtimeMessage{realtimeValue: realtimeValue{Code: "UNAUTHENTICATED", Message: "会话或授权已失效"}})
				return
			}
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
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

// Successful state changes wake other sessions as well as the initiating page.
func (s *Server) realtimeMutation(r *http.Request) {
	if s.Realtime == nil || r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || strings.HasPrefix(r.URL.Path, "/api/v1/logs/") {
		return
	}
	for _, suffix := range []string{"/preview", "/plan", "/resolve", "/query", "/check", "/download"} {
		if strings.HasSuffix(r.URL.Path, suffix) {
			return
		}
	}
	topics := make([]string, 0, len(realtimeScopes))
	for topic := range realtimeScopes {
		topics = append(topics, topic)
	}
	s.Realtime.Notify(topics...)
}
