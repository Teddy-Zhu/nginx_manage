package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

type realtimeFilter struct {
	Connection string   `json:"connection"`
	Topics     []string `json:"topics"`
}
type realtimeRequest struct {
	Type          string           `json:"type"`
	Revision      uint64           `json:"revision"`
	Subscriptions []realtimeFilter `json:"subscriptions"`
}
type realtimeData struct {
	Connection string   `json:"connection"`
	Topics     []string `json:"topics"`
	Revision   uint64   `json:"revision"`
}
type realtimeChannel struct {
	filter realtimeFilter
	cancel context.CancelFunc
	failed bool
}
type realtimeUpdate struct {
	channel *realtimeChannel
	node    string
	topics  []string
	error   bool
}

// One browser socket owns all of its local and remote subscriptions. Only this
// loop writes frames or changes channels; workers own their source connections.
func (s *Server) realtimeBrowser(r *http.Request, p auth.Principal, conn *websocket.Conn) {
	ctx, cancel := context.WithCancel(r.Context())
	var workers sync.WaitGroup
	channels := map[string]*realtimeChannel{}
	defer func() {
		cancel()
		for _, channel := range channels {
			channel.cancel()
		}
		workers.Wait()
	}()
	conn.SetReadLimit(16 << 10)
	commands := make(chan realtimeRequest, 1)
	go func() {
		defer cancel()
		for {
			var command realtimeRequest
			if err := conn.ReadJSON(&command); err != nil {
				return
			}
			select {
			case commands <- command:
			case <-ctx.Done():
				return
			}
		}
	}()
	updates := make(chan realtimeUpdate, 16)
	var revision uint64
	write := func(code, message, node string, data any) error {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(Response{Code: code, Message: message, Data: data, NodeID: node, RequestID: r.Context().Value(requestIDKey).(string)})
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case command := <-commands:
			if !s.realtimeAlive(r, p) {
				write("UNAUTHENTICATED", "会话或授权已失效", s.NodeID, nil)
				return
			}
			if err := s.validateRealtimeRequest(p, command, revision); err != nil {
				write("INVALID_SUBSCRIPTION", "实时订阅无效或权限不足", s.NodeID, nil)
				return
			}
			revision = command.Revision
			desired := map[string]realtimeFilter{}
			for _, filter := range command.Subscriptions {
				slices.Sort(filter.Topics)
				desired[filter.Connection] = filter
			}
			for key, channel := range channels {
				filter, exists := desired[key]
				if !exists || channel.failed || !slices.Equal(filter.Topics, channel.filter.Topics) {
					channel.cancel()
					delete(channels, key)
				}
			}
			for key, filter := range desired {
				if channels[key] != nil {
					continue
				}
				channelCtx, stop := context.WithCancel(ctx)
				channel := &realtimeChannel{filter: filter, cancel: stop}
				channels[key] = channel
				workers.Add(1)
				go func() { defer workers.Done(); s.realtimeChannel(channelCtx, r, p, channel, updates) }()
			}
		case update := <-updates:
			channel := update.channel
			if channels[channel.filter.Connection] != channel {
				continue
			}
			if !s.realtimeAlive(r, p) {
				write("UNAUTHENTICATED", "会话或授权已失效", s.NodeID, nil)
				return
			}
			code, message := "OK", "状态已更新"
			if update.error {
				channel.failed = true
				code, message = "REMOTE_STREAM_INTERRUPTED", "服务器状态更新暂时中断，正在重新连接"
			}
			if err := write(code, message, update.node, realtimeData{Connection: channel.filter.Connection, Topics: update.topics, Revision: revision}); err != nil {
				return
			}
		case <-heartbeat.C:
			if !s.realtimeAlive(r, p) {
				write("UNAUTHENTICATED", "会话或授权已失效", s.NodeID, nil)
				return
			}
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		}
	}
}

func (s *Server) validateRealtimeRequest(p auth.Principal, in realtimeRequest, previous uint64) error {
	if in.Type != "subscribe" || in.Revision <= previous || in.Revision > 1<<53-1 || in.Subscriptions == nil || len(in.Subscriptions) > 16 {
		return fault.Invalid("实时订阅无效")
	}
	seen := map[string]bool{}
	for _, filter := range in.Subscriptions {
		if seen[filter.Connection] || filter.Connection != "" && len(filter.Connection) != 36 {
			return fault.Invalid("服务器订阅无效")
		}
		seen[filter.Connection] = true
		if err := realtimeTopics(p, filter.Topics, filter.Connection != ""); err != nil {
			return err
		}
		if filter.Connection != "" {
			if s.Nodes == nil {
				return auth.ErrForbidden
			}
			if err := p.Require("nodes.manage"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) realtimeChannel(ctx context.Context, r *http.Request, p auth.Principal, channel *realtimeChannel, out chan<- realtimeUpdate) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	send := func(node string, topics []string, failed bool) bool {
		select {
		case out <- realtimeUpdate{channel: channel, node: node, topics: topics, error: failed}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	if channel.filter.Connection == "" {
		sub := s.Realtime.Subscribe(channel.filter.Topics)
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sub.Wake:
				topics := sub.Take()
				if len(topics) > 0 && !send(s.NodeID, topics, false) {
					return
				}
			}
		}
	}
	upstream, node, err := s.Nodes.OpenRealtime(ctx, p, channel.filter.Connection, channel.filter.Topics)
	if err != nil {
		if ctx.Err() == nil {
			send(s.NodeID, []string{}, true)
		}
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stop()
	upstream.SetReadLimit(64 << 10)
	upstream.SetReadDeadline(time.Now().Add(45 * time.Second))
	upstream.SetPongHandler(func(string) error { return upstream.SetReadDeadline(time.Now().Add(45 * time.Second)) })
	incoming := make(chan []byte, 1)
	go func() {
		defer close(incoming)
		for {
			_, raw, e := upstream.ReadMessage()
			if e != nil {
				return
			}
			select {
			case incoming <- raw:
			case <-ctx.Done():
				return
			}
		}
	}()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case raw, open := <-incoming:
			if !open || !validRemoteEnvelope(raw, node, 200) {
				send(node, []string{}, true)
				return
			}
			var frame struct {
				Data struct {
					Topics []string `json:"topics"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &frame) != nil || len(frame.Data.Topics) == 0 {
				send(node, []string{}, true)
				return
			}
			for _, topic := range frame.Data.Topics {
				if !slices.Contains(channel.filter.Topics, topic) {
					send(node, []string{}, true)
					return
				}
			}
			if !send(node, frame.Data.Topics, false) {
				return
			}
		case <-heartbeat.C:
			if s.Nodes.RealtimeAlive(ctx, p, channel.filter.Connection, node) != nil || upstream.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
				send(node, []string{}, true)
				return
			}
		}
	}
}
