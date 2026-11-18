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
	Resources  []string `json:"resources"`
	Refresh    bool     `json:"refresh,omitempty"`
}
type realtimeRequest struct {
	Type          string           `json:"type"`
	Revision      uint64           `json:"revision"`
	Refresh       bool             `json:"refresh,omitempty"`
	Subscriptions []realtimeFilter `json:"subscriptions"`
}
type realtimeChannel struct {
	filter realtimeFilter
	cancel context.CancelFunc
}
type realtimeUpdate struct {
	channel *realtimeChannel
	values  map[string]realtimeValue
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
	conn.SetReadLimit(64 << 10)
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
	write := func(message realtimeMessage) error {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(message)
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case command := <-commands:
			if !s.realtimeAlive(r, p) {
				write(realtimeMessage{realtimeValue: realtimeValue{Code: "UNAUTHENTICATED", Message: "会话或授权已失效"}})
				return
			}
			if err := s.validateRealtimeRequest(p, command, revision); err != nil {
				write(realtimeMessage{realtimeValue: realtimeValue{Code: "INVALID_SUBSCRIPTION", Message: "实时订阅无效或权限不足"}})
				return
			}
			revision = command.Revision
			desired := map[string]realtimeFilter{}
			for _, filter := range command.Subscriptions {
				slices.Sort(filter.Topics)
				slices.Sort(filter.Resources)
				desired[filter.Connection] = filter
			}
			for key, channel := range channels {
				filter, exists := desired[key]
				if !exists || command.Refresh || filter.Refresh || !slices.Equal(filter.Topics, channel.filter.Topics) || !slices.Equal(filter.Resources, channel.filter.Resources) {
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
				write(realtimeMessage{realtimeValue: realtimeValue{Code: "UNAUTHENTICATED", Message: "会话或授权已失效"}})
				return
			}
			if update.error {
				if err := write(realtimeMessage{realtimeValue: realtimeValue{Code: "REMOTE_STREAM_INTERRUPTED", Message: "服务器状态更新暂时中断，正在重新连接"}, Connection: channel.filter.Connection, Revision: revision}); err != nil {
					return
				}
				continue
			}
			for _, resource := range channel.filter.Resources {
				value, exists := update.values[resource]
				if !exists {
					continue
				}
				if err := write(realtimeMessage{realtimeValue: value, Resource: resource, Connection: channel.filter.Connection, Revision: revision}); err != nil {
					return
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

func (s *Server) validateRealtimeRequest(p auth.Principal, in realtimeRequest, previous uint64) error {
	if in.Type != "subscribe" || in.Revision <= previous || in.Revision > 1<<53-1 || in.Subscriptions == nil || len(in.Subscriptions) > 16 {
		return fault.Invalid("实时订阅无效")
	}
	seen := map[string]bool{}
	total := 0
	for _, filter := range in.Subscriptions {
		if seen[filter.Connection] || filter.Connection != "" && len(filter.Connection) != 36 {
			return fault.Invalid("服务器订阅无效")
		}
		seen[filter.Connection] = true
		if err := realtimeTopics(p, filter.Topics, filter.Connection != ""); err != nil {
			return err
		}
		total += len(filter.Resources)
		if total > 128 {
			return fault.Invalid("实时资源数量超出限制")
		}
		if err := validateRealtimeResources(filter.Topics, filter.Resources); err != nil {
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
	send := func(values map[string]realtimeValue, failed bool) bool {
		select {
		case out <- realtimeUpdate{channel: channel, values: values, error: failed}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	if channel.filter.Connection == "" {
		state := s.realtimeResources(r)
		defer state.Close()
		sub := s.Realtime.Subscribe(channel.filter.Topics)
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sub.Wake:
				topics := sub.Take()
				if len(topics) > 0 && !send(state.Read(ctx, topics, channel.filter.Resources), false) {
					return
				}
			}
		}
	}
	upstream, node, err := s.Nodes.OpenRealtime(ctx, p, channel.filter.Connection, channel.filter.Topics, channel.filter.Resources)
	if err != nil {
		if ctx.Err() == nil {
			send(nil, true)
		}
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stop()
	upstream.SetReadLimit(realtimeFrameLimit)
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
			var frame realtimeMessage
			if !open || json.Unmarshal(raw, &frame) != nil || !slices.Contains(channel.filter.Resources, frame.Resource) || frame.Connection != "" || frame.Revision != 0 || !validRealtimeValue(frame.realtimeValue) {
				send(nil, true)
				return
			}
			if !send(map[string]realtimeValue{frame.Resource: frame.realtimeValue}, false) {
				return
			}
		case <-heartbeat.C:
			if s.Nodes.RealtimeAlive(ctx, p, channel.filter.Connection, node) != nil || upstream.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
				send(nil, true)
				return
			}
		}
	}
}
