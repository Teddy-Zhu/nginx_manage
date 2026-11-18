// Package realtime coalesces resource changes for connected subscribers. One
// observer runs per process, regardless of the number of browser connections.
package realtime

import (
	"context"
	"sort"
	"sync"
	"time"
)

type Observer func(context.Context, string) (string, error)

const pollInterval = 2 * time.Second

type Hub struct {
	mu       sync.Mutex
	observe  Observer
	interval func(string) time.Duration
	clients  map[*Subscription]bool
	stop     context.CancelFunc
	running  bool
}
type Subscription struct {
	hub     *Hub
	topics  map[string]bool
	pending map[string]bool
	Wake    chan struct{}
}

func New(observe Observer, interval func(string) time.Duration) *Hub {
	return &Hub{observe: observe, interval: interval, clients: make(map[*Subscription]bool)}
}
func (h *Hub) Subscribe(topics []string) *Subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &Subscription{hub: h, topics: map[string]bool{}, pending: map[string]bool{}, Wake: make(chan struct{}, 1)}
	for _, topic := range topics {
		s.topics[topic] = true
		s.pending[topic] = true
	}
	h.clients[s] = true
	s.Wake <- struct{}{}
	if !h.running {
		ctx, stop := context.WithCancel(context.Background())
		h.running = true
		h.stop = stop
		go h.run(ctx)
	}
	return s
}
func (s *Subscription) Close() {
	h := s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, s)
	if len(h.clients) == 0 && h.running {
		h.stop()
		h.running = false
	}
}
func (s *Subscription) Take() []string {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	out := make([]string, 0, len(s.pending))
	for topic := range s.pending {
		out = append(out, topic)
	}
	clear(s.pending)
	sort.Strings(out)
	return out
}
func (h *Hub) Notify(topics ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.clients {
		for _, topic := range topics {
			if s.topics[topic] {
				s.pending[topic] = true
			}
		}
		if len(s.pending) > 0 {
			select {
			case s.Wake <- struct{}{}:
			default:
			}
		}
	}
}
func (h *Hub) run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	fingerprints := map[string]string{}
	next := map[string]time.Time{}
	tick := time.Now()
	for ctx.Err() == nil {
		h.mu.Lock()
		topics := map[string]bool{}
		for s := range h.clients {
			for topic := range s.topics {
				topics[topic] = true
			}
		}
		h.mu.Unlock()
		for topic := range fingerprints {
			if !topics[topic] {
				delete(fingerprints, topic)
				delete(next, topic)
			}
		}
		changed := []string{}
		for topic := range topics {
			interval := h.interval(topic)
			if interval <= 0 || (interval > pollInterval && tick.Before(next[topic])) || ctx.Err() != nil {
				continue
			}
			call, cancel := context.WithTimeout(ctx, 4*time.Second)
			value, err := h.observe(call, topic)
			cancel()
			next[topic] = tick.Add(interval)
			if err != nil {
				value = "unavailable"
			} else {
				value = "ok:" + value
			}
			if previous, ok := fingerprints[topic]; !ok || previous != value {
				fingerprints[topic] = value
				changed = append(changed, topic)
			}
		}
		if len(changed) > 0 && ctx.Err() == nil {
			h.Notify(changed...)
		}
		select {
		case <-ctx.Done():
			return
		case tick = <-ticker.C:
		}
	}
}
