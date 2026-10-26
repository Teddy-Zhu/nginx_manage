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
type Hub struct {
	mu      sync.Mutex
	observe Observer
	clients map[*Subscription]bool
	running bool
}
type Subscription struct {
	hub     *Hub
	topics  map[string]bool
	pending map[string]bool
	Wake    chan struct{}
}

func New(observe Observer) *Hub { return &Hub{observe: observe, clients: make(map[*Subscription]bool)} }
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
		h.running = true
		go h.run()
	}
	return s
}
func (s *Subscription) Close() { s.hub.mu.Lock(); delete(s.hub.clients, s); s.hub.mu.Unlock() }
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
func (h *Hub) run() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	fingerprints := map[string]string{}
	for {
		h.mu.Lock()
		if len(h.clients) == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
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
			}
		}
		changed := []string{}
		for topic := range topics {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			value, err := h.observe(ctx, topic)
			cancel()
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
		if len(changed) > 0 {
			h.Notify(changed...)
		}
		<-ticker.C
	}
}
