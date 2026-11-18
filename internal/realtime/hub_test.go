package realtime

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSubscriptionCoalescingAndCleanup(t *testing.T) {
	started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
	h := New(func(ctx context.Context, _ string) (string, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case stopped <- struct{}{}:
		default:
		}
		return "", errors.New("unavailable")
	}, func(topic string) time.Duration {
		if topic == "nginx" {
			return 0
		}
		return 2 * time.Second
	})
	eventOnly := h.Subscribe([]string{"nginx"})
	defer eventOnly.Close()
	if h.pollers != 0 {
		t.Fatal("event-only subscription started periodic work")
	}
	first := h.Subscribe([]string{"tasks", "monitoring"})
	second := h.Subscribe([]string{"notifications"})
	defer first.Close()
	defer second.Close()
	if !slices.Equal(first.Take(), []string{"monitoring", "tasks"}) {
		t.Fatal("missing initial synchronization")
	}
	h.Notify("tasks", "tasks", "notifications")
	if !slices.Equal(first.Take(), []string{"tasks"}) {
		t.Fatal("notifications were duplicated or leaked between subscriptions")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("observer did not start")
	}
	first.Close()
	second.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("closing the last subscription did not cancel the active probe")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) != 1 || h.pollers != 0 {
		t.Fatal("periodic observer or its subscriptions remained active")
	}
}
