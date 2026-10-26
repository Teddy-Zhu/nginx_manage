package realtime

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestSubscriptionCoalescingAndCleanup(t *testing.T) {
	releaseCtx, release := context.WithCancel(context.Background())
	defer release()
	h := New(func(ctx context.Context, _ string) (string, error) {
		select {
		case <-releaseCtx.Done():
		case <-ctx.Done():
		}
		return "", errors.New("unavailable")
	})
	first := h.Subscribe([]string{"tasks", "monitoring"})
	second := h.Subscribe([]string{"notifications"})
	if !slices.Equal(first.Take(), []string{"monitoring", "tasks"}) {
		t.Fatal("missing initial synchronization")
	}
	h.Notify("tasks", "tasks", "notifications")
	if !slices.Equal(first.Take(), []string{"tasks"}) {
		t.Fatal("notifications were duplicated or leaked between subscriptions")
	}
	first.Close()
	second.Close()
	release()
	h.mu.Lock()
	count := len(h.clients)
	h.mu.Unlock()
	if count != 0 {
		t.Fatal("subscriptions retained after disconnect")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.Lock()
		running := h.running
		h.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("observer did not stop without subscribers")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
