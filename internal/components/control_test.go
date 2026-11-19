package components

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/containers"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"nginxpanel/internal/storage"
)

func TestInteractiveSoftwareActionsCannotCreateTasks(t *testing.T) {
	ctx := t.Context()
	db, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := Service{DB: db}
	p := auth.Principal{ID: "operator", Scopes: []string{"components.manage", "system.write", "security.write"}}
	autoStart, revision := true, int64(1)
	requests := []software.Request{
		{Action: "logs", AppID: "fail2ban"},
		{Action: "restart", AppID: "frps"},
		{Action: "container", Container: &containers.Control{ID: strings.Repeat("a", 64), Action: "stop"}},
		{Action: "fail2ban", Fail2ban: &fail2ban.ContainerRequest{Action: "ban", JailID: secure.ID(), Address: "192.0.2.1"}},
		{Action: "fail2ban", Fail2ban: &fail2ban.ContainerRequest{Action: "auto-start", AutoStart: &autoStart, Revision: &revision}},
	}
	for _, request := range requests {
		if err := request.Validate(); err != nil {
			t.Fatalf("%s test request is invalid: %v", request.Action, err)
		}
		input := CreateInput{Input: Input{Action: "software", Software: &request}}
		_, err := s.Create(ctx, p, secure.ID(), secure.ID(), input)
		var rejected *fault.Error
		if !errors.As(err, &rejected) || rejected.Status != http.StatusBadRequest {
			t.Fatalf("%s was not rejected at task creation: %v", request.Action, err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks").Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected no tasks, got %d: %v", count, err)
	}
}
