package components

import (
	"context"
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"nginxpanel/internal/storage"
)

type coreUpdateHost struct {
	Host
	candidate CoreUpdateCandidate
	beta      bool
}

func (h *coreUpdateHost) CheckCoreUpdate(_ context.Context, beta bool) (CoreUpdateCandidate, error) {
	h.beta = beta
	return h.candidate, nil
}

func TestCoreUpdateCheckQueuesOnlyConfirmedInstall(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	host := &coreUpdateHost{candidate: CoreUpdateCandidate{Release: Release{
		Version: "1.2.4-dev", Tag: "v1.2.4-dev", Channel: "beta", ExpiresAt: time.Now().Add(time.Hour).Unix(),
		PlanID: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), TrustSHA256: strings.Repeat("c", 64),
		Selected: []string{"panel-linux-amd64"}, Assets: []Asset{{ID: "panel-linux-amd64", Component: "panel"}},
	}}}
	s := Service{DB: db, Vault: vault, Agent: host, Version: "1.2.3"}
	p := auth.Principal{ID: "operator", Scopes: []string{"read", "components.manage", "system.write"}}
	result, err := s.CheckCoreUpdate(ctx, p, "beta")
	if err != nil || result.State != "available" || result.Version != host.candidate.Release.Version || len(result.Confirmation) == 0 || !host.beta {
		t.Fatalf("check = %+v, err = %v", result.CoreUpdateStatus, err)
	}
	if tasks, err := s.List(ctx, p); err != nil || len(tasks) != 0 {
		t.Fatalf("check wrote tasks: %v, err = %v", tasks, err)
	}
	in := CreateInput{Input: Input{Action: "software", Software: &software.Request{Action: "update-panel"}}}
	if _, err := s.Create(ctx, p, secure.ID(), secure.ID(), in); err == nil {
		t.Fatal("an unconfirmed check queued an install")
	}
	in.UpdateConfirmation = result.Confirmation
	other := p
	other.ID = "another-operator"
	if _, err := s.Create(ctx, other, secure.ID(), secure.ID(), in); err == nil {
		t.Fatal("another account reused an update confirmation")
	}
	key := secure.ID()
	task, err := s.Create(ctx, p, secure.ID(), key, in)
	if err != nil || task.State != "queued" || task.Action != "software" {
		t.Fatalf("install task = %+v, err = %v", task, err)
	}
	s.Version = result.Version
	if again, err := s.Create(ctx, p, secure.ID(), key, in); err != nil || again.ID != task.ID {
		t.Fatalf("install retry = %+v, err = %v", again, err)
	}
	current, err := s.CheckCoreUpdate(ctx, p, "beta")
	if err != nil || current.State != "current" || len(current.Confirmation) != 0 {
		t.Fatalf("current result = %+v, err = %v", current.CoreUpdateStatus, err)
	}
}

func TestCoreUpdateStatusUsesRunningVersion(t *testing.T) {
	task := Task{Result: &Operation{Release: &Release{
		Version: "1.2.4", Selected: []string{"panel-linux-amd64"},
		Assets: []Asset{{ID: "panel-linux-amd64", Component: "panel"}},
	}}}
	s := Service{}
	for _, test := range []struct {
		current, state string
	}{
		{"1.2.3", "available"},
		{"1.2.4", "current"},
		{"1.2.5", "older"},
		{"unknown", "unknown"},
	} {
		s.Version = test.current
		task = s.withCoreUpdate(task)
		if task.CoreUpdate == nil || task.CoreUpdate.CurrentVersion != test.current || task.CoreUpdate.State != test.state {
			t.Fatalf("current=%s: %+v", test.current, task.CoreUpdate)
		}
		if test.state == "unknown" && task.CoreUpdate.Message == "" {
			t.Fatal("invalid current version needs an explanation")
		}
	}
	for _, task := range []Task{
		{},
		{Result: &Operation{}},
		{Result: &Operation{Release: &Release{Version: "1.2.4", Selected: []string{"image-nginx"}}}},
		{Result: &Operation{Release: &Release{Version: "1.2.4", Selected: []string{"other"}, Assets: []Asset{{ID: "panel-linux-amd64", Component: "panel"}}}}},
	} {
		if got := s.withCoreUpdate(task); got.CoreUpdate != nil {
			t.Fatal("non-core results must not be labeled as core updates")
		}
	}
}
