package components

import (
	"context"
	"testing"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type rejectedCheckHost struct {
	Host
	submissions int
}

func (h *rejectedCheckHost) ComponentOperation(context.Context, string) (Operation, error) {
	return Operation{}, fault.NotFound("组件操作记录不存在")
}

func (h *rejectedCheckHost) SubmitComponent(context.Context, Request) (Operation, error) {
	h.submissions++
	return Operation{}, fault.New(503, "COMPONENT_NOT_SUBMITTED", "缺少发行签名配置")
}

func TestCoreCheckKeepsPreflightRejectionAndAllowsRetry(t *testing.T) {
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
	host := &rejectedCheckHost{}
	s := Service{DB: db, Vault: vault, Agent: host}
	p := auth.Principal{ID: "operator", Scopes: []string{"components.manage", "system.write"}}
	input := CreateInput{Input: Input{Action: "check", Components: []string{"panel"}}}
	task, err := s.Create(ctx, p, secure.ID(), secure.ID(), input)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.next(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, p, task.ID)
	if err != nil || got.State != "failed" || got.Stage != "preflight_rejected" || got.Error != "缺少发行签名配置" || host.submissions != 1 {
		t.Fatalf("check result = %+v, submitted %d times, err = %v", got, host.submissions, err)
	}
	if _, err := s.Create(ctx, p, secure.ID(), secure.ID(), input); err != nil {
		t.Fatalf("rejected task blocked another check: %v", err)
	}
}
