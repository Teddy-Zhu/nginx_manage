package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type operationHost struct {
	status  RootStatus
	pending bool
	offline bool
	reads   chan struct{}
}

func (h *operationHost) MaintenanceStatus(context.Context) (RootStatus, error) {
	select {
	case h.reads <- struct{}{}:
	default:
	}
	if h.offline {
		return RootStatus{}, errors.New("agent offline")
	}
	return h.status, nil
}
func (h *operationHost) AcquireMaintenance(_ context.Context, in RootRequest) (RootStatus, error) {
	h.status.ID, h.status.Phase = in.OperationID, "held"
	return h.status, nil
}
func (h *operationHost) ReleaseMaintenance(_ context.Context, in RootRequest) (RootStatus, error) {
	if h.pending {
		return RootStatus{}, fault.Conflict("cleanup pending")
	}
	out := h.status
	out.ID, out.Phase = in.OperationID, "released"
	h.status.ID, h.status.Phase = "", "open"
	return out, nil
}
func operationService(t *testing.T) (*Service, *operationHost, auth.Principal) {
	t.Helper()
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	host := &operationHost{status: RootStatus{Available: true, Phase: "open", Epoch: secure.ID()}}
	s := &Service{DB: db, Vault: vault, Agent: host}
	if err = s.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s, host, auth.Principal{ID: "test:admin", Scopes: []string{"system.write", "components.manage", "auth.manage"}}
}
func TestNewMaintenanceWakesIdleReconciliation(t *testing.T) {
	s, host, p := operationService(t)
	host.reads = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	waitForRead := func() {
		t.Helper()
		select {
		case <-host.reads:
		case <-time.After(5 * time.Second):
			t.Fatal("maintenance reconciliation did not wake")
		}
	}
	waitForRead()
	if _, err := s.Start(ctx, p, secure.ID(), secure.ID(), StartInput{DrainSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	waitForRead()
}

func TestOperationTaskAutomaticallyReleases(t *testing.T) {
	for _, state := range []string{"succeeded", "failed", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			s, host, p := operationService(t)
			prepare, task := secure.ID(), secure.ID()
			insertTask := func(id, kind, state string) {
				t.Helper()
				_, err := s.DB.Exec("INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,?, 'host',?,'queued',?,1,1)", id, kind, state, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			insertTask(prepare, "component.prepare", "succeeded")
			if _, err := s.DB.Exec("INSERT INTO component_operations(task_id,principal,payload) VALUES(?,?,?)", prepare, p.ID, []byte("{}")); err != nil {
				t.Fatal(err)
			}
			err := s.Submit(t.Context(), p, secure.ID(), func(id string) (string, error) {
				insertTask(task, "component.install", "queued")
				_, err := s.DB.Exec("INSERT INTO nginx_installations(task_id,principal,maintenance_id,prepare_task_id,sequence,command,authorization_until,payload) VALUES(?,?,?,?,1,'install',?,?)", task, p.ID, id, prepare, time.Now().Unix()+600, []byte("{}"))
				return task, err
			})
			if err != nil {
				t.Fatal(err)
			}
			if s.View().Phase != "held" {
				t.Fatal("running task lost exclusive preparation")
			}
			if _, err = s.DB.Exec("UPDATE tasks SET state=? WHERE id=?", state, task); err != nil {
				t.Fatal(err)
			}
			if err = s.step(t.Context()); err != nil {
				t.Fatal(err)
			}
			if s.View().Phase != "open" || host.status.ID != "" {
				t.Fatal("terminal task left system locked")
			}
		})
	}
}
func TestRejectedOperationAllowsRetry(t *testing.T) {
	s, host, p := operationService(t)
	rejected := errors.New("invalid package")
	for range 2 {
		err := s.Submit(t.Context(), p, secure.ID(), func(string) (string, error) { return "", rejected })
		if !errors.Is(err, rejected) {
			t.Fatalf("rejection lost: %v", err)
		}
		if s.View().Phase != "open" || host.status.ID != "" {
			t.Fatal("rejected task blocked subsequent requests")
		}
	}
}
func TestTemporaryCleanupCanResumeWithoutUserManagedMode(t *testing.T) {
	s, host, p := operationService(t)
	var id string
	err := s.Temporary(t.Context(), p, secure.ID(), "", func(root RootStatus) error {
		id = root.ID
		host.pending = true
		return errors.New("interrupted cleanup")
	})
	if err == nil || s.View().Phase != "held" {
		t.Fatal("interrupted cleanup should retain its own guard")
	}
	if _, err = s.DB.Exec("UPDATE maintenance_sessions SET deadline=1 WHERE task_id=?", id); err != nil {
		t.Fatal(err)
	}
	if err = s.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s.View().Phase != "held" {
		t.Fatal("expired cleanup cannot resume")
	}
	err = s.Temporary(t.Context(), p, secure.ID(), id, func(root RootStatus) error {
		if root.ID != id {
			t.Fatal("retry replaced original cleanup guard")
		}
		host.pending = false
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.View().Phase != "open" || host.status.ID != "" {
		t.Fatal("cleanup did not release guard")
	}
	// A plain preview must release before the UI waits for confirmation.
	if err = s.Temporary(t.Context(), p, secure.ID(), "", func(RootStatus) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if s.View().Phase != "open" {
		t.Fatal("preview left system locked")
	}
}
func TestOfflineAgentDoesNotCreateGlobalReadOnlyMode(t *testing.T) {
	s, host, _ := operationService(t)
	host.offline = true
	if err := s.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	done, ok := s.Admit()
	if !ok {
		t.Fatal("ordinary configuration blocked without an operation")
	}
	done()
}
