package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

func TestRealtimeOriginAuthorizationAndLogout(t *testing.T) {
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(t.Context(), "INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'admin','unused',1)"); err != nil {
		t.Fatal(err)
	}
	authentication := auth.New(db, true)
	ctx, err := authentication.Sessions.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	authentication.Sessions.Put(ctx, "user", "admin")
	authentication.Sessions.Put(ctx, "epoch", int64(1))
	token, _, err := authentication.Sessions.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{DB: db, Auth: authentication, NodeID: secure.ID(), Dev: true}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	target := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/api/v1/events?topics=tasks"
	headers := http.Header{"Origin": {httpServer.URL}, "Cookie": {authentication.Sessions.Cookie.Name + "=" + token}}
	for _, test := range []struct {
		name, url string
		headers   http.Header
		status    int
	}{
		{"unauthenticated", target, http.Header{"Origin": {httpServer.URL}}, 401},
		{"foreign origin", target, http.Header{"Origin": {"http://example.invalid"}, "Cookie": headers.Values("Cookie")}, 403},
		{"missing origin", target, http.Header{"Cookie": headers.Values("Cookie")}, 403},
		{"unknown subscription", target + ",unknown", headers, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, response, e := websocket.DefaultDialer.Dial(test.url, test.headers)
			if conn != nil {
				conn.Close()
				t.Fatal("unexpected upgrade")
			}
			if e == nil || response == nil {
				t.Fatal("missing handshake rejection")
			}
			defer response.Body.Close()
			var body Response
			if e = json.NewDecoder(response.Body).Decode(&body); e != nil {
				t.Fatal(e)
			}
			if response.StatusCode != test.status || body.Code == "OK" || body.NodeID != server.NodeID || body.RequestID == "" {
				t.Fatalf("invalid rejection: %d %+v", response.StatusCode, body)
			}
		})
	}
	conn, response, err := websocket.DefaultDialer.Dial(target, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if response.Header.Get("X-Node-ID") != server.NodeID {
		t.Fatal("missing handshake identity")
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var frame Response
	if err = conn.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame.Code != "OK" || frame.NodeID != server.NodeID || frame.RequestID == "" {
		t.Fatalf("invalid sync: %+v", frame)
	}
	if _, err = db.ExecContext(t.Context(), "DELETE FROM sessions"); err != nil {
		t.Fatal(err)
	}
	server.Realtime.Notify("tasks")
	for frame.Code != "UNAUTHENTICATED" {
		if err = conn.ReadJSON(&frame); err != nil {
			t.Fatalf("missing logout notification: %v", err)
		}
	}
	// Wait for the handler to return, then verify that the loaded session was
	// not re-committed by the ordinary HTTP session middleware.
	deadline := time.Now().Add(time.Second)
	for server.realtimeStreams.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if server.realtimeStreams.Load() != 0 {
		t.Fatal("disconnected stream was not released")
	}
	var count int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("socket closure resurrected a revoked session")
	}
}

func TestRealtimeFingerprintsCoverTaskAndBackupChanges(t *testing.T) {
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{DB: db}
	before, err := server.realtimeFingerprint(t.Context(), "tasks")
	if err != nil {
		t.Fatal(err)
	}
	id := secure.ID()
	if _, err = db.ExecContext(t.Context(), "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'backup.create','','queued','queued',?,1,1)", id, secure.ID()); err != nil {
		t.Fatal(err)
	}
	after, err := server.realtimeFingerprint(t.Context(), "tasks")
	if err != nil || before == after {
		t.Fatalf("task change not observed: %v", err)
	}
	before, err = server.realtimeFingerprint(t.Context(), "backups")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "UPDATE backup_policy SET version=version+1"); err != nil {
		t.Fatal(err)
	}
	after, err = server.realtimeFingerprint(t.Context(), "backups")
	if err != nil || before == after {
		t.Fatalf("backup policy change not observed: %v", err)
	}
}
