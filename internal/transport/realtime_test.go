package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type realtimeHostReader struct{}

func TestRealtimeFirewallResponseDeadline(t *testing.T) {
	capture := &realtimeCapture{header: http.Header{}}
	ctx, cancel, ok := (&Server{}).firewallControlContext(capture, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/runtime", nil))
	if !ok {
		t.Fatalf("firewall snapshot rejected: %s", capture.body.String())
	}
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("firewall request deadline missing")
	}
	if _, err := capture.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := http.NewResponseController(capture).SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Write([]byte("{}")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("snapshot write deadline not enforced: %v", err)
	}
}

func (realtimeHostReader) ReadHostMetrics(context.Context, int64) (monitoring.Sample, error) {
	value := 13.5
	return monitoring.Sample{At: time.Now().Unix(), Source: "host-agent", Metrics: []monitoring.Metric{{Kind: "cpu", ID: "total", Values: map[string]*float64{"usage_percent": &value}}}, Services: []monitoring.ServiceState{}, Warnings: []string{}}, nil
}

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
	if err = modules.Init(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err = monitoring.Ensure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "UPDATE module_settings SET enabled=1 WHERE id='monitoring'"); err != nil {
		t.Fatal(err)
	}
	metrics := &monitoring.Service{DB: db, Agent: realtimeHostReader{}}
	sampleCtx, cancelSample := context.WithCancel(t.Context())
	sampleDone := make(chan error, 1)
	go func() { sampleDone <- metrics.Run(sampleCtx) }()
	defer func() {
		cancelSample()
		if err := <-sampleDone; err != nil {
			t.Error(err)
		}
	}()
	sampleReady := time.Now().Add(time.Second)
	for {
		latest, e := metrics.Latest(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		if latest.Sample != nil {
			break
		}
		if time.Now().After(sampleReady) {
			t.Fatal("initial sample missing")
		}
		time.Sleep(time.Millisecond)
	}
	server := &Server{Monitoring: metrics, DB: db, Auth: authentication, NodeID: secure.ID(), Dev: true, Nodes: &nodes.Service{DB: db}}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	target := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/api/v1/events"
	headers := http.Header{"Origin": {httpServer.URL}, "Cookie": {authentication.Sessions.Cookie.Name + "=" + token}}
	for _, test := range []struct {
		name, url string
		headers   http.Header
		status    int
	}{
		{"unauthenticated", target, http.Header{"Origin": {httpServer.URL}}, 401},
		{"foreign origin", target, http.Header{"Origin": {"http://example.invalid"}, "Cookie": headers.Values("Cookie")}, 403},
		{"missing origin", target, http.Header{"Cookie": headers.Values("Cookie")}, 403},
		{"browser query subscription rejected", target + "?topics=unknown", headers, 400},
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
	remote := secure.ID()
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks", "monitoring"}, Resources: []string{"/tasks", "/monitoring/latest", "/monitoring/history?kind=cpu&id=total&value=usage_percent&points=3&window=3600"}}, {Connection: remote, Topics: []string{"tasks"}, Resources: []string{"/tasks"}}}}); err != nil {
		t.Fatal(err)
	}
	var frame Response
	localReady, remoteFailed := false, false
	for !localReady || !remoteFailed {
		if err = conn.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.NodeID != server.NodeID || frame.RequestID == "" {
			t.Fatalf("invalid identity: %+v", frame)
		}
		data := decodeRealtimeData(t, frame)
		if data.Revision != 1 {
			t.Fatalf("invalid subscription revision: %+v", data)
		}
		if data.Connection == remote && frame.Code == "REMOTE_STREAM_INTERRUPTED" {
			remoteFailed = true
		}
		if data.Connection == "" && frame.Code == "OK" && slices.Contains(data.Topics, "tasks") {
			value, exists := data.Values["/tasks"]
			var payload Response
			if !exists || value.Status != 200 || json.Unmarshal(value.Response, &payload) != nil || payload.Code != "OK" || payload.NodeID != server.NodeID {
				t.Fatalf("missing authorized task snapshot: %+v", data)
			}
			var metricFrame struct{ Data monitoring.Latest }
			latest := data.Values["/monitoring/latest"]
			if latest.Status != 200 || json.Unmarshal(latest.Response, &metricFrame) != nil || metricFrame.Data.Sample == nil || *metricFrame.Data.Sample.Metrics[0].Values["usage_percent"] != 13.5 {
				t.Fatalf("missing metric values: %s", latest.Response)
			}
			history := data.Values["/monitoring/history?kind=cpu&id=total&value=usage_percent&points=3&window=3600"]
			if history.Status != 200 {
				t.Fatalf("rolling history unavailable: %s", history.Response)
			}
			localReady = true
		}
	}
	// Replace topics in the same socket and remove the failed remote source.
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 2, Subscriptions: []realtimeFilter{{Topics: []string{"backups"}, Resources: []string{"/backups"}}}}); err != nil {
		t.Fatal(err)
	}
	for {
		if err = conn.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		data := decodeRealtimeData(t, frame)
		if data.Revision < 2 {
			continue
		}
		if data.Connection != "" || !slices.Equal(data.Topics, []string{"backups"}) {
			t.Fatalf("old subscription leaked: %+v", data)
		}
		break
	}
	if server.realtimeStreams.Load() != 1 {
		t.Fatal("subscription changes created another browser stream")
	}
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 3, Subscriptions: []realtimeFilter{}}); err != nil {
		t.Fatal(err)
	}
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 4, Subscriptions: []realtimeFilter{{Topics: []string{"tasks"}, Resources: []string{"/tasks"}}}}); err != nil {
		t.Fatal(err)
	}
	for {
		if err = conn.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if decodeRealtimeData(t, frame).Revision == 4 {
			break
		}
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

func decodeRealtimeData(t *testing.T, frame Response) realtimeData {
	t.Helper()
	raw, err := json.Marshal(frame.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data realtimeData
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRealtimeSubscriptionValidation(t *testing.T) {
	server := &Server{Nodes: &nodes.Service{}}
	p := auth.Principal{Scopes: auth.AllScopes}
	for _, test := range []struct {
		name    string
		request realtimeRequest
		valid   bool
	}{
		{"empty releases all", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{}}, true},
		{"local DNS", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"dns"}, Resources: []string{"/host/dns"}}}}, true},
		{"missing resource", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks"}}}}, false},
		{"wrong resource topic", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks"}, Resources: []string{"/monitoring/latest"}}}}, false},
		{"unlisted resource", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks"}, Resources: []string{"/me"}}}}, false},
		{"download is not a snapshot", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"backups"}, Resources: []string{"/backups/x/download"}}}}, false},
		{"firewall mutations rejected", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"firewall"}, Resources: []string{"/firewall/plan?input=%7B%22action%22:%22apply%22,%22version%22:1%7D"}}}}, false},
		{"unknown topic", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"unknown"}}}}, false},
		{"duplicate source", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks"}, Resources: []string{"/tasks"}}, {Topics: []string{"version"}, Resources: []string{"/system/version"}}}}, false},
		{"replayed revision", realtimeRequest{Type: "subscribe", Revision: 0, Subscriptions: []realtimeFilter{}}, false},
		{"remote local-only topic", realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Connection: secure.ID(), Topics: []string{"firewall"}, Resources: []string{"/firewall/runtime"}}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := server.validateRealtimeRequest(p, test.request, 0); (err == nil) != test.valid {
				t.Fatalf("unexpected validation: %v", err)
			}
		})
	}
	if err := server.validateRealtimeRequest(auth.Principal{Scopes: []string{"read"}}, realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"maintenance"}, Resources: []string{"/maintenance"}}}}, 0); err == nil {
		t.Fatal("permission check bypassed")
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
	server.HostDNS = &hostdns.Service{DB: db}
	if _, err = db.ExecContext(t.Context(), "INSERT INTO module_settings(id,enabled) VALUES('host-dns',0)"); err != nil {
		t.Fatal(err)
	}
	before, err = server.realtimeFingerprint(t.Context(), "dns")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "UPDATE module_settings SET enabled=NOT enabled WHERE id='host-dns'"); err != nil {
		t.Fatal(err)
	}
	after, err = server.realtimeFingerprint(t.Context(), "dns")
	if err != nil || before == after {
		t.Fatalf("DNS management change not observed: %v", err)
	}
}
