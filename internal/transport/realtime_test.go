package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	contract "nginxpanel/api"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
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
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"tasks", "monitoring"}, Resources: []string{"/tasks", "/monitoring/latest", "/monitoring/history?kind=cpu&id=total&value=usage_percent&window=3600"}}, {Connection: remote, Topics: []string{"tasks"}, Resources: []string{"/tasks"}}}}); err != nil {
		t.Fatal(err)
	}
	var frame realtimeMessage
	seen := map[string]bool{}
	remoteFailed := false
	for len(seen) < 3 || !remoteFailed {
		frame = readRealtimeMessage(t, conn)
		if frame.Revision != 1 {
			t.Fatalf("invalid subscription revision: %+v", frame)
		}
		if frame.Connection == remote && frame.Code == "REMOTE_STREAM_INTERRUPTED" {
			remoteFailed = true
			continue
		}
		if frame.Connection != "" || frame.Code != "OK" {
			t.Fatalf("invalid local snapshot: %+v", frame)
		}
		switch frame.Resource {
		case "/tasks":
			var tasks []json.RawMessage
			if json.Unmarshal(frame.Data, &tasks) != nil {
				t.Fatalf("missing task data: %s", frame.Data)
			}
		case "/monitoring/latest":
			var latest monitoring.Latest
			if json.Unmarshal(frame.Data, &latest) != nil || latest.Sample == nil || *latest.Sample.Metrics[0].Values["usage_percent"] != 13.5 {
				t.Fatalf("missing metric values: %s", frame.Data)
			}
		case "/monitoring/history?kind=cpu&id=total&value=usage_percent&window=3600":
		default:
			t.Fatalf("unrequested resource: %s", frame.Resource)
		}
		seen[frame.Resource] = true
	}
	// Replace topics in the same socket and remove the failed remote source.
	if err = conn.WriteJSON(realtimeRequest{Type: "subscribe", Revision: 2, Subscriptions: []realtimeFilter{{Topics: []string{"backups"}, Resources: []string{"/backups"}}}}); err != nil {
		t.Fatal(err)
	}
	for {
		frame = readRealtimeMessage(t, conn)
		if frame.Revision < 2 {
			continue
		}
		if frame.Connection != "" || frame.Resource != "/backups" {
			t.Fatalf("old subscription leaked: %+v", frame)
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
		frame = readRealtimeMessage(t, conn)
		if frame.Revision == 4 {
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

func readRealtimeMessage(t *testing.T, conn *websocket.Conn) realtimeMessage {
	t.Helper()
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"code": true, "message": true, "data": true, "resource": true, "connection": true, "revision": true, "status": true, "reset": true}
	for field := range fields {
		if !allowed[field] {
			t.Fatalf("redundant envelope field %s: %s", field, raw)
		}
	}
	var frame realtimeMessage
	if err = json.Unmarshal(raw, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Code == "OK" && (frame.Status != 0 || frame.Message != "" || !json.Valid(frame.Data)) {
		t.Fatalf("invalid success payload: %s", raw)
	}
	if frame.Resource != "" && !validRealtimeValue(frame.realtimeValue) {
		t.Fatalf("invalid resource result: %s", raw)
	}
	return frame
}

func TestRealtimeResourcesOnlyPushChangedData(t *testing.T) {
	server := &Server{NodeID: secure.ID()}
	value := 1
	server.realtimeReader = server.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			server.fail(w, r, fault.New(404, "NOT_FOUND", "任务不存在"))
			return
		}
		server.ok(w, r, map[string]int{"value": value})
	}))
	state := server.realtimeResources(httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	resources := []string{"/tasks", "/tasks/missing"}
	first := state.Read(t.Context(), []string{"tasks"}, resources)
	if len(first) != 2 || first["/tasks"].Code != "OK" || first["/tasks"].Message != "" || first["/tasks"].Status != 0 || first["/tasks/missing"].Status != 404 {
		t.Fatalf("invalid initial snapshot: %+v", first)
	}
	// Request IDs change on every dispatch and must not trigger another push.
	if unchanged := state.Read(t.Context(), []string{"tasks"}, resources); len(unchanged) != 0 {
		t.Fatalf("unchanged resources repeated: %+v", unchanged)
	}
	value++
	changed := state.Read(t.Context(), []string{"tasks"}, resources)
	if len(changed) != 1 || !bytes.Equal(changed["/tasks"].Data, []byte(`{"value":2}`)) {
		t.Fatalf("changed resource missing: %+v", changed)
	}
	reset := server.realtimeResources(state.request).Read(t.Context(), []string{"tasks"}, resources)
	if len(reset) != 2 {
		t.Fatalf("new subscription did not receive complete snapshot: %+v", reset)
	}
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
	if err := server.validateRealtimeRequest(auth.Principal{Scopes: []string{"read"}}, realtimeRequest{Type: "subscribe", Revision: 1, Subscriptions: []realtimeFilter{{Topics: []string{"docker"}, Resources: []string{"/docker/containers"}}}}, 0); err == nil {
		t.Fatal("permission check bypassed")
	}
}

func TestRealtimeServiceLogsResource(t *testing.T) {
	resource := "/components/service-logs?app_id=fail2ban"
	if err := validateRealtimeResources([]string{"docker"}, []string{resource}); err != nil {
		t.Fatal(err)
	}
	if !contract.RealtimeRemoteAllowed(resource) {
		t.Fatal("service logs are unavailable on remote nodes")
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
	if _, err = db.ExecContext(t.Context(), "UPDATE tasks SET observed_revision='changed' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	updated, err := server.realtimeFingerprint(t.Context(), "tasks")
	if err != nil || updated == after {
		t.Fatalf("task progress at the same timestamp not observed: %v", err)
	}
	if _, err = db.ExecContext(t.Context(), "DELETE FROM tasks WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if deleted, err := server.realtimeFingerprint(t.Context(), "tasks"); err != nil || deleted == updated {
		t.Fatalf("task removal not observed: %v", err)
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
