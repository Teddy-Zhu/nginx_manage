package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/app"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

type apiEnvelope struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	NodeID    string          `json:"node_id"`
}

type apiNode struct {
	client             *http.Client
	base, csrf, nodeID string
	bootstrap          string
}

func startAPINode(t *testing.T) *apiNode {
	t.Helper()
	dir := t.TempDir()
	bootstrap, err := app.Init(t.Context(), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	// Reserve a loopback address without exposing a port outside the test container.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	o := app.Defaults(dir, true)
	o.Listen, o.WebDir, o.Version = address, t.TempDir(), "0.1.0"
	ctx, cancel := context.WithCancel(context.Background())
	agentDone := make(chan error, 1)
	readOnlyAgent := &agent.Server{
		Socket: o.Socket, AllowedUID: uint32(os.Geteuid()), Policy: o.Policy,
		Journal: &agent.Journal{Dir: filepath.Join(dir, "agent", "operations")},
		Dev:     true, DataDir: dir, MaintenanceScope: "unconfirmed", MetricsScope: "unconfirmed",
		DNSOwner: "unconfirmed", DNSScope: "unconfirmed", FirewallScope: "unconfirmed",
		FirewallOwner: "unconfirmed", FirewallSSH: "unconfirmed", ComponentScope: "unconfirmed",
	}
	go func() { agentDone <- readOnlyAgent.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-agentDone:
			if err != nil {
				t.Errorf("read-only Agent shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("read-only Agent shutdown timed out")
		}
	})
	agentClient := agent.NewClient(o.Socket)
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := agentClient.MaintenanceStatus(t.Context())
		if err == nil && status.Phase == "open" && !status.Available {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read-only Agent did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, o) }()
	jar, err := cookiejar.New(nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n := &apiNode{client: &http.Client{Jar: jar, Timeout: 10 * time.Second}, base: "http://" + address + "/api/v1", bootstrap: strings.TrimSpace(string(token))}
	t.Cleanup(func() {
		cancel()
		n.client.CloseIdleConnections()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("API shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("API shutdown timed out")
		}
	})
	deadline = time.Now().Add(10 * time.Second)
	for {
		res, err := n.client.Get(n.base + "/system/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("API did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return n
}

func (n *apiNode) request(t *testing.T, method, path string, body any, headers map[string]string, status int, code string) apiEnvelope {
	t.Helper()
	var data []byte
	var err error
	if raw, ok := body.([]byte); ok {
		data = raw
	} else if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, n.base+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", n.csrf)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := n.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, migration.MaxRequestBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(b, &envelope); err != nil {
		t.Fatalf("%s %s: non-JSON response (%d): %v", method, path, res.StatusCode, err)
	}
	if res.StatusCode != status || envelope.Code != code {
		t.Fatalf("%s %s: got %d/%s (%s), want %d/%s", method, path, res.StatusCode, envelope.Code, envelope.Message, status, code)
	}
	if envelope.Message == "" || envelope.Data == nil || envelope.RequestID == "" || envelope.NodeID == "" || envelope.RequestID != res.Header.Get("X-Request-ID") || envelope.NodeID != res.Header.Get("X-Node-ID") {
		t.Fatal("response envelope or identity headers are incomplete")
	}
	if n.nodeID != "" && n.nodeID != envelope.NodeID {
		t.Fatal("node identity changed")
	}
	n.nodeID = envelope.NodeID
	var csrf struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(envelope.Data, &csrf) == nil && csrf.CSRF != "" {
		n.csrf = csrf.CSRF
	}
	return envelope
}

func readAPIData[T any](t *testing.T, e apiEnvelope) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(e.Data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (n *apiNode) initialize(t *testing.T) {
	t.Helper()
	n.request(t, "GET", "/me", nil, nil, 200, "OK")
	credentials := map[string]string{"username": "admin", "password": "integration-only-password-2026", "token": n.bootstrap}
	n.request(t, "POST", "/bootstrap", credentials, nil, 201, "OK")
	delete(credentials, "token")
	n.request(t, "POST", "/session", credentials, nil, 200, "OK")
}

func TestAPIAuthenticationAndConfigurationMigration(t *testing.T) {
	source, target := startAPINode(t), startAPINode(t)
	source.request(t, "GET", "/nginx/config-tree", nil, nil, 401, "UNAUTHENTICATED")
	source.request(t, "GET", "/missing", nil, nil, 404, "NOT_FOUND")
	source.request(t, "GET", "/nodes/connections/"+secure.ID()+"/nginx/config-tree", nil, nil, 401, "UNAUTHENTICATED")
	source.request(t, "POST", "/bootstrap", map[string]string{}, nil, 403, "CSRF_REJECTED")
	source.initialize(t)
	target.initialize(t)
	if source.nodeID == target.nodeID {
		t.Fatal("independent installations reused a node identity")
	}
	source.request(t, "POST", "/migrations/export", map[string]string{"mode": "portable"}, map[string]string{"Origin": "https://untrusted.invalid"}, 403, "ORIGIN_REJECTED")
	source.request(t, "POST", "/session", []byte(`{"username":"admin","unexpected":true}`), nil, 400, "VALIDATION_FAILED")
	source.request(t, "GET", "/firewall/operations/not-a-uuid", nil, nil, 400, "VALIDATION_FAILED")
	site := nginxconfig.CreateRequest{Kind: "http", Listen: []string{"8088"}, Domains: []string{"migration.example.test"}, Upstream: "http://127.0.0.1:9000"}
	saved := readAPIData[nginxconfig.SaveResult](t, source.request(t, "POST", "/nginx/resources", site, map[string]string{"Idempotency-Key": "source-save"}, 201, "OK"))
	if saved.Tree.RevisionID == "" || saved.Tree.Version != 1 || saved.TaskID != "" {
		t.Fatal("save did not create an unapplied revision")
	}
	pkg := readAPIData[migration.Package](t, source.request(t, "POST", "/migrations/export", migration.ExportInput{Mode: "portable"}, nil, 200, "OK"))
	if secure.Hash(pkg.Content) != pkg.SHA256 || pkg.Manifest.SourceNode != source.nodeID {
		t.Fatal("export content or source identity does not match manifest")
	}
	input := migration.ImportInput{Content: pkg.Content, Mappings: map[string]string{}}
	plan := readAPIData[migration.Plan](t, target.request(t, "POST", "/migrations/plan", input, nil, 200, "OK"))
	if plan.SourceNode != source.nodeID || plan.CanApply || plan.CanSave {
		t.Fatal("target without managed Nginx incorrectly admitted runtime migration")
	}
	missingRuntime := false
	for _, step := range plan.Steps {
		missingRuntime = missingRuntime || step.State == "unavailable"
	}
	if !missingRuntime {
		t.Fatal("migration preflight did not identify unavailable dependencies")
	}
	// Draft import must remain available without pretending that Nginx was installed or started.
	executePath := "/migrations/" + plan.ID + "/execute"
	target.request(t, "POST", executePath, migration.ExecuteInput{Mode: "save"}, map[string]string{"Idempotency-Key": "blocked-import"}, 409, "MIGRATION_BLOCKED")
	execute := migration.ExecuteInput{Mode: "draft"}
	headers := map[string]string{"Idempotency-Key": "target-import"}
	imported := readAPIData[migration.Plan](t, target.request(t, "POST", executePath, execute, headers, 200, "OK"))
	replay := readAPIData[migration.Plan](t, target.request(t, "POST", executePath, execute, headers, 200, "OK"))
	if imported.State != "draft" || imported.RevisionID == "" || imported.TaskID != "" || imported.RevisionID != replay.RevisionID {
		t.Fatal("draft import or idempotent replay is inconsistent")
	}
	tree := readAPIData[nginxconfig.Tree](t, target.request(t, "GET", "/nginx/revisions/"+imported.RevisionID, nil, nil, 200, "OK"))
	found := false
	for _, file := range tree.Files {
		found = found || strings.Contains(file.Content, "migration.example.test")
	}
	if !found {
		t.Fatal("import lost the source site configuration")
	}
	if len(tree.Resources) != 1 || tree.Resources[0].Metadata.Enabled {
		t.Fatal("portable import did not preserve the site in a disabled state")
	}
	current := readAPIData[nginxconfig.Tree](t, target.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
	if current.RevisionID != "" || current.Version != 0 {
		t.Fatal("draft import changed the target desired configuration")
	}
	tampered := append([]byte(nil), pkg.Content...)
	if !bytes.Contains(tampered, []byte("migration.example.test")) {
		t.Fatal("portable export omitted the source site")
	}
	tampered = bytes.Replace(tampered, []byte("migration.example.test"), []byte("malicious.example.test"), 1)
	input.Content = tampered
	target.request(t, "POST", "/migrations/plan", input, nil, 400, "VALIDATION_FAILED")
	passphrase := "migration-encryption-only-test-2026"
	encrypted := readAPIData[migration.Package](t, source.request(t, "POST", "/migrations/export", migration.ExportInput{Mode: "encrypted", Passphrase: passphrase}, nil, 200, "OK"))
	if bytes.Contains(encrypted.Content, []byte("migration.example.test")) {
		t.Fatal("encrypted package exposed source configuration")
	}
	input.Content, input.Passphrase = encrypted.Content, "wrong-migration-passphrase"
	target.request(t, "POST", "/migrations/plan", input, nil, 400, "VALIDATION_FAILED")
	input.Passphrase = passphrase
	readAPIData[migration.Plan](t, target.request(t, "POST", "/migrations/plan", input, nil, 200, "OK"))
}
