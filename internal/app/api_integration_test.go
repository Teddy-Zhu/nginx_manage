package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"nginxpanel/internal/firewall"
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
	dataDir            string
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
	n := &apiNode{client: &http.Client{Jar: jar, Timeout: 10 * time.Second}, base: "http://" + address + "/api/v1", bootstrap: strings.TrimSpace(string(token)), dataDir: dir}
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

func TestAPIStreamUpstreamGroupInput(t *testing.T) {
	n := startAPINode(t)
	n.initialize(t)
	direct := nginxconfig.CreateRequest{Kind: "stream", Listen: []string{"18080"}}
	n.request(t, "POST", "/nginx/resources", direct, map[string]string{"Idempotency-Key": "empty-direct"}, 400, "VALIDATION_FAILED")
	group := direct
	group.UpstreamServers = []string{"127.0.0.1:9000 weight=2", "[::1]:9001 backup"}
	httpGroup := group
	httpGroup.Kind, httpGroup.Domains = "http", []string{"group.example.test"}
	n.request(t, "POST", "/nginx/resources", httpGroup, map[string]string{"Idempotency-Key": "empty-http-target"}, 400, "VALIDATION_FAILED")
	saved := readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", "/nginx/resources", group, map[string]string{"Idempotency-Key": "stream-group"}, 201, "OK"))
	if len(saved.Tree.Resources) != 1 {
		t.Fatal("stream group did not create exactly one proxy")
	}
	resource := saved.Tree.Resources[0]
	members, upstream := resource.Fields["upstream_servers"], resource.Fields["upstream"]
	if resource.Kind != "stream" || len(members.Values) != 2 || !members.Editable || len(upstream.Values) != 1 || !strings.HasPrefix(upstream.Values[0], "nginxpanel_up_") {
		t.Fatal("stream group did not retain editable members and use its generated upstream")
	}
	containsGroup := func(files []nginxconfig.File, name string) bool {
		for _, file := range files {
			if strings.Contains(file.Content, "upstream "+name+" {") {
				return true
			}
		}
		return false
	}
	for _, kind := range []string{"stream", "http"} {
		if kind == "http" {
			httpGroup.BaseVersion, httpGroup.Upstream = saved.Tree.Version, "http://127.0.0.1:9000"
			saved = readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", "/nginx/resources", httpGroup, map[string]string{"Idempotency-Key": "http-group"}, 201, "OK"))
		}
		owner := saved.Tree.Resources[0]
		groupName := strings.TrimPrefix(owner.Fields["upstream"].Values[0], "http://")
		alias := nginxconfig.CreateRequest{BaseVersion: saved.Tree.Version, Kind: kind, Listen: []string{"18081"}, Upstream: groupName}
		if kind == "http" {
			alias.Upstream, alias.Domains = "http://"+groupName, []string{"alias.example.test"}
		}
		saved = readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", "/nginx/resources", alias, map[string]string{"Idempotency-Key": kind + "-shared"}, 201, "OK"))
		aliasID := ""
		for _, item := range saved.Tree.Resources {
			if item.ID != owner.ID {
				aliasID = item.ID
			}
		}
		saved = readAPIData[nginxconfig.SaveResult](t, n.request(t, "DELETE", "/nginx/resources/"+owner.ID, nginxconfig.ResourceActionRequest{BaseVersion: saved.Tree.Version}, map[string]string{"Idempotency-Key": kind + "-delete-owner"}, 200, "OK"))
		if len(saved.Tree.Resources) != 1 || !containsGroup(saved.Tree.Files, groupName) {
			t.Fatal("deleting one proxy removed a shared upstream group")
		}
		saved = readAPIData[nginxconfig.SaveResult](t, n.request(t, "DELETE", "/nginx/resources/"+aliasID, nginxconfig.ResourceActionRequest{BaseVersion: saved.Tree.Version}, map[string]string{"Idempotency-Key": kind + "-delete-last"}, 200, "OK"))
		if len(saved.Tree.Resources) != 0 || containsGroup(saved.Tree.Files, groupName) {
			t.Fatal("deleting the last proxy retained its generated upstream group")
		}
	}
}

func TestAPIWebsiteEditorCreateAndCopy(t *testing.T) {
	for _, kind := range []string{"http", "stream"} {
		t.Run(kind, func(t *testing.T) {
			n := startAPINode(t)
			n.initialize(t)
			before := readAPIData[nginxconfig.Tree](t, n.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
			template := readAPIData[nginxconfig.Resource](t, n.request(t, "GET", "/nginx/resources/template?kind="+kind, nil, nil, 200, "OK"))
			if template.Kind != kind || !template.Fields["connect_timeout"].Editable || !template.Fields["error_log"].Editable {
				t.Fatalf("incomplete editor template: %+v", template)
			}
			if kind == "http" && (!template.Fields["certificate"].Editable || !template.Fields["request_headers"].Editable || !template.Fields["access_list"].Editable) {
				t.Fatal("new websites must expose the same HTTPS, forwarding and access fields as editing")
			}
			unchanged := readAPIData[nginxconfig.Tree](t, n.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
			if unchanged.Version != before.Version || len(unchanged.Resources) != len(before.Resources) {
				t.Fatal("opening the creation form persisted a site")
			}
			input := nginxconfig.CreateRequest{
				BaseVersion: before.Version, Kind: kind, Listen: []string{"18081"}, Upstream: "127.0.0.1:8080",
				UpstreamServers: []string{"127.0.0.1:8080 weight=2", "127.0.0.1:8081 backup"},
				Metadata:        &nginxconfig.ResourceMetadata{Name: "Original", Notes: "created with full settings", Enabled: true},
				Changes:         map[string][]string{"connect_timeout": {"17s"}, "error_log": {strings.Replace(template.Fields["error_log"].Values[0], " warn", " error", 1)}},
			}
			if kind == "http" {
				input.Upstream, input.Domains = "http://service.example.test", []string{"first.example.test", "alias.example.test"}
				input.Changes["body_size"] = []string{"4m"}
				input.Changes["request_headers"] = []string{"Host $host", "Upgrade $http_upgrade", "Connection upgrade"}
			}
			saved := readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", "/nginx/resources", input, map[string]string{"Idempotency-Key": "editor-create"}, 201, "OK"))
			if len(saved.Tree.Resources) != 1 {
				t.Fatal("creation did not save exactly one site")
			}
			original := saved.Tree.Resources[0]
			if original.Fields["connect_timeout"].Values[0] != "17s" || !strings.Contains(original.Fields["error_log"].Values[0], original.ID+"/error.log error") {
				t.Fatal("creation lost edited settings or the site's own log path")
			}
			if kind == "http" && (original.Fields["body_size"].Values[0] != "4m" || len(original.Fields["request_headers"].Values) != 3) {
				t.Fatal("creation lost HTTP settings")
			}
			originalJSON, _ := json.Marshal(original.Fields)
			copyInput := nginxconfig.ResourceActionRequest{BaseVersion: saved.Tree.Version,
				Metadata: &nginxconfig.ResourceMetadata{Name: "Edited copy", Notes: "independent", Enabled: false},
				Changes:  map[string][]string{"connect_timeout": {"31s"}, "upstream_servers": {"127.0.0.1:9090"}, "error_log": {strings.Replace(original.Fields["error_log"].Values[0], " error", " crit", 1)}},
			}
			if kind == "http" {
				copyInput.Changes["domains"] = []string{"copy.example.test"}
				copyInput.Changes["upstream"] = []string{original.Fields["upstream"].Values[0] + "/copied/"}
			}
			path := "/nginx/resources/" + original.ID + "/copy"
			copied := readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", path, copyInput, map[string]string{"Idempotency-Key": "editor-copy"}, 201, "OK"))
			var clone nginxconfig.Resource
			for _, item := range copied.Tree.Resources {
				if item.ID != original.ID {
					clone = item
				} else {
					currentJSON, _ := json.Marshal(item.Fields)
					if !bytes.Equal(originalJSON, currentJSON) || item.Metadata != original.Metadata {
						t.Fatal("copying modified the source site")
					}
				}
			}
			if len(copied.Tree.Resources) != 2 || clone.Metadata.Name != "Edited copy" || clone.Metadata.Enabled || clone.Fields["connect_timeout"].Values[0] != "31s" || clone.Fields["upstream_servers"].Values[0] != "127.0.0.1:9090" {
				t.Fatalf("copy did not persist edited settings atomically: %+v", clone)
			}
			if clone.Fields["upstream"].Values[0] == original.Fields["upstream"].Values[0] || !strings.Contains(clone.Fields["error_log"].Values[0], clone.ID+"/error.log crit") {
				t.Fatal("copy shared the source's upstream or logs")
			}
			replayed := readAPIData[nginxconfig.SaveResult](t, n.request(t, "POST", path, copyInput, map[string]string{"Idempotency-Key": "editor-copy"}, 201, "OK"))
			if replayed.Tree.Version != copied.Tree.Version {
				t.Fatal("replaying copy created another site")
			}
			bad := nginxconfig.ResourceActionRequest{BaseVersion: copied.Tree.Version, Changes: map[string][]string{"listeners": {"not-a-port"}}}
			n.request(t, "POST", path, bad, map[string]string{"Idempotency-Key": "editor-invalid-copy"}, 400, "VALIDATION_FAILED")
			final := readAPIData[nginxconfig.Tree](t, n.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
			if final.Version != copied.Tree.Version || len(final.Resources) != 2 {
				t.Fatal("a failed copy left a partial site")
			}
		})
	}
}

func TestAPILargeFirewallPolicyPersistence(t *testing.T) {
	n := startAPINode(t)
	n.initialize(t)
	sources := make([]string, 20000)
	for i := range sources {
		sources[i] = fmt.Sprintf("2001:db8:%x::/48", i)
	}
	in := firewall.PolicyInput{Policy: firewall.Policy{Backend: "direct-nftables", Rules: []firewall.Rule{{
		ID: secure.ID(), Name: "Country address set", Enabled: true, Scope: "host_input", Family: "ipv6", Protocol: "tcp",
		Ports: []firewall.PortRange{{From: 8080, To: 8080}}, Sources: sources, Countries: []string{"CN"},
		GeoIPUpdatedAt: time.Now().Unix(), Action: "deny", Priority: 10,
	}}}}
	raw, err := json.Marshal(in.Policy)
	if err != nil || len(raw) <= 256<<10 {
		t.Fatal("fixture must exceed the former storage limit", err)
	}
	headers := map[string]string{"Idempotency-Key": "large-country-policy"}
	saved := readAPIData[firewall.PolicyView](t, n.request(t, "PUT", "/firewall/policy", in, headers, 200, "OK"))
	read := readAPIData[firewall.PolicyView](t, n.request(t, "GET", "/firewall/policy", nil, nil, 200, "OK"))
	replay := readAPIData[firewall.PolicyView](t, n.request(t, "PUT", "/firewall/policy", in, headers, 200, "OK"))
	if saved.Version != 1 || read.Version != saved.Version || replay.Version != saved.Version || read.Policy.Hash() != saved.Policy.Hash() || replay.Policy.Hash() != saved.Policy.Hash() || len(read.Policy.Rules[0].Sources) != len(sources) {
		t.Fatal("large country policy was not persisted or replayed intact")
	}
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
