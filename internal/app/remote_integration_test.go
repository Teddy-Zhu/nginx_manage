package app_test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/secure"
)

type apiCredential struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func (n *apiNode) credential(t *testing.T, scopes ...string) apiCredential {
	t.Helper()
	input := auth.CredentialInput{Name: "P5 integration", Scopes: scopes, AllowedSources: []string{"127.0.0.1/32"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	return readAPIData[apiCredential](t, n.request(t, "POST", "/credentials", input, nil, 201, "OK"))
}

// The normal development API runs behind an actual HTTPS reverse proxy, as
// supported by the deployment contract. Both remain inside the test container.
func tlsAPINode(t *testing.T, n *apiNode) (string, string, *atomic.Int64) {
	t.Helper()
	destination, err := url.Parse(strings.TrimSuffix(n.base, "/api/v1"))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(destination)
	transport := &http.Transport{Proxy: nil}
	proxy.Transport = transport
	exports := &atomic.Int64{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/migrations/export" {
			exports.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0) // Expected certificate rejection cases.
	server.StartTLS()
	t.Cleanup(func() { server.Close(); transport.CloseIdleConnections() })
	return server.URL + "/api/v1", secure.Hash(server.Certificate().Raw), exports
}

func waitAPIPush(t *testing.T, n *apiNode, id, state, stage string) migration.PushTask {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		task := readAPIData[migration.PushTask](t, n.request(t, "GET", "/migrations/push/"+id, nil, nil, 200, "OK"))
		switch task.State {
		case "succeeded", "failed", "waiting_confirmation", "recovery_required", "expired":
			if task.State != state || task.Stage != stage {
				t.Fatalf("push ended at %s/%s (%s), want %s/%s", task.State, task.Stage, task.Error, state, stage)
			}
			return task
		}
		if time.Now().After(deadline) {
			t.Fatalf("push %s remained at %s/%s", id, task.State, task.Stage)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertNoAPIKeyFiles(t *testing.T, n *apiNode, secrets ...string) {
	t.Helper()
	err := filepath.WalkDir(n.dataDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range secrets {
			if secret == "" || bytes.Contains(content, []byte(secret)) {
				t.Errorf("plaintext API key in %s", strings.TrimPrefix(path, n.dataDir))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAPIRemoteMigrationAndAuthorization(t *testing.T) {
	source, target := startAPINode(t), startAPINode(t)
	source.initialize(t)
	target.initialize(t)
	sourceURL, sourcePin, exports := tlsAPINode(t, source)
	targetURL, targetPin, _ := tlsAPINode(t, target)
	key := source.credential(t, "read", "config.write", "config.secrets", "security.write", "backup.export", "backup.secrets")
	readOnly := source.credential(t, "read", "config.secrets")
	targetKey := target.credential(t, "read", "backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write")
	resource := nginxconfig.CreateRequest{Kind: "http", Listen: []string{"8088"}, Domains: []string{"remote-migration.example.test"}, Upstream: "http://127.0.0.1:9000"}
	saved := readAPIData[nginxconfig.SaveResult](t, source.request(t, "POST", "/nginx/resources", resource, map[string]string{"Idempotency-Key": "remote-source-site"}, 201, "OK"))
	input := migration.PullInput{Remote: migration.Remote{URL: sourceURL, APIKey: key.Token, Fingerprint: sourcePin, NodeID: source.nodeID}, Mode: "draft", Mappings: map[string]string{"8088": "18088"}}
	plan := readAPIData[migration.Plan](t, target.request(t, "POST", "/migrations/pull", input, map[string]string{"Idempotency-Key": "remote-pull"}, 200, "OK"))
	if plan.SourceNode != source.nodeID || plan.State != "draft" || plan.RevisionID == "" || plan.CanSave || plan.CanApply || exports.Load() != 1 {
		t.Fatal("HTTPS pull did not create the expected draft with unavailable target runtime")
	}
	draft := readAPIData[nginxconfig.Tree](t, target.request(t, "GET", "/nginx/revisions/"+plan.RevisionID, nil, nil, 200, "OK"))
	if len(draft.Resources) != 1 || !draft.Resources[0].Metadata.Enabled || len(draft.Resources[0].Fields["listeners"].Values) != 1 || draft.Resources[0].Fields["listeners"].Values[0] != "18088" {
		t.Fatal("encrypted remote draft lost the listener mapping or source metadata")
	}
	connection := readAPIData[nodes.Connection](t, target.request(t, "POST", "/nodes", nodes.CreateInput{Name: "Source", URL: sourceURL, APIKey: key.Token, Fingerprint: sourcePin}, map[string]string{"Idempotency-Key": "source-connection"}, 201, "OK"))
	if connection.NodeID != source.nodeID || connection.State != "connected" || connection.CredentialID != key.ID {
		t.Fatal("registered node identity or credential changed")
	}
	remote := *target
	remote.nodeID = source.nodeID
	path := "/nodes/connections/" + connection.ID + "/nginx/config-tree"
	forwarded := readAPIData[nginxconfig.Tree](t, remote.request(t, "GET", path, nil, nil, 200, "OK"))
	if forwarded.Version != saved.Tree.Version || forwarded.RevisionID != saved.Tree.RevisionID {
		t.Fatal("remote route returned a different node's configuration")
	}
	resource.BaseVersion = saved.Tree.Version
	resource.Listen, resource.Domains = []string{"8089"}, []string{"forwarded.example.test"}
	remoteSaved := readAPIData[nginxconfig.SaveResult](t, remote.request(t, "POST", "/nodes/connections/"+connection.ID+"/nginx/resources", resource, map[string]string{"Idempotency-Key": "forwarded-site"}, 201, "OK"))
	if remoteSaved.Tree.Version != saved.Tree.Version+1 || len(remoteSaved.Tree.Resources) != 2 {
		t.Fatal("authorized remote configuration write did not reach the source")
	}
	replay := readAPIData[migration.Plan](t, target.request(t, "POST", "/migrations/pull", input, map[string]string{"Idempotency-Key": "remote-pull"}, 200, "OK"))
	if replay.ID != plan.ID || replay.RevisionID != plan.RevisionID || exports.Load() != 1 {
		t.Fatal("idempotent pull fetched or imported the changed source again")
	}
	changed := input
	changed.Mode = "preview"
	target.request(t, "POST", "/migrations/pull", changed, map[string]string{"Idempotency-Key": "remote-pull"}, 409, "CONFLICT")

	for _, failure := range []struct {
		name   string
		remote migration.Remote
	}{
		{"certificate", migration.Remote{URL: sourceURL, APIKey: key.Token, Fingerprint: strings.Repeat("0", 64)}},
		{"identity", migration.Remote{URL: sourceURL, APIKey: key.Token, Fingerprint: sourcePin, NodeID: secure.ID()}},
		{"scope", migration.Remote{URL: sourceURL, APIKey: readOnly.Token, Fingerprint: sourcePin}},
	} {
		failed := target.request(t, "POST", "/migrations/pull", migration.PullInput{Remote: failure.remote, Mode: "preview"}, map[string]string{"Idempotency-Key": failure.name}, 503, "CAPABILITY_UNAVAILABLE")
		if strings.Contains(failed.Message, failure.remote.APIKey) {
			t.Fatal("remote failure exposed its credential")
		}
	}
	redirects := atomic.Int64{}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, sourceURL+"/migrations/export", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	before := exports.Load()
	target.request(t, "POST", "/migrations/pull", migration.PullInput{Remote: migration.Remote{URL: redirect.URL, APIKey: key.Token, Fingerprint: secure.Hash(redirect.Certificate().Raw)}, Mode: "preview"}, map[string]string{"Idempotency-Key": "redirect"}, 503, "CAPABILITY_UNAVAILABLE")
	if redirects.Load() != 1 || exports.Load() != before {
		t.Fatal("migration followed a remote redirect")
	}
	limitedInput := nodes.CreateInput{Name: "Read only", URL: sourceURL, APIKey: readOnly.Token, Fingerprint: sourcePin}
	target.request(t, "POST", "/nodes", limitedInput, map[string]string{"Idempotency-Key": "duplicate-node"}, 409, "CONFLICT")

	pushInput := migration.PushInput{Remote: migration.Remote{URL: targetURL, APIKey: targetKey.Token, Fingerprint: targetPin, NodeID: target.nodeID}, Mode: "preview"}
	push := readAPIData[migration.PushTask](t, source.request(t, "POST", "/migrations/push", pushInput, map[string]string{"Idempotency-Key": "preview-push"}, 202, "OK"))
	pushed := waitAPIPush(t, source, push.ID, "succeeded", "preview")
	if pushed.Plan == nil || pushed.Plan.State != "planned" || pushed.Plan.SourceNode != source.nodeID || pushed.Plan.CanSave || pushed.Plan.CanApply || !pushed.TargetBound || pushed.TargetNode != target.nodeID {
		t.Fatal("push preview did not retain target dependency and identity evidence")
	}
	pushReplay := readAPIData[migration.PushTask](t, source.request(t, "POST", "/migrations/push", pushInput, map[string]string{"Idempotency-Key": "preview-push"}, 202, "OK"))
	if pushReplay.ID != push.ID {
		t.Fatal("push retry created another parent transfer")
	}
	pushInput.Mode = "draft"
	pushDraft := readAPIData[migration.PushTask](t, source.request(t, "POST", "/migrations/push", pushInput, map[string]string{"Idempotency-Key": "draft-push"}, 202, "OK"))
	drafted := waitAPIPush(t, source, pushDraft.ID, "succeeded", "draft")
	if drafted.Plan == nil || drafted.Plan.RevisionID == "" || drafted.Plan.State != "draft" {
		t.Fatal("push executor did not produce a target draft")
	}
	target.request(t, "GET", "/nginx/revisions/"+drafted.Plan.RevisionID, nil, nil, 200, "OK")
	current := readAPIData[nginxconfig.Tree](t, target.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
	if current.Version != 0 {
		t.Fatal("remote drafts or failed requests changed target desired configuration")
	}

	source.request(t, "DELETE", "/credentials/"+key.ID, nil, nil, 200, "OK")
	remote.request(t, "GET", path, nil, nil, 401, "UNAUTHENTICATED")
	revoked := readAPIData[nodes.Connection](t, target.request(t, "GET", "/nodes/"+connection.ID, nil, nil, 200, "OK"))
	if revoked.State != "authorization_failed" {
		t.Fatal("revoked source key left the connection active")
	}
	target.request(t, "GET", path, nil, nil, 409, "REMOTE_CONNECTION_UNAVAILABLE")
	target.request(t, "POST", "/migrations/pull", migration.PullInput{Remote: input.Remote, Mode: "preview"}, map[string]string{"Idempotency-Key": "revoked-source"}, 503, "CAPABILITY_UNAVAILABLE")
	removed := readAPIData[nodes.Connection](t, target.request(t, "DELETE", "/nodes/"+connection.ID, nil, map[string]string{"Idempotency-Key": "remove-revoked-connection"}, 200, "OK"))
	if removed.State != "removed" || removed.Revocation != "pending" {
		t.Fatal("unconfirmed self-revocation was reported as confirmed")
	}
	limited := readAPIData[nodes.Connection](t, target.request(t, "POST", "/nodes", limitedInput, map[string]string{"Idempotency-Key": "replacement-connection"}, 201, "OK"))
	remote.request(t, "GET", "/nodes/connections/"+limited.ID+"/nginx/config-tree", nil, nil, 200, "OK")
	resource.BaseVersion = remoteSaved.Tree.Version
	remote.request(t, "POST", "/nodes/connections/"+limited.ID+"/nginx/resources", resource, map[string]string{"Idempotency-Key": "denied-forward"}, 403, "FORBIDDEN")
	unchanged := readAPIData[nginxconfig.Tree](t, source.request(t, "GET", "/nginx/config-tree", nil, nil, 200, "OK"))
	if unchanged.Version != remoteSaved.Tree.Version {
		t.Fatal("restricted remote write changed source configuration")
	}
	removed = readAPIData[nodes.Connection](t, target.request(t, "DELETE", "/nodes/"+limited.ID, nil, map[string]string{"Idempotency-Key": "remove-limited-connection"}, 200, "OK"))
	if removed.State != "removed" || removed.Revocation != "revoked" {
		t.Fatal("connection removal did not confirm the target's credential revocation")
	}
	source.request(t, "GET", "/me", nil, map[string]string{"Authorization": "Bearer " + readOnly.Token}, 401, "UNAUTHENTICATED")
	assertNoAPIKeyFiles(t, source, key.Token, readOnly.Token, targetKey.Token)
	assertNoAPIKeyFiles(t, target, key.Token, readOnly.Token, targetKey.Token)
	encoded, err := json.Marshal(pushed)
	if err != nil || bytes.Contains(encoded, []byte(targetKey.Token)) {
		t.Fatal("push summary exposed its target credential")
	}
}
