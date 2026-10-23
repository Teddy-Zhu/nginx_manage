package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

// Run only inside the built Nginx image. The test needs ownership changes in
// its private /srv tmpfs, never access to a host Agent or Docker socket.
func TestPrebuiltNginxRuntime(t *testing.T) {
	binary := os.Getenv("NGINXPANEL_TEST_NGINX")
	if binary == "" {
		t.Skip("requires the isolated prebuilt Nginx runtime image")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(os.TempDir(), "/srv/") {
		t.Fatal("requires a root-owned private /srv tmpfs inside the test container")
	}
	var capabilities nginxcontainer.Capabilities
	raw, err := os.ReadFile("/usr/share/nginxpanel/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.Policy != "image-only" || capabilities.Installation || capabilities.Compilation || len(capabilities.Dynamic) != 0 {
		t.Fatal("image permits runtime module changes")
	}
	build, err := os.ReadFile(capabilities.BuildInformation)
	if err != nil {
		t.Fatal(err)
	}
	features, err := containerFeatures(nginxcontainer.Binding{Build: string(build), Capabilities: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	data := t.TempDir()
	for at := data; at != os.TempDir(); at = filepath.Dir(at) {
		if err := os.Chmod(at, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// Restore traversal for Go's root test cleanup after the non-root master
		// has exited. Runtime directories deliberately belong to UID 1000.
		if err := filepath.WalkDir(data, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(path, 0755)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	db, err := storage.Open(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := modules.Init(ctx, db); err != nil {
		t.Fatal(err)
	}
	vault, err := secure.NewVault(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &nginxconfig.Service{DB: db, Vault: vault, Policy: nginxconfig.DefaultPolicy(), RequireFeatures: func(_ context.Context, required []string) error {
		for _, feature := range required {
			if !features.Features[feature].Available {
				return fmt.Errorf("image lacks %s", feature)
			}
		}
		return nil
	}}
	p := auth.Principal{ID: secure.ID(), Scopes: auth.AllScopes}
	var tree nginxconfig.Tree
	accept := func(result nginxconfig.SaveResult, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		tree = result.Tree
	}
	add := func(kind, address, upstream string) string {
		t.Helper()
		prior := map[string]bool{}
		for _, resource := range tree.Resources {
			prior[resource.ID] = true
		}
		in := nginxconfig.CreateRequest{BaseVersion: tree.Version, Kind: kind, Listen: []string{address}, Upstream: upstream}
		if kind == "http" {
			in.Domains = []string{"runtime.example.test"}
		}
		accept(s.CreateResource(ctx, p, "runtime", secure.ID(), in))
		for _, resource := range tree.Resources {
			if !prior[resource.ID] {
				return resource.ID
			}
		}
		t.Fatal("resource was not created")
		return ""
	}
	patch := func(id, field, value string) {
		t.Helper()
		accept(s.Patch(ctx, p, "runtime", secure.ID(), id, tree.Version, map[string][]string{field: {value}}, nil))
	}
	held, release := make(chan struct{}), make(chan struct{})
	var holdOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			holdOnce.Do(func() { close(held) })
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "upstream:"+r.URL.Path)
	}))
	defer func() { unblock(); upstream.Close() }()
	httpAddress, rateAddress, aclAddress := runtimeTestAddress(t, "tcp"), runtimeTestAddress(t, "tcp"), runtimeTestAddress(t, "tcp")
	site := add("http", httpAddress, upstream.URL)
	rateSite := add("http", rateAddress, upstream.URL)
	aclSite := add("http", aclAddress, upstream.URL)
	for _, policy := range []struct {
		resource string
		config   nginxconfig.WAFConfig
	}{
		{site, nginxconfig.WAFConfig{Metadata: nginxconfig.ResourceMetadata{Name: "Runtime rules", Enabled: true}, RateUnit: "r/s", Connections: 1, RejectStatus: 429, BodySize: "1k", Methods: []string{"GET", "POST"}, DeniedPaths: []nginxconfig.WAFPath{{Match: "prefix", Path: "/blocked"}}, ExemptPaths: []nginxconfig.WAFPath{{Match: "exact", Path: "/exempt"}}}},
		{rateSite, nginxconfig.WAFConfig{Metadata: nginxconfig.ResourceMetadata{Name: "Runtime rate", Enabled: true}, Rate: 1, RateUnit: "r/m", RejectStatus: 429}},
	} {
		prior := map[string]bool{}
		for _, existing := range tree.WAFPolicies {
			prior[existing.ID] = true
		}
		accept(s.WAF(ctx, p, "runtime", secure.ID(), "", "create", nginxconfig.WAFInput{BaseVersion: tree.Version, WAFConfig: policy.config}))
		for _, created := range tree.WAFPolicies {
			if !prior[created.ID] {
				patch(policy.resource, "waf_policy", created.ID)
				break
			}
		}
	}
	accept(s.AccessList(ctx, p, "runtime", secure.ID(), "", "create", nginxconfig.AccessListRequest{BaseVersion: tree.Version, Name: "Loopback denial", Mode: "denylist", Entries: []string{"127.0.0.1/32"}}))
	if len(tree.AccessLists) != 1 {
		t.Fatal("missing ACL")
	}
	patch(aclSite, "access_list", tree.AccessLists[0].ID)

	tcpUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpUpstream.Close()
	go func() {
		for {
			connection, err := tcpUpstream.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); io.Copy(connection, connection) }()
		}
	}()
	udpUpstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpUpstream.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			size, peer, err := udpUpstream.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpUpstream.WriteTo(buffer[:size], peer)
		}
	}()
	tcpAddress, udpAddress := runtimeTestAddress(t, "tcp"), runtimeTestAddress(t, "udp")
	tcpSite := add("stream", tcpAddress, tcpUpstream.Addr().String())
	udpSite := add("stream", udpAddress+" udp", udpUpstream.LocalAddr().String())
	patch(udpSite, "responses", "1")
	files := append([]nginxconfig.File(nil), tree.Files...)
	for i := range files {
		if files[i].Path == "nginx.conf" {
			files[i].Content = strings.Replace(files[i].Content, "worker_processes auto;", "worker_processes 1;", 1)
		}
	}
	accept(s.Save(ctx, p, "runtime", secure.ID(), nginxconfig.SaveRequest{BaseVersion: tree.Version, Files: files}))

	n := &Nginx{DataDir: data, Binary: binary, Policy: s.Policy, Container: &nginxcontainer.Runtime{}, uid: 1000, gid: 1000, tempModules: features.httpTempModules}
	if err := os.MkdirAll(filepath.Join(data, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := n.runtimeDirectories(); err != nil {
		t.Fatal(err)
	}
	parsed, err := nginxconfig.Parse(tree.Files, s.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) != 0 {
		t.Fatalf("invalid generated source: %v", err)
	}
	m := &manifest{DeploymentID: secure.ID(), Probe: "runtime-probe", Modules: map[string]ModuleDependency{}}
	contents, err := n.render(parsed, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := n.configPath(m.DeploymentID)
	for name, content := range contents {
		path := filepath.Join(filepath.Dir(config), name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := func(extra ...string) *exec.Cmd {
		args := []string{"-p", data + "/", "-c", config, "-e", "stderr"}
		cmd := exec.Command(binary, append(args, extra...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		return cmd
	}
	if output, err := command("-t").CombinedOutput(); err != nil {
		t.Fatalf("real Nginx rejected generated config: %v\n%s", err, output)
	}
	output, err := os.Create(filepath.Join(data, "nginx-process.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	process := command("-g", "daemon off;")
	process.Stdout, process.Stderr = output, output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		process.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				log, _ := os.ReadFile(output.Name())
				t.Errorf("Nginx exit: %v\n%s", err, log)
			}
		case <-time.After(5 * time.Second):
			process.Process.Kill()
			<-done
			t.Error("Nginx shutdown timed out")
		}
	}
	defer stop()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	request := func(method, address, path, body string) (int, string, error) {
		req, err := http.NewRequest(method, "http://"+address+path, strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.Host = "runtime.example.test"
		req.Header.Set("Authorization", "Bearer runtime-authorization-secret")
		response, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		result, err := io.ReadAll(io.LimitReader(response.Body, 8192))
		return response.StatusCode, string(result), err
	}
	expect := func(method, address, path, body string, status int) string {
		t.Helper()
		actual, result, err := request(method, address, path, body)
		if err != nil || actual != status {
			t.Fatalf("%s %s: got %d (%v), want %d: %s", method, path, actual, err, status, result)
		}
		return result
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, _, err := request("GET", httpAddress, "/ready", "")
		if err == nil && status == 200 {
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(output.Name())
			t.Fatalf("Nginx startup failed: %v\n%s", err, log)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if body := expect("GET", httpAddress, "/normal?secret=runtime-query-secret", "", 200); body != "upstream:/normal" {
		t.Fatalf("HTTP proxy response: %q", body)
	}
	expect("GET", httpAddress, "/blocked/subpath", "", 403)
	expect("DELETE", httpAddress, "/normal", "", 405)
	expect("POST", httpAddress, "/normal", strings.Repeat("x", 2048), 413)
	expect("DELETE", httpAddress, "/exempt", "", 200)
	expect("GET", aclAddress, "/normal", "", 403)
	expect("GET", rateAddress, "/first", "", 200)
	expect("GET", rateAddress, "/second", "", 429)
	heldDone := make(chan error, 1)
	go func() {
		status, _, err := request("GET", httpAddress, "/hold", "")
		if err == nil && status != 200 {
			err = fmt.Errorf("held request returned %d", status)
		}
		heldDone <- err
	}()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive held request")
	}
	expect("GET", httpAddress, "/concurrent", "", 429)
	unblock()
	if err := <-heldDone; err != nil {
		t.Fatal(err)
	}
	const payload = "runtime-stream-payload-secret"
	for _, target := range []struct{ network, address string }{{"tcp", tcpAddress}, {"udp", udpAddress}} {
		connection, err := net.DialTimeout(target.network, target.address, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(connection, payload); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		result := make([]byte, len(payload))
		_, err = io.ReadFull(connection, result)
		connection.Close()
		if err != nil || string(result) != payload {
			t.Fatalf("%s bidirectional proxy: %v, %q", target.network, err, result)
		}
	}
	stop()
	for _, source := range []struct{ kind, id string }{{"nginx", site}, {"nginx", rateSite}, {"stream", tcpSite}, {"stream", udpSite}} {
		log, err := os.ReadFile(filepath.Join(data, "logs", source.kind, source.id, "access.log"))
		if err != nil || len(bytes.TrimSpace(log)) == 0 {
			t.Fatalf("missing %s JSON log: %v", source.kind, err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(log), []byte{'\n'}) {
			var event map[string]string
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatalf("invalid %s JSON log: %v", source.kind, err)
			}
			if event["remote_addr"] != "127.0.0.1" || event["status"] == "" {
				t.Fatalf("missing runtime log evidence: %v", event)
			}
		}
		for _, secret := range []string{"runtime-query-secret", "runtime-authorization-secret", payload} {
			if bytes.Contains(log, []byte(secret)) {
				t.Fatalf("secret appeared in %s access log", source.kind)
			}
		}
	}
}

func runtimeTestAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		listener, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.LocalAddr().String()
	}
	listener, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}
