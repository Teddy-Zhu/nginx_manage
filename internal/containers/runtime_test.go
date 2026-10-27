package containers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise the actual fixed Docker socket transport inside an isolated build
// container. Never replace an existing socket or touch a developer's daemon.
func TestContainerWorkflow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root container")
	}
	if os.Getenv("NGINXPANEL_ISOLATED_DOCKER_TEST") != "1" {
		t.Skip("requires explicit isolated Docker test environment")
	}
	if _, err := os.Lstat("/run/docker.sock"); !os.IsNotExist(err) {
		t.Skip("requires a container without a mounted Docker socket")
	}
	listener, err := net.Listen("unix", "/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod("/run/docker.sock", 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	id, systemID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	state, tty, logMode, posts := "running", false, "normal", 0
	frame := func(text string) []byte {
		header := make([]byte, 8)
		header[0] = 1
		binary.BigEndian.PutUint32(header[4:], uint32(len(text)))
		return append(header, []byte(text)...)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/v1.47")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && path == "/containers/json" {
			json.NewEncoder(w).Encode([]any{map[string]any{"Id": id, "Names": []string{"/demo"}, "Image": "demo:latest", "State": state, "Created": 123, "Labels": map[string]string{"com.docker.compose.project": "example", "secret": "hidden-value"}, "Ports": []any{map[string]any{"PrivatePort": 80, "PublicPort": 8080, "IP": "0.0.0.0", "Type": "tcp"}}}, map[string]any{"Id": systemID, "Names": []string{"/nginxpanel"}, "State": "running"}})
			return
		}
		if r.Method == http.MethodGet && (path == "/containers/"+id+"/json" || path == "/containers/"+systemID+"/json") {
			name, current := "/demo", id
			if strings.Contains(path, systemID) {
				name, current = "/nginxpanel", systemID
			}
			json.NewEncoder(w).Encode(map[string]any{"Id": current, "Name": name, "Image": "sha256:abc", "Created": "2026-10-27T00:00:00Z", "Config": map[string]any{"Image": "demo:latest", "Tty": tty, "Env": []string{"PASSWORD=hidden-value"}}, "State": map[string]any{"Status": state, "StartedAt": "2026-10-27T00:00:01Z", "FinishedAt": "0001-01-01T00:00:00Z", "Health": map[string]string{"Status": "healthy"}}, "HostConfig": map[string]any{"NetworkMode": "bridge", "RestartPolicy": map[string]string{"Name": "unless-stopped"}}, "NetworkSettings": map[string]any{"Networks": map[string]any{"bridge": map[string]string{"IPAddress": "172.18.0.2", "Gateway": "172.18.0.1"}}, "Ports": map[string]any{"80/tcp": []any{map[string]string{"HostIP": "0.0.0.0", "HostPort": "8080"}}}}, "Mounts": []any{map[string]any{"Source": "/srv/demo", "Destination": "/data", "RW": false}}})
			return
		}
		if r.Method == http.MethodGet && path == "/containers/"+id+"/logs" {
			if r.URL.Query().Get("follow") != "false" || r.URL.Query().Get("timestamps") != "true" {
				http.Error(w, "invalid log options", 400)
				return
			}
			if logMode == "unsupported" {
				w.WriteHeader(501)
				return
			}
			content := []byte("hello\n")
			if logMode == "large" {
				content = []byte(strings.Repeat("x", logLimit+100))
			}
			if !tty {
				content = frame(string(content))
				if logMode == "normal" {
					content = append(content, frame("error\n")...)
				}
				if logMode == "corrupt" {
					content = content[:len(content)-1]
				}
			}
			w.Write(content)
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(path, "/containers/"+id+"/") {
			action := strings.TrimPrefix(path, "/containers/"+id+"/")
			if action != "start" && r.URL.Query().Get("t") != "10" {
				http.Error(w, "missing stop timeout", 400)
				return
			}
			switch action {
			case "stop":
				state = "exited"
			case "start", "restart":
				state = "running"
			default:
				http.NotFound(w, r)
				return
			}
			posts++
			w.WriteHeader(204)
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); listener.Close(); os.Remove("/run/docker.sock") })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	view, err := List(ctx)
	if err != nil || !view.Available || len(view.Containers) != 2 {
		t.Fatalf("list: %#v %v", view, err)
	}
	if view.Containers[0].Project != "example" || !view.Containers[1].Protected || view.Containers[0].Ports[0].Public != 8080 {
		t.Fatalf("list details: %#v", view)
	}
	detail, err := Inspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Health != "healthy" || detail.Networks[0].Address != "172.18.0.2" || !detail.Mounts[0].ReadOnly || detail.Ports[0].Public != 8080 {
		t.Fatalf("detail: %#v", detail)
	}
	for _, data := range []any{detail, view} {
		raw, _ := json.Marshal(data)
		if strings.Contains(string(raw), "hidden-value") {
			t.Fatal("sensitive fields leaked")
		}
	}
	for _, action := range []string{"stop", "start", "restart"} {
		progress := ""
		message, err := Run(ctx, Control{ID: id, Action: action}, func(value string) { progress = value })
		if err != nil || message == "" || progress == "" {
			t.Fatalf("%s: %s %v", action, message, err)
		}
	}
	mu.Lock()
	before := posts
	mu.Unlock()
	if _, err = Run(ctx, Control{ID: systemID, Action: "stop"}, func(string) {}); err == nil {
		t.Fatal("panel container stop accepted")
	}
	if _, err = Run(ctx, Control{ID: "../bad", Action: "restart"}, func(string) {}); err == nil {
		t.Fatal("invalid container ID accepted")
	}
	mu.Lock()
	if posts != before {
		t.Error("rejected control reached Docker")
	}
	mu.Unlock()
	for _, tc := range []struct {
		name              string
		tty               bool
		mode, text        string
		truncated, failed bool
	}{
		{name: "multiplexed", mode: "normal", text: "hello\nerror\n"},
		{name: "tty", tty: true, mode: "normal", text: "hello\n"},
		{name: "bounded-multiplex", mode: "large", text: strings.Repeat("x", logLimit-8), truncated: true},
		{name: "bounded-tty", tty: true, mode: "large", text: strings.Repeat("x", logLimit), truncated: true},
		{name: "incomplete", mode: "corrupt", failed: true},
		{name: "unsupported-driver", mode: "unsupported", failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			tty, logMode = tc.tty, tc.mode
			mu.Unlock()
			out, err := ReadLogs(ctx, id, 10)
			if tc.failed {
				if err == nil {
					t.Fatal("invalid logs accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.Text != tc.text || out.Truncated != tc.truncated {
				t.Fatalf("log content/truncation mismatch: length=%d, truncated=%t", len(out.Text), out.Truncated)
			}
		})
	}
	if _, err = ReadLogs(ctx, id, 501); err == nil {
		t.Fatal("unbounded logs accepted")
	}
	// A missing container is distinct from a daemon connection error.
	if _, err = Inspect(ctx, strings.Repeat("c", 64)); err == nil {
		t.Fatal("missing container accepted")
	}
}
