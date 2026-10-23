package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

func TestPrebuiltStreamDualStackWeights(t *testing.T) {
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
	for path := data; path != os.TempDir(); path = filepath.Dir(path) {
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	db, err := storage.Open(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := modules.Init(ctx, db); err != nil {
		t.Fatal(err)
	}
	vault, err := secure.NewVault(bytes.Repeat([]byte{11}, 32))
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
	tcpBackend := func(network, address string, value byte) string {
		t.Helper()
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer connection.Close()
					connection.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := io.ReadFull(connection, make([]byte, 1)); err == nil {
						connection.Write([]byte{value})
					}
				}()
			}
		}()
		return listener.Addr().String()
	}
	udpBackend := func(network, address string, value byte) string {
		t.Helper()
		listener, err := net.ListenPacket(network, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			buffer := make([]byte, 64)
			for {
				_, peer, err := listener.ReadFrom(buffer)
				if err != nil {
					return
				}
				listener.WriteTo([]byte{value}, peer)
			}
		}()
		return listener.LocalAddr().String()
	}
	reserve := func(network, address string) string {
		t.Helper()
		if strings.HasPrefix(network, "udp") {
			listener, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			return listener.LocalAddr().String()
		}
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().String()
	}
	tcp4, tcp6 := reserve("tcp4", "127.0.0.1:0"), reserve("tcp6", "[::1]:0")
	udp4, udp6 := reserve("udp4", "127.0.0.1:0"), reserve("udp6", "[::1]:0")
	var tree nginxconfig.Tree
	for _, in := range []nginxconfig.CreateRequest{
		{Kind: "stream", Listen: []string{tcp4, tcp6}, Upstream: "127.0.0.1:1", UpstreamServers: []string{tcpBackend("tcp4", "127.0.0.1:0", 'A') + " weight=1", tcpBackend("tcp6", "[::1]:0", 'B') + " weight=3"}},
		{Kind: "stream", Listen: []string{udp4 + " udp", udp6 + " udp"}, Upstream: "127.0.0.1:1", UpstreamServers: []string{udpBackend("udp4", "127.0.0.1:0", 'A') + " weight=1", udpBackend("udp6", "[::1]:0", 'B') + " weight=3"}},
	} {
		in.BaseVersion = tree.Version
		out, err := s.CreateResource(ctx, p, "stream-matrix", secure.ID(), in)
		if err != nil {
			t.Fatal(err)
		}
		tree = out.Tree
	}
	for _, resource := range tree.Resources {
		out, err := s.Patch(ctx, p, "stream-matrix", secure.ID(), resource.ID, tree.Version, map[string][]string{"responses": {"1"}, "session_timeout": {"2s"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = out.Tree
	}
	files := append([]nginxconfig.File(nil), tree.Files...)
	for i := range files {
		if files[i].Path == "nginx.conf" {
			files[i].Content = strings.Replace(files[i].Content, "worker_processes auto;", "worker_processes 1;", 1)
		}
	}
	parsed, err := nginxconfig.Parse(files, s.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) != 0 {
		t.Fatalf("invalid generated Stream config: %v", err)
	}
	n := &Nginx{DataDir: data, Binary: binary, Policy: s.Policy, Container: &nginxcontainer.Runtime{}, uid: 1000, gid: 1000, tempModules: features.httpTempModules}
	if err := os.MkdirAll(filepath.Join(data, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := n.runtimeDirectories(); err != nil {
		t.Fatal(err)
	}
	m := &manifest{DeploymentID: secure.ID(), Probe: "stream-matrix", Modules: map[string]ModuleDependency{}}
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
		cmd := exec.Command(binary, append([]string{"-p", data + "/", "-c", config, "-e", "stderr"}, extra...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		return cmd
	}
	if output, err := command("-t").CombinedOutput(); err != nil {
		t.Fatalf("real Nginx rejected generated Stream config: %v\n%s", err, output)
	}
	log, err := os.Create(filepath.Join(data, "stream-process.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := os.ReadFile(log.Name())
			t.Logf("Nginx runtime log:\n%s", output)
		}
	})
	process := command("-g", "daemon off;")
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		process.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Nginx exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			process.Process.Kill()
			<-done
			t.Error("Nginx shutdown timed out")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", tcp4, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			output, _ := os.ReadFile(log.Name())
			t.Fatalf("Stream startup timed out: %v\n%s", err, output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, endpoint := range []struct{ network, address string }{{"tcp4", tcp4}, {"tcp6", tcp6}, {"udp4", udp4}, {"udp6", udp6}} {
		t.Run(endpoint.network, func(t *testing.T) {
			counts := map[byte]int{}
			for i := 0; i < 12; i++ {
				connection, err := net.DialTimeout(endpoint.network, endpoint.address, 2*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = connection.Write([]byte{'x'})
				response := make([]byte, 1)
				if err == nil {
					_, err = io.ReadFull(connection, response)
				}
				connection.Close()
				if err != nil {
					t.Fatal(err)
				}
				counts[response[0]]++
			}
			if counts['A'] != 3 || counts['B'] != 9 {
				t.Fatalf("1:3 weighting did not reach both IPv4/IPv6 upstreams: %v", counts)
			}
			t.Logf("IPv4 upstream=%d, IPv6 upstream=%d", counts['A'], counts['B'])
		})
	}
	t.Run("shared-udp-ownership", func(t *testing.T) {
		requireNginxSocketFixture(t)
		owned, err := processSockets(process.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := func() []networkSocket {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			sockets, err := networkSockets(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return sockets
		}
		if err := confirmNginxListeners(m.Listeners, owned, snapshot()); err != nil {
			t.Fatal(err)
		}
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			var optionErr error
			if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) }); err != nil {
				return err
			}
			return optionErr
		}}
		foreign, err := lc.ListenPacket(t.Context(), "udp4", udp4)
		if err != nil {
			t.Fatalf("fixture did not reproduce shared UDP binding: %v", err)
		}
		if err := confirmNginxListeners(m.Listeners, owned, snapshot()); err == nil {
			foreign.Close()
			t.Fatal("Nginx was confirmed despite a foreign UDP socket on the same endpoint")
		}
		if err := checkListenerOccupancy(m.Listeners, owned, snapshot()); err == nil {
			foreign.Close()
			t.Fatal("preflight accepted a shared foreign UDP socket")
		}
		foreign.Close()
		if err := confirmNginxListeners(m.Listeners, owned, snapshot()); err != nil {
			t.Fatalf("Nginx ownership did not recover after closing only the foreign fixture: %v", err)
		}
	})
	t.Run("reuseport-two-workers", func(t *testing.T) {
		requireNginxSocketFixture(t)
		backend4 := udpBackend("udp4", "127.0.0.1:0", 'R')
		backendTCP6 := tcpBackend("tcp6", "[::1]:0", 'R')
		backendUDP6 := udpBackend("udp6", "[::1]:0", 'R')
		tcp4Lease, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer tcp4Lease.Close()
		udp4Lease, err := net.ListenPacket("udp4", tcp4Lease.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer udp4Lease.Close()
		tcp6Lease, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		defer tcp6Lease.Close()
		udp6Lease, err := net.ListenPacket("udp6", tcp6Lease.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer udp6Lease.Close()
		address4, address6 := tcp4Lease.Addr().String(), tcp6Lease.Addr().String()
		_, port4, _ := net.SplitHostPort(address4)
		wildcard := "0.0.0.0:" + port4
		content := fmt.Sprintf("worker_processes 2;\npid run/nginx.pid;\nevents { worker_connections 64; }\nhttp { access_log off; server { listen %s reuseport; return 200 wildcard; } server { listen %s; return 200 specific; } }\nstream { server { listen %s udp reuseport; proxy_pass %s; } server { listen %s reuseport; proxy_pass %s; } server { listen %s udp reuseport; proxy_pass %s; } }\n", wildcard, address4, address4, backend4, address6, backendTCP6, address6, backendUDP6)
		parsed, err := nginxconfig.Parse([]nginxconfig.File{{ID: "main", Path: "nginx.conf", Content: content}}, s.Policy)
		if err != nil || len(parsed.Tree.Diagnostics) != 0 {
			t.Fatalf("invalid reuseport fixture: %v", err)
		}
		private := t.TempDir()
		for path := private; path != os.TempDir(); path = filepath.Dir(path) {
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
		}
		runtime := &Nginx{DataDir: private, Binary: binary, Policy: s.Policy, Container: &nginxcontainer.Runtime{}, uid: 1000, gid: 1000, tempModules: features.httpTempModules}
		if err := os.MkdirAll(filepath.Join(private, "run"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := runtime.runtimeDirectories(); err != nil {
			t.Fatal(err)
		}
		manifest := &manifest{DeploymentID: secure.ID(), Probe: "reuseport-matrix", Modules: map[string]ModuleDependency{}}
		contents, err := runtime.render(parsed, manifest, nil)
		if err != nil {
			t.Fatal(err)
		}
		file := runtime.configPath(manifest.DeploymentID)
		for name, content := range contents {
			path := filepath.Join(filepath.Dir(file), name)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
		}
		wants := manifest.Listeners
		tcp4Lease.Close()
		udp4Lease.Close()
		tcp6Lease.Close()
		udp6Lease.Close()
		cmd := exec.Command(binary, "-p", private+"/", "-c", file, "-e", "stderr", "-g", "daemon off;")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("reuseport Nginx exit: %v", err)
				}
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Error("reuseport Nginx shutdown timed out")
			}
		}()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		for {
			owned, err := processSockets(cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			sockets, err := networkSockets(ctx)
			if err != nil {
				t.Fatal(err)
			}
			err = confirmNginxListeners(wants, owned, sockets)
			if err == nil {
				for _, want := range []listener{wants[0], wants[2], wants[3], wants[4]} {
					count := 0
					for _, socket := range sockets {
						if socket.passive && owned[socket.inode] && listenerCovers(socket.listener, want) {
							count++
						}
					}
					if count != 2 {
						t.Fatalf("expected two worker reuseport sockets for %+v, got %d", want, count)
					}
				}
				break
			}
			if ctx.Err() != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, endpoint := range []struct{ network, address string }{{"udp4", address4}, {"tcp6", address6}, {"udp6", address6}} {
			connection, err := net.DialTimeout(endpoint.network, endpoint.address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			connection.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = connection.Write([]byte{'x'})
			var response [1]byte
			if err == nil {
				_, err = io.ReadFull(connection, response[:])
			}
			connection.Close()
			if err != nil || response[0] != 'R' {
				t.Fatalf("reuseport %s proxy failed: %q, %v", endpoint.network, response, err)
			}
		}
		connection, err := net.DialTimeout("tcp4", address4, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(connection, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
		response, err := io.ReadAll(connection)
		if err != nil || !bytes.HasSuffix(response, []byte("specific")) {
			t.Fatalf("coalesced HTTP listener failed: %q, %v", response, err)
		}
	})
	t.Run("listen-conflict", func(t *testing.T) {
		// Nginx UDP sockets allow SO_REUSEADDR; use an exclusive external
		// listener so the negative case really exercises a UDP bind conflict.
		occupied, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		blockedUDP := occupied.LocalAddr().String()
		conflictConfig := filepath.Join(filepath.Dir(config), "conflict.conf")
		content := fmt.Sprintf("worker_processes 1;\npid %s;\nevents { worker_connections 64; }\nstream { server { listen %s; proxy_pass 127.0.0.1:1; } server { listen %s udp; proxy_pass 127.0.0.1:1; } }\n", n.runPath("conflict.pid"), tcp4, blockedUDP)
		if err := os.WriteFile(conflictConfig, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		conflictCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		conflict := exec.CommandContext(conflictCtx, binary, "-p", data+"/", "-c", conflictConfig, "-e", "stderr", "-g", "daemon off;")
		conflict.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		output, err := conflict.CombinedOutput()
		if err == nil || conflictCtx.Err() != nil || !bytes.Contains(output, []byte(tcp4)) || !bytes.Contains(output, []byte(blockedUDP)) || !bytes.Contains(output, []byte("98:")) {
			t.Fatalf("TCP/UDP listener conflict was not diagnosed: %v\n%s", err, output)
		}
		connection, err := net.DialTimeout("tcp4", tcp4, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 1)
		if _, err := io.ReadFull(connection, response); err != nil || response[0] != 'A' && response[0] != 'B' {
			t.Fatalf("existing proxy stopped after rejected candidate: %q, %v", response, err)
		}
	})
}
