package agent

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/secure"
)

func TestRenderListenerAddressConflicts(t *testing.T) {
	requireNginxSocketFixture(t)
	for _, test := range []struct {
		name, http, stream string
		conflict           bool
	}{
		{"wildcard-specific", "0.0.0.0:39080", "127.0.0.1:39080", true},
		{"specific-wildcard", "127.0.0.1:39080", "0.0.0.0:39080", true},
		{"dual-stack", "[::]:39080 ipv6only=off", "127.0.0.1:39080", true},
		{"ipv6-only", "[::]:39080 ipv6only=on", "127.0.0.1:39080", false},
		{"separate-protocols", "0.0.0.0:39080", "0.0.0.0:39080 udp", false},
		{"separate-addresses", "127.0.0.1:39080", "127.0.0.2:39080", false},
		{"mapped-ipv4", "[::ffff:127.0.0.1]:39080 ipv6only=off", "127.0.0.1:39080", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := nginxconfig.DefaultPolicy()
			content := "worker_processes 1; pid run/nginx.pid; events { worker_connections 64; } http { server { listen " + test.http + "; return 200; } } stream { server { listen " + test.stream + "; proxy_pass 127.0.0.1:1; } }"
			parsed, err := nginxconfig.Parse([]nginxconfig.File{{ID: "main", Path: "nginx.conf", Content: content}}, policy)
			if err != nil || len(parsed.Tree.Diagnostics) != 0 {
				t.Fatalf("invalid fixture: %v, %#v", err, parsed.Tree.Diagnostics)
			}
			data := t.TempDir()
			for path := data; path != os.TempDir(); path = filepath.Dir(path) {
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			n := &Nginx{DataDir: data, Policy: policy, Container: &nginxcontainer.Runtime{}, uid: 1000, gid: 1000}
			if err := os.MkdirAll(filepath.Join(data, "run"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := n.runtimeDirectories(); err != nil {
				t.Fatal(err)
			}
			_, err = n.render(parsed, &manifest{DeploymentID: secure.ID(), Probe: "listener-test", Modules: map[string]ModuleDependency{}}, nil)
			if (err != nil) != test.conflict {
				t.Fatalf("conflict=%v, render error=%v", test.conflict, err)
			}
			if test.conflict && !strings.Contains(err.Error(), "conflicting listeners") {
				t.Fatalf("unrelated fixture failure: %v", err)
			}
		})
	}
}

func TestListenerCoverageDoesNotHideIPv6ModeOrForeignUDP(t *testing.T) {
	wildcard := listener{Network: "tcp4", IP: "0.0.0.0", Port: 39080}
	specific := listener{Network: "tcp4", IP: "127.0.0.1", Port: 39080}
	owned := map[string]bool{"10": true}
	if err := confirmNginxListeners([]listener{wildcard, specific}, owned, []networkSocket{{listener: wildcard, inode: "10", passive: true}}); err != nil {
		t.Fatalf("HTTP wildcard coalescing was rejected: %v", err)
	}
	v6 := listener{Network: "tcp6", IP: "::1", Port: 39080}
	actual := v6
	actual.DualStack = true
	if err := confirmNginxListeners([]listener{v6}, owned, []networkSocket{{listener: actual, inode: "10", passive: true}}); err == nil {
		t.Fatal("IPv6-only option mismatch was confirmed")
	}
	udp := listener{Network: "udp4", IP: "127.0.0.1", Port: 39080}
	if err := confirmNginxListeners([]listener{udp}, owned, []networkSocket{{listener: udp, inode: "10", passive: true}, {listener: udp, inode: "11", passive: true}}); err == nil {
		t.Fatal("foreign UDP socket sharing the same endpoint was confirmed")
	}
	if listenersOverlap(listener{}, wildcard) || listenerCovers(listener{}, wildcard) {
		t.Fatal("invalid listener was accepted")
	}
}

func TestParseNginxSocketRequiresCompleteIPv6Proof(t *testing.T) {
	data := make([]byte, 80)
	data[0], data[1] = unix.AF_INET6, 10
	binary.BigEndian.PutUint16(data[4:6], 39080)
	binary.NativeEndian.PutUint32(data[68:72], 10)
	binary.NativeEndian.PutUint16(data[72:74], 5)
	binary.NativeEndian.PutUint16(data[74:76], nginxDiagV6Only)
	for _, value := range []byte{0, 1} {
		data[76] = value
		item, err := parseNginxSocket(data, "tcp6", unix.AF_INET6, 1<<10)
		if err != nil || item.listener.DualStack != (value == 0) {
			t.Fatalf("IPV6_V6ONLY=%d: %#v, %v", value, item, err)
		}
	}
	for _, raw := range [][]byte{data[:71], data[:72], data[:79], append(append([]byte{}, data...), data[72:]...)} {
		if _, err := parseNginxSocket(raw, "tcp6", unix.AF_INET6, 1<<10); err == nil {
			t.Fatal("incomplete or duplicated IPv6 proof was accepted")
		}
	}
}

func requireNginxSocketFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("NGINXPANEL_TEST_SOCKET_DIAG") != "1" {
		t.Skip("requires an isolated socket diagnostic fixture")
	}
	marker, err := os.ReadFile("/.nginxpanel-socket-fixture")
	if err != nil || string(marker) != "nginxpanel-isolated-socket-diagnostics\n" {
		t.Fatal("missing isolated socket fixture marker")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("socket diagnostics must run in a private Docker network namespace")
	}
}

func TestIsolatedSocketDiagnostics(t *testing.T) {
	requireNginxSocketFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var wants []listener
	for _, test := range []struct {
		network string
		only    int
	}{{"tcp6", 0}, {"tcp6", 1}, {"udp6", 0}, {"udp6", 1}} {
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, test.only)
			}); err != nil {
				return err
			}
			return optionErr
		}}
		var address net.Addr
		if strings.HasPrefix(test.network, "tcp") {
			ln, err := lc.Listen(ctx, test.network, "[::]:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			address = ln.Addr()
		} else {
			ln, err := lc.ListenPacket(ctx, test.network, "[::]:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			address = ln.LocalAddr()
		}
		_, port, _ := net.SplitHostPort(address.String())
		want, _, err := parseListener([]nginxconfig.Token{{Value: "[::]:" + port}, {Value: map[int]string{0: "ipv6only=off", 1: "ipv6only=on"}[test.only]}}, "stream")
		if err != nil {
			t.Fatal(err)
		}
		want.Network = test.network
		wants = append(wants, want)
	}
	connected, err := net.Dial("udp6", "[::1]:39081")
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	connectedWant, _, err := parseListener([]nginxconfig.Token{{Value: connected.LocalAddr().String()}, {Value: "udp"}}, "stream")
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := networkSockets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := processSockets(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmNginxListeners(wants, owned, sockets); err != nil {
		t.Fatal(err)
	}
	if err := panelReadinessListener(ctx, os.Getpid(), net.JoinHostPort("::", strconv.Itoa(wants[0].Port))); err != nil {
		t.Fatalf("management readiness did not preserve TCP listener ownership: %v", err)
	}
	for _, want := range wants {
		ipv4 := listener{Network: want.Network[:3] + "4", IP: "127.0.0.1", Port: want.Port}
		err := checkListenerOccupancy([]listener{ipv4}, nil, sockets)
		if (err != nil) != want.DualStack {
			t.Fatalf("IPv4 occupancy for %+v: %v", want, err)
		}
	}
	if err := checkListenerOccupancy([]listener{connectedWant}, nil, sockets); err == nil {
		t.Fatal("connected UDP reservation was omitted")
	}
}
