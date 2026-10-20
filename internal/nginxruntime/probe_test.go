package nginxruntime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func TestReservedProbeCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated environment")
	}
	base := t.TempDir()
	if err := secure.RootDirectory(base, 0700); err != nil {
		t.Skip("requires a root-owned TMPDIR with protected ancestors")
	}
	for _, kind := range []string{"missing", "stale", "listening", "bound", "file", "symlink", "foreign_owner", "writable_parent", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			data := filepath.Join(base, kind)
			dir := filepath.Join(data, "run")
			if err := secure.RootDirectory(dir, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "nginx-probe.sock")
			switch kind {
			case "missing":
			case "file":
				if err := os.WriteFile(name, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("elsewhere", name); err != nil {
					t.Fatal(err)
				}
			case "bound":
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if err = unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
					t.Fatal(err)
				}
			default:
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				l.SetUnlinkOnClose(false)
				if kind == "listening" {
					defer l.Close()
				} else if err = l.Close(); err != nil {
					t.Fatal(err)
				}
				if kind == "foreign_owner" {
					if err = os.Chown(name, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "writable_parent" {
					if err = os.Chmod(dir, 0777); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _ := os.Lstat(name)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			err := clearStaleProbe(ctx, data)
			after, statErr := os.Lstat(name)
			if kind == "missing" || kind == "stale" {
				if err != nil || !os.IsNotExist(statErr) {
					t.Fatalf("cleanup: %v, remaining path: %v", err, statErr)
				}
			} else if err == nil || statErr != nil || !os.SameFile(before, after) {
				t.Fatalf("unsafe cleanup: %v, path changed: %v", err, statErr)
			}
		})
	}
}
