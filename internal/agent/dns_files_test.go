package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNetplanDNSSourceReplacement(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("NGINXPANEL_TEST_DNS_FILES") != "isolated" {
		t.Skip("requires isolated root filesystem with DNS configuration directories")
	}
	for _, parent := range []string{"/etc/netplan", "/run/systemd/network", "/run/NetworkManager/system-connections"} {
		var fs unix.Statfs_t
		if err := unix.Statfs(parent, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
			t.Fatalf("DNS test requires a private tmpfs at %s: %v", parent, err)
		}
	}
	const operation = "f048c7a2-6efd-4f79-88b2-bf3571542e6b"
	paths := []string{
		"/etc/netplan/nginxpanel-test-" + operation + ".yaml",
		"/run/systemd/network/10-netplan-nginxpanel-test-" + operation + ".network",
		"/run/NetworkManager/system-connections/netplan-nginxpanel-test-" + operation + ".nmconnection",
		filepath.Join(t.TempDir(), "outside-dns.yaml"),
	}
	for index, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(path) })
			_, err = f.WriteString("original DNS source\n")
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("prepare source: %v, %v", err, closeErr)
			}
			if err := unix.Setxattr(path, "user.nginxpanel-dns-test", []byte("preserve"), 0); err != nil {
				t.Fatal(err)
			}
			before, err := readDNSFile(path)
			if err != nil {
				t.Fatal(err)
			}
			after := before
			after.Data = []byte("approved replacement\n")
			err = writeHostDNSFile(path, before, after, operation)
			if index == len(paths)-1 {
				if err == nil {
					t.Fatal("writer accepted a path outside approved DNS sources")
				}
				after = before
			} else if err != nil {
				t.Fatal(err)
			}
			current, err := readDNSFile(path)
			if err != nil || !sameDNSFile(current, after) {
				t.Fatalf("source content or attributes differ: %v", err)
			}
			if index != len(paths)-1 {
				if err := writeHostDNSFile(path, before, before, operation); err == nil {
					t.Fatal("writer accepted a stale source snapshot")
				}
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, after.Data) {
					t.Fatal("stale request changed the source")
				}
			}
		})
	}
}
