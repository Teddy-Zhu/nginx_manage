package agent

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolatedFirewallELFPinning(t *testing.T) {
	if os.Getenv("NGINXPANEL_TEST_FIREWALL_ELF") != "isolated" {
		t.Skip("requires an isolated firewall ELF fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 || !strings.HasPrefix(os.TempDir(), "/srv/") {
		t.Fatal("requires Docker root and a private trusted temporary directory")
	}
	raw, err := os.ReadFile("/bin/true")
	if err != nil || len(raw) < 4 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatal("fixture requires a real ELF executable", err)
	}
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"unchanged", "contents", "replacement", "alias", "permissions", "setid", "invalid-elf"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tool")
			write(t, path)
			invoked := path
			if name == "alias" {
				invoked = filepath.Join(root, "alias")
				if err := os.Symlink(path, invoked); err != nil {
					t.Fatal(err)
				}
			}
			tool, err := readUFWBoundFile("fixture", invoked, true, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if name == "unchanged" {
				streamed, err := hashUFWBoundFile("fixture", invoked, true, 1<<20)
				if err != nil || streamed.File != tool.File || len(streamed.Raw) != 0 {
					t.Fatal("streamed verification changed the binding or retained bytes", err)
				}
				if _, err := hashUFWBoundFile("fixture", invoked, true, int64(len(raw)-1)); err == nil {
					t.Fatal("streamed verification accepted an oversized executable")
				}
			}
			switch name {
			case "contents":
				changed := bytes.Clone(raw)
				changed[len(changed)-1] ^= 1
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, changed, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "replacement", "alias":
				other := filepath.Join(root, "other")
				write(t, other)
				if name == "alias" {
					if err := os.Remove(invoked); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(other, invoked); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Rename(other, path); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			case "setid":
				if err := os.Chmod(path, 0755|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
				tool, err = readUFWBoundFile("fixture", invoked, true, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
			case "invalid-elf":
				changed := bytes.Clone(raw)
				changed[0] = 0
				if err := os.WriteFile(path, changed, 0755); err != nil {
					t.Fatal(err)
				}
				tool, err = hashUFWBoundFile("fixture", invoked, true, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
			}
			file, err := openFirewallELF(tool, 1<<20)
			if file != nil {
				defer file.Close()
			}
			if name != "unchanged" {
				if err == nil || file != nil {
					t.Fatal("accepted a changed or invalid executable", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := io.ReadAll(file)
			if err != nil || !bytes.Equal(pinned, raw) {
				t.Fatal("pinned the wrong executable", err)
			}
			if _, err := file.Write([]byte{0}); err == nil {
				t.Fatal("pinned descriptor is writable")
			}
		})
	}
}
