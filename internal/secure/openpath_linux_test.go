package secure

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenReadNoSymlinks(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(child, "value")
	if err := os.WriteFile(file, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"link": "child", "file-link": "child/value"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	base, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(base)
	for _, tc := range []struct {
		name  string
		fd    int
		path  string
		flags int
		ok    bool
	}{
		{"absolute", unix.AT_FDCWD, file, unix.O_NONBLOCK, true},
		{"relative", base, "child/value", 0, true},
		{"ancestor link", base, "link/value", 0, false},
		{"final link", base, "file-link", 0, false},
		{"parent traversal", base, "../child/value", 0, false},
		{"internal traversal", base, "child/../child/value", 0, false},
		{"absolute beneath fd", base, file, 0, false},
		{"write request", base, "child/value", unix.O_WRONLY, false},
		{"create request", base, "new", unix.O_CREAT, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := OpenReadNoSymlinks(tc.fd, tc.path, tc.flags)
			if err != nil {
				if tc.ok {
					t.Fatal(err)
				}
				return
			}
			f := os.NewFile(uintptr(fd), tc.path)
			defer f.Close()
			if !tc.ok {
				t.Fatal("unsafe path or flags accepted")
			}
			raw, err := io.ReadAll(f)
			if err != nil || string(raw) != "retained" {
				t.Fatalf("unexpected contents: %q, %v", raw, err)
			}
		})
	}
	// Replacing the base's pathname cannot redirect an already pinned directory.
	if err := os.Rename(dir, dir+"-retained"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir + "-retained") })
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	fd, err := OpenReadNoSymlinks(base, "child/value", 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "value")
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil || string(raw) != "retained" {
		t.Fatalf("pinned directory was redirected: %q, %v", raw, err)
	}
}
