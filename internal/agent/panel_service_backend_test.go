package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginxpanel/internal/panelruntime"
)

func TestNativeCoreProcessUsesInstalledEntryForSelectedRelease(t *testing.T) {
	snapshot := panelruntime.Snapshot{Directory: t.TempDir(), Deployment: panelruntime.Deployment{DataDir: "/srv/nginxpanel"}}
	release := filepath.Join(snapshot.Directory, "nginxpanel")
	if err := os.WriteFile(release, []byte("core"), 0555); err != nil {
		t.Fatal(err)
	}
	live, err := os.Stat(release)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"/opt/nginxpanel/current/nginxpanel", "core", "--data-dir", snapshot.Deployment.DataDir,
		"--allowed-uid", "0", "--nginx-container", "--nginx-user", "nginxpanel-nginx", "--nginx-modules",
		"/etc/nginxpanel/nginx-modules.json", "--metrics-scope", "host", "--component-scope", "host", "--maintenance-scope", "host",
	}
	cmdline := func() []byte { return []byte(strings.Join(args, "\x00") + "\x00") }
	if err := validateNativeCoreProcess(snapshot, live, cmdline()); err != nil {
		t.Fatalf("installed entry with selected binary: %v", err)
	}
	args[1] = "serve"
	if err := validateNativeCoreProcess(snapshot, live, cmdline()); err == nil {
		t.Fatal("selected binary with altered arguments was accepted")
	}
}
