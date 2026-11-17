package software

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"nginxpanel/internal/componentversions"
)

func testVersionSource() Source {
	write := Action{Command: []string{"/bin/sh", "-c", `printf '%s' "$NGINXPANEL_TARGET_VERSION" > .actual; if [ "$NGINXPANEL_TARGET_VERSION" = 1.2.0 ]; then exit 1; fi`}}
	return Source{Schema: 1, ID: "example", Name: "example", Applications: []Application{{ID: "demo", Name: "demo", Versions: []componentversions.Version{
		{ID: "release-1", Version: "1.0.0", Channel: "stable"}, {ID: "release-2", Version: "1.1.0", Channel: "stable"}, {ID: "broken", Version: "1.2.0", Channel: "stable"}, {ID: "future", Version: "1.3.0", Channel: "stable", MinimumCore: "9.0.0"},
	}, Actions: map[string]Action{
		"install": write, "update": write,
		"uninstall": {Command: []string{"/bin/sh", "-c", "rm -f .actual"}},
		"status":    {Command: []string{"/bin/sh", "-c", `printf '{"state":"running","version":"%s"}\n' "$(cat .actual)"`}},
		"backup":    {Command: []string{"/bin/sh", "-c", "cp .actual .backup"}},
		"restore":   {Command: []string{"/bin/sh", "-c", `cp .backup .actual; printf '%s:%s' "$NGINXPANEL_TARGET_VERSION_ID" "$NGINXPANEL_PREVIOUS_VERSION_ID" > .restored`}},
	}}}}
}
func versionTestData(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned software storage")
	}
	dir, err := os.MkdirTemp("/root", "software-version-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestVersionedLifecycleDowngradeAndRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned software storage")
	}
	ctx := context.Background()
	data := versionTestData(t)
	source := testVersionSource()
	if _, err := RunWithCore(ctx, data, "2.0.0", Request{Action: "import", Source: &source}, nil); err != nil {
		t.Fatal(err)
	}
	var progress []string
	for i, id := range []string{"release-1", "release-2", "release-1"} {
		action := "update"
		if i == 0 {
			action = "install"
		}
		if _, err := RunWithCore(ctx, data, "2.0.0", Request{Action: action, SourceID: "example", AppID: "demo", Version: id}, func(text string) { progress = append(progress, text) }); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(strings.Join(progress, "\n"), "不兼容") {
		t.Fatal("downgrade risk was not reported")
	}
	catalog, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	installed := catalog.Installed[0]
	if installed.Version.Version != "1.0.0" || installed.Previous.Version != "1.1.0" {
		t.Fatalf("wrong history: %+v", installed)
	}
	_, err = RunWithCore(ctx, data, "2.0.0", Request{Action: "update", SourceID: "example", AppID: "demo", Version: "broken"}, nil)
	if err == nil || !strings.Contains(err.Error(), "已恢复原版本") {
		t.Fatalf("missing recovery result: %v", err)
	}
	actual, err := os.ReadFile(applicationDirectory(data, "example", "demo") + "/.actual")
	if err != nil || string(actual) != "1.0.0" {
		t.Fatalf("runtime was not restored: %s %v", actual, err)
	}
	restored, err := os.ReadFile(applicationDirectory(data, "example", "demo") + "/.restored")
	if err != nil || string(restored) != "release-1:broken" {
		t.Fatalf("incorrect recovery environment: %s %v", restored, err)
	}
	catalog, err = Read(data)
	if err != nil || catalog.Installed[0].Version.Version != "1.0.0" {
		t.Fatalf("failed version recorded: %+v %v", catalog, err)
	}
	if _, err = RunWithCore(ctx, data, "2.0.0", Request{Action: "update", SourceID: "example", AppID: "demo", Version: "future"}, nil); err == nil {
		t.Fatal("unsupported core version accepted")
	}
	if err = (Request{Action: "update-panel", Version: "1.0.0", PlanID: strings.Repeat("a", 64)}).Validate(); err == nil {
		t.Fatal("component version selector accepted for panel core")
	}
}

func TestRemoteVersionPaginationAndCachedFallback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned software storage")
	}
	var hits atomic.Int32
	var offline atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if offline.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		versions := []componentversions.Version{}
		for i := 0; i < 25; i++ {
			version := fmt.Sprintf("1.0.%d", i)
			versions = append(versions, componentversions.Version{ID: version, Version: version, Channel: "stable"})
		}
		_ = json.NewEncoder(w).Encode(versionDocument{Schema: 1, Versions: versions})
	}))
	defer server.Close()
	source := testVersionSource()
	source.Applications[0].Versions = nil
	source.Applications[0].VersionsURL = server.URL
	data := versionTestData(t)
	ctx := context.Background()
	if _, err := Run(ctx, data, Request{Action: "import", Source: &source}, nil); err != nil {
		t.Fatal(err)
	}
	q := componentversions.Query{SourceID: "example", AppID: "demo", Channel: "stable", Page: 1}
	first, err := Versions(ctx, data, "2.0.0", q)
	if err != nil || len(first.Versions) != 20 || !first.HasMore || first.Versions[0].Version != "1.0.24" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	q.Page = 2
	second, err := Versions(ctx, data, "2.0.0", q)
	if err != nil || len(second.Versions) != 5 || second.HasMore || hits.Load() != 1 {
		t.Fatalf("cached second page: %+v %v hits=%d", second, err, hits.Load())
	}
	offline.Store(true)
	q.Refresh = true
	fallback, err := Versions(ctx, data, "2.0.0", q)
	if err != nil || !fallback.Cached || fallback.Error == "" || len(fallback.Versions) != 5 {
		t.Fatalf("offline fallback: %+v %v", fallback, err)
	}
}
