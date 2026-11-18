package componentversions

import (
	"os"
	"runtime"
	"testing"
)

func TestBundledCatalogAndRequirements(t *testing.T) {
	document, err := Builtin()
	if err != nil {
		t.Fatalf("内置组件目录：%v", err)
	}
	for _, app := range []string{"frps", "fail2ban"} {
		versions := document.Applications[app]
		if len(versions) < 2 {
			t.Fatalf("%s has no historical selection", app)
		}
		if versions[0].Version.Version == versions[0].SoftwareVersion {
			t.Fatalf("%s does not separate package and software versions", app)
		}
		for _, v := range versions {
			if err = v.Version.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := Version{ID: "1.0.0", Version: "1.0.0", Channel: "stable", Architectures: []string{runtime.GOARCH}}
	if got := ApplyAvailability(old, "5.0.0"); got.Unavailable != "" {
		t.Fatalf("older component rejected: %+v", got)
	}
	old.MinimumCore = "6.0.0"
	if got := ApplyAvailability(old, "5.0.0"); got.Unavailable == "" {
		t.Fatal("minimum core requirement ignored")
	}
}

func TestInstalledHistoryAndCacheIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned version storage")
	}
	data, createErr := os.MkdirTemp("/root", "component-version-test-")
	if createErr != nil {
		t.Fatal(createErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(data) })
	current := Version{ID: "1.1.0", Version: "1.1.0", Channel: "stable"}
	previous := Version{ID: "1.0.0", Version: "1.0.0", Channel: "stable"}
	state := State{Current: &current, Previous: &previous, Image: "current", PreviousImage: "previous"}
	if err := SaveState(data, "builtin", "frps", state); err != nil {
		t.Fatal(err)
	}
	read, err := ReadState(data, "builtin", "frps")
	if err != nil || read.Current.ID != current.ID || read.Previous.ID != previous.ID || read.PreviousImage != "previous" {
		t.Fatalf("history lost: %+v %v", read, err)
	}
	q := Query{AppID: "frps", Channel: "stable", Page: 1}
	if err = SaveCatalog(data, q, Catalog{AppID: "fail2ban", Channel: "stable", Page: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadCatalog(data, q); err == nil {
		t.Fatal("cache for another component accepted")
	}
}
