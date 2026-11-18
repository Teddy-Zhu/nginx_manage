package components

import (
	"path/filepath"
	"testing"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/software"
)

func TestNginxVersionDistinguishesEngineAndInstaller(t *testing.T) {
	binding := nginxcontainer.Binding{
		Capabilities: nginxcontainer.Capabilities{Version: "1.30.6"},
		SignedImage:  releases.ImageApproval{Version: "2.0.1"},
	}
	got := NginxVersion(binding)
	if got == nil || got.ID != "nginx-v2.0.1" || got.Version != "2.0.1" || got.SoftwareVersion != "1.30.6" {
		t.Fatalf("unexpected component and engine versions: %+v", got)
	}
	binding.SignedImage.LocalBuild = true
	if got := NginxVersion(binding); got != nil {
		t.Fatalf("offline installer version reported as a component release: %+v", got)
	}
}

func TestBundledNginxSelectableWithoutRemoteCatalog(t *testing.T) {
	temp := t.TempDir()
	data := filepath.Join("/srv", filepath.Base(filepath.Dir(temp)))
	bundled := componentversions.Version{ID: componentversions.BundledNginxID, Version: "1.30.6", SoftwareVersion: "1.30.6", Channel: "stable"}
	m := Manager{DataDir: data, TrustPath: filepath.Join(temp, "missing-trust.json"),
		BundledNginxVersion: func() (*componentversions.Version, error) { return &bundled, nil }}
	out, err := m.Versions(t.Context(), componentversions.Query{AppID: "nginx", Channel: "stable", Page: 1})
	if err != nil || out.Error == "" || len(out.Versions) != 1 || out.Versions[0].ID != bundled.ID {
		t.Fatalf("offline catalog = %+v, %v", out, err)
	}

	input := Input{Action: "software", Software: &software.Request{Action: "install-nginx"}}
	if input.Validate() != nil || input.validateSubmission() == nil {
		t.Fatal("expected an explicit version for new tasks, while retaining existing receipts")
	}
	for _, version := range []string{bundled.ID, "nginx-v2.0.1", "nginx-v2.0.2-dev"} {
		input.Software.Version = version
		if err := input.validateSubmission(); err != nil {
			t.Fatalf("selected version %q rejected: %v", version, err)
		}
	}
}
