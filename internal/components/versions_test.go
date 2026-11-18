package components

import (
	"testing"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
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
