package releases

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestImageApprovalDaemonIdentity(t *testing.T) {
	index := "sha256:" + strings.Repeat("a", 64)
	config := "sha256:" + strings.Repeat("b", 64)
	platform := "sha256:" + strings.Repeat("c", 64)
	launcher := strings.Repeat("d", 64)
	reference := "ghcr.io/validation/nginxpanel/nginx@" + index
	approval := ImageApproval{
		Schema: Schema, Repository: "validation/nginxpanel", Version: "0.1.0", Commit: strings.Repeat("e", 40),
		KeyID: "test", ManifestSHA256: launcher, TrustSHA256: launcher, TrustPath: "/etc/nginxpanel/release-trust.json", ApprovedAt: time.Now().Unix(),
		Image: ImageChoice{ID: "nginx", Reference: reference,
			Platform: ImagePlatform{OS: "linux", Architecture: runtime.GOARCH, Digest: platform, ConfigDigest: config, LauncherSHA256: launcher},
			Evidence: File{Path: "nginx.oci.json", SHA256: launcher, Size: 1, Mode: 0644}},
	}
	for _, test := range []struct {
		name, id string
		accepted bool
	}{
		{"classic config", config, true},
		{"containerd index", index, true},
		{"platform is not the bound target", platform, false},
		{"unapproved content", "sha256:" + strings.Repeat("f", 64), false},
		{"missing identity", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := approval.Validate("nginx", reference, test.id, launcher)
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
		})
	}
}
