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
			Platform: ImagePlatform{OS: "linux", Architecture: runtime.GOARCH, Digest: platform, ConfigDigest: config, LauncherProtocol: LauncherVersion},
			Evidence: File{Path: "nginx.oci.json", SHA256: launcher, Size: 1, Mode: 0644}},
	}
	for _, test := range []struct {
		name, id string
		accepted bool
		mutate   func(*ImageApproval)
	}{
		{"classic config", config, true, nil},
		{"containerd index", index, true, nil},
		{"Docker Hub signed image", config, true, func(a *ImageApproval) { a.Image.Reference = "docker.io/team/nginxpanel-nginx@" + index }},
		{"unapproved registry", config, false, func(a *ImageApproval) { a.Image.Reference = "registry.example/team/nginx@" + index }},
		{"Docker Hub hostname spoof", config, false, func(a *ImageApproval) { a.Image.Reference = "docker.io.example/team/nginx@" + index }},
		{"tag cannot replace digest", config, false, func(a *ImageApproval) { a.Image.Reference = "docker.io/team/nginxpanel-nginx:v1.0.0" }},
		{"platform is not the bound target", platform, false, nil},
		{"unapproved content", "sha256:" + strings.Repeat("f", 64), false, nil},
		{"missing identity", "", false, nil},
		{"unsupported launcher protocol", config, false, func(a *ImageApproval) { a.Image.Platform.LauncherProtocol = LauncherVersion + 1 }},
		{"unbound launcher hash", config, false, func(a *ImageApproval) { a.Image.Platform.LauncherSHA256 = launcher }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := approval
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			err := candidate.Validate("nginx", candidate.Image.Reference, test.id, launcher)
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
		})
	}
}

func TestLocalImageApprovalOriginAndContent(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	launcher, manifest := strings.Repeat("b", 64), strings.Repeat("c", 64)
	base := ImageApproval{LocalBuild: true, Schema: Schema, Version: "0.1.0-dev", ManifestSHA256: manifest, TrustSHA256: manifest,
		TrustPath: "/opt/nginxpanel/installer/containers.json", ApprovedAt: time.Now().Unix(),
		Image: ImageChoice{ID: "nginx", Reference: id, Platform: ImagePlatform{OS: "linux", Architecture: runtime.GOARCH, ConfigDigest: id, LauncherProtocol: LauncherVersion, LauncherSHA256: launcher},
			Evidence: File{Path: "containers.json", SHA256: manifest, Size: 100, Mode: 0644}}}
	if err := base.Validate("nginx", id, id, launcher); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*ImageApproval)
	}{
		{"cannot claim publisher signature", func(a *ImageApproval) { a.LocalBuild = false }},
		{"cannot mix publisher identity", func(a *ImageApproval) { a.Repository = "example/panel" }},
		{"cannot replace content", func(a *ImageApproval) { a.Image.Platform.ConfigDigest = "sha256:" + manifest }},
		{"cannot replace program", func(a *ImageApproval) { a.Image.Platform.LauncherSHA256 = manifest }},
		{"cannot replace inventory", func(a *ImageApproval) { a.Image.Evidence.SHA256 = launcher }},
		{"cannot use registry reference", func(a *ImageApproval) { a.Image.Reference = "example/nginx@" + id }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := base
			test.edit(&a)
			if err := a.Validate("nginx", a.Image.Reference, id, launcher); err == nil {
				t.Fatal("accepted a mismatched approval")
			}
		})
	}
}
