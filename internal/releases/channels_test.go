package releases

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIndependentReleaseSelections(t *testing.T) {
	for _, test := range []struct {
		name     string
		in       OnlineInput
		endpoint string
		accepted bool
	}{
		{"latest core", OnlineInput{Components: []string{"panel"}}, "latest", true},
		{"latest nginx", OnlineInput{Components: []string{"nginx"}}, "?per_page=100", true},
		{"pinned core", OnlineInput{Assets: []string{"panel-linux-amd64"}, Tag: "v2.0.0"}, "tags/v2.0.0", true},
		{"pinned nginx", OnlineInput{Assets: []string{"image-nginx"}, Tag: "nginx-v1.30.6"}, "tags/nginx-v1.30.6", true},
		{"wrong core channel", OnlineInput{Components: []string{"panel"}, Tag: "nginx-v1.30.6"}, "", false},
		{"wrong nginx channel", OnlineInput{Components: []string{"nginx"}, Tag: "v2.0.0"}, "", false},
		{"mixed components", OnlineInput{Components: []string{"panel", "nginx"}}, "", false},
		{"mixed assets", OnlineInput{Assets: []string{"panel-linux-amd64", "image-nginx"}}, "", false},
		{"implicit prerelease", OnlineInput{Components: []string{"nginx"}, AllowPrerelease: true}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateOnlineSelection(test.in)
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, expected %v: %v", err == nil, test.accepted, err)
			}
			if err == nil && test.in.metadataEndpoint() != test.endpoint {
				t.Fatalf("unexpected metadata endpoint: %s", test.in.metadataEndpoint())
			}
		})
	}
}

func TestImageDiscoveryDoesNotUseCoreLatest(t *testing.T) {
	base := githubRelease{ID: 1, Tag: "nginx-v1.30.5", PublishedAt: time.Now().UTC().Add(-time.Hour), Assets: []githubAsset{
		{ID: 1, Name: "release-manifest.json", State: "uploaded", Size: 1},
		{ID: 2, Name: "release-manifest.sig", State: "uploaded", Size: 1},
	}}
	newer := base
	newer.ID, newer.Tag, newer.PublishedAt = 2, "nginx-v1.30.6", base.PublishedAt.Add(time.Minute)
	core := newer
	core.ID, core.Tag, core.PublishedAt = 3, "v2.0.0", newer.PublishedAt.Add(time.Minute)
	preview := core
	preview.ID, preview.Tag, preview.Prerelease = 4, "nginx-v1.31.0-rc.1", true
	draft := core
	draft.ID, draft.Tag, draft.Draft = 5, "nginx-v1.31.0", true
	in := OnlineInput{Components: []string{"nginx"}}
	raw, _ := json.Marshal([]githubRelease{preview, core, base, draft, newer})
	got, err := discoverRelease(raw, in)
	if err != nil || got.Tag != newer.Tag {
		t.Fatalf("component discovery chose %q: %v", got.Tag, err)
	}
	raw, _ = json.Marshal([]githubRelease{core, preview, draft})
	if _, err := discoverRelease(raw, in); err == nil {
		t.Fatal("must not fall back to core, draft or prerelease")
	}
	in.Tag, in.AllowPrerelease = preview.Tag, true
	raw, _ = json.Marshal(preview)
	if _, err := discoverRelease(raw, in); err != nil {
		t.Fatalf("explicit component prerelease: %v", err)
	}
}

func TestIndependentPublicationCatalogs(t *testing.T) {
	core, err := NewPublication("validation/nginxpanel", "2.0.0", strings.Repeat("a", 40), "Core release", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range core.Packages {
		a := source.Asset
		a.SHA256, a.Size, a.UnpackedBytes = strings.Repeat("b", 64), 1, 3
		a.Files = []File{{Path: "nginxpanel", SHA256: a.SHA256, Size: 1, Mode: 0755}, {Path: "LICENSE", SHA256: a.SHA256, Size: 1, Mode: 0644}, {Path: "THIRD_PARTY_NOTICES.txt", SHA256: a.SHA256, Size: 1, Mode: 0644}}
		core.Manifest.Assets = append(core.Manifest.Assets, a)
	}
	image, err := NewImagePublication("validation/nginxpanel", "1.30.6", strings.Repeat("c", 40), "Nginx release", false)
	if err != nil || len(image.Packages) != 0 {
		t.Fatalf("image release must not require core archives: %v", err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	image.Manifest.Images = []ContainerImage{{ID: "nginx", Repository: "ghcr.io/validation/nginxpanel/nginx", Version: "1.30.6", Commit: image.Commit, Digest: digest,
		Platforms: []ImagePlatform{{OS: "linux", Architecture: "amd64", Digest: digest, ConfigDigest: digest, LauncherProtocol: LauncherVersion}, {OS: "linux", Architecture: "arm64", Digest: digest, ConfigDigest: digest, LauncherProtocol: LauncherVersion}},
		Evidence:  File{Path: "nginx.oci.json", SHA256: strings.Repeat("e", 64), Size: 1, Mode: 0644}}}
	for _, manifest := range []Manifest{core.Manifest, image.Manifest} {
		if _, err := manifestCatalog(manifest); err != nil {
			t.Fatalf("independent catalog rejected: %v", err)
		}
	}
	if ManifestTag(core.Manifest) != "v2.0.0" || ManifestTag(image.Manifest) != "nginx-v1.30.6" {
		t.Fatal("independent release identities were lost")
	}
	core.Manifest.Images = image.Manifest.Images
	core.Manifest.Images[0].Version = core.Manifest.Version
	if _, err := manifestCatalog(core.Manifest); err == nil {
		t.Fatal("mixed core/image publication must be rejected")
	}
}
