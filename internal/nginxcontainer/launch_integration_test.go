package nginxcontainer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

// This prepares an installer-owned record in a private Docker volume for the
// real image entry point. Approval provenance is synthetic: these cases test
// launcher execution and hash rejection, not signature or registry admission.
func TestPrepareNginxLauncherFixture(t *testing.T) {
	mode := os.Getenv("NGINXPANEL_TEST_PREPARE_LAUNCHER")
	if mode == "" {
		t.Skip("requires an isolated launcher fixture container")
	}
	if mode != "valid" && mode != "bad-launcher" && mode != "bad-nginx" {
		t.Fatal("unknown launcher fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("fixture preparation requires root in an isolated Docker container")
	}
	data := "/srv/nginxpanel"
	fixtureHash := secure.Hash([]byte("isolated launcher fixture; not a signed release"))
	b := Binding{Schema: Schema, DataDir: data, Image: "ghcr.io/validation/nginxpanel/nginx@sha256:" + fixtureHash, ImageID: os.Getenv("NGINXPANEL_TEST_IMAGE_ID"), Architecture: runtime.GOARCH, UID: 1000, GID: 1000, BoundAt: time.Now().Unix()}
	var err error
	b.BinarySHA256, err = secure.HashRootFile(Binary, binaryLimit)
	if err != nil {
		t.Fatal(err)
	}
	b.BootstrapSHA256, err = secure.HashRootFile(Bootstrap, binaryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "bad-launcher" {
		b.BootstrapSHA256 = fixtureHash
	}
	if mode == "bad-nginx" {
		b.BinarySHA256 = fixtureHash
	}
	build, err := os.ReadFile("/usr/share/nginxpanel/nginx-build.txt")
	if err != nil {
		t.Fatal(err)
	}
	b.Build = string(build)
	capabilities, err := os.ReadFile("/usr/share/nginxpanel/capabilities.json")
	if err != nil || json.Unmarshal(capabilities, &b.Capabilities) != nil {
		t.Fatal("cannot read image capabilities")
	}
	b.SignedImage = releases.ImageApproval{
		Schema: releases.Schema, Repository: "validation/nginxpanel", Version: "0.1.0", Commit: strings.Repeat("1", 40),
		KeyID: "fixture", ManifestSHA256: fixtureHash, TrustSHA256: fixtureHash, TrustPath: "/etc/nginxpanel/release-trust.json", ApprovedAt: b.BoundAt,
		Image: releases.ImageChoice{ID: "nginx", Reference: b.Image,
			Platform: releases.ImagePlatform{OS: "linux", Architecture: runtime.GOARCH, Digest: "sha256:" + fixtureHash, ConfigDigest: b.ImageID, LauncherSHA256: b.BootstrapSHA256},
			Evidence: releases.File{Path: "nginx.oci.json", SHA256: fixtureHash, Size: 1, Mode: 0644}},
	}
	for _, name := range []string{"bin/components", "nginx/active", "nginx/tmp", "certificates", "run", "logs"} {
		if err := os.MkdirAll(filepath.Join(data, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nginx/tmp/client", "nginx/tmp/proxy", "nginx/tmp/fastcgi", "nginx/tmp/uwsgi", "nginx/tmp/scgi", "run/nginx"} {
		path := filepath.Join(data, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, b.UID, b.GID); err != nil {
			t.Fatal(err)
		}
	}
	config := "worker_processes 1;\npid " + data + "/run/nginx/nginx.pid;\nerror_log stderr notice;\nevents { worker_connections 64; }\nhttp {\n    access_log off;\n"
	for _, kind := range []struct{ directive, directory string }{{"client_body", "client"}, {"proxy", "proxy"}, {"fastcgi", "fastcgi"}, {"uwsgi", "uwsgi"}, {"scgi", "scgi"}} {
		config += "    " + kind.directive + "_temp_path " + data + "/nginx/tmp/" + kind.directory + ";\n"
	}
	config += "    server { listen 127.0.0.1:80; location / { return 200 launcher-ok; } }\n}\n"
	if err := os.WriteFile(filepath.Join(data, "nginx/active/nginx.conf"), []byte(config), 0444); err != nil {
		t.Fatal(err)
	}
	path, err := Path(data)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(canonical(b)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(data); err != nil {
		t.Fatal(err)
	}
}
