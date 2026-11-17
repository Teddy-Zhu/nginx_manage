package releases

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrimpathCorePublicationRequiresVerifiedRuntimeVersion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("core release assets target Linux")
	}
	root := publicationPolicyTestDir(t)
	source := filepath.Join(root, "source")
	directory := filepath.Join(root, "package")
	for _, path := range []string{filepath.Join(source, "cmd/nginxpanel"), directory} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(source, "go.mod"), []byte("module nginxpanel\n\ngo 1.27.0\n"))
	write(filepath.Join(source, "cmd/nginxpanel/main.go"), []byte(`package main
import "encoding/json"
import "os"
var version string
func main() { json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version}) }
`))
	command := func(program string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(program, args...)
		cmd.Dir = source
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", program, args, err, out)
		}
		return out
	}
	command("git", "init", "-q")
	command("git", "add", ".")
	command("git", "-c", "user.name=Release test", "-c", "user.email=release@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
	commit := strings.TrimSpace(string(command("git", "rev-parse", "HEAD")))
	binary := filepath.Join(directory, "nginxpanel")
	command("go", "build", "-trimpath", "-buildvcs=true", "-ldflags", "-s -w -X main.version=1.2.3", "-o", binary, "./cmd/nginxpanel")
	var reported struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(command(binary, "version"), &reported); err != nil || reported.Version != "1.2.3" {
		t.Fatalf("unexpected runtime version: %q, %v", reported.Version, err)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	asset := Asset{ID: "panel-linux-" + runtime.GOARCH, Component: "panel", Version: "1.2.3", Architecture: runtime.GOARCH, Files: []File{{Path: "nginxpanel", SHA256: hash(raw)}}}
	spec := PublicationSpec{Commit: commit, Manifest: Manifest{Repository: "validation/nginxpanel", Version: asset.Version}}
	write(filepath.Join(directory, asset.ID+".spdx.json"), []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{}]}`))
	provenance := BuildProvenance{
		Schema: Schema, Repository: spec.Manifest.Repository, Version: asset.Version, Commit: commit,
		Asset: asset.ID, Scope: "source-and-build-dependencies", GoVersion: runtime.Version(),
		NodeVersion: "v24.0.0", PNPMVersion: "10.0.0", WorkflowRun: "1/1",
		GoSumSHA256: strings.Repeat("a", 64), WebLockSHA256: strings.Repeat("b", 64), BinarySHA256: hash(raw),
	}
	for _, test := range []struct {
		name, version, digest, runtimeHash, architecture, errorText string
	}{
		{"verified trimpath binary", reported.Version, hash(raw), hash(raw), runtime.GOARCH, ""},
		{"missing runtime version", "", hash(raw), hash(raw), runtime.GOARCH, "运行版本"},
		{"wrong runtime version", "1.2.4", hash(raw), hash(raw), runtime.GOARCH, "运行版本"},
		{"wrong binary hash", reported.Version, strings.Repeat("0", 64), hash(raw), runtime.GOARCH, "未绑定实际面板二进制"},
		{"wrong runtime binary hash", reported.Version, hash(raw), strings.Repeat("0", 64), runtime.GOARCH, "二进制散列"},
		{"wrong architecture", reported.Version, hash(raw), hash(raw), "wrong", "Go 构建信息"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provenance.BinarySHA256 = test.digest
			asset.Architecture = test.architecture
			installed := ContainerPackage{Schema: Schema, Version: test.version, Architecture: test.architecture, BinarySHA256: test.runtimeHash, LauncherProtocol: LauncherVersion, Images: map[string]string{"nginx": "sha256:" + strings.Repeat("c", 64)}}
			raw, err := json.Marshal(installed)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(directory, "containers.json"), raw)
			raw, err = json.Marshal(provenance)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(directory, asset.ID+".provenance.json"), raw)
			_, err = publicationEvidence(directory, asset, spec)
			if test.errorText == "" && err != nil || test.errorText != "" && (err == nil || !strings.Contains(err.Error(), test.errorText)) {
				t.Fatalf("expected %q, got %v", test.errorText, err)
			}
		})
	}
	if err := os.Remove(filepath.Join(directory, "containers.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := publicationEvidence(directory, asset, spec); err == nil || !strings.Contains(err.Error(), "读取原生安装清单") {
		t.Fatalf("missing runtime inventory must fail: %v", err)
	}
}
