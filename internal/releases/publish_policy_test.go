package releases

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func publicationPolicyTestDir(t *testing.T) string {
	t.Helper()
	// The publisher rejects shared temporary ancestors such as /tmp or caches.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", home)
	return t.TempDir()
}

func TestPublicationPolicyRequiresExplicitVersionDecision(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		accepted  bool
		rollback  bool
	}{
		{"approved", `{"version":"1.2.3","automatic_rollback":true}`, true, true},
		{"declined", `{"version":"1.2.3","automatic_rollback":false}`, true, false},
		{"different version", `{"version":"1.2.4","automatic_rollback":true}`, false, false},
		{"missing version", `{"automatic_rollback":true}`, false, false},
		{"missing decision", `{"version":"1.2.3"}`, false, false},
		{"null decision", `{"version":"1.2.3","automatic_rollback":null}`, false, false},
		{"string decision", `{"version":"1.2.3","automatic_rollback":"true"}`, false, false},
		{"unknown field", `{"version":"1.2.3","automatic_rollback":true,"approved":true}`, false, false},
		{"duplicate decision", `{"version":"1.2.3","automatic_rollback":false,"automatic_rollback":true}`, false, false},
		{"case alias", `{"version":"1.2.3","AUTOMATIC_ROLLBACK":true}`, false, false},
		{"over budget", `{"version":"1.2.3","automatic_rollback":true}` + strings.Repeat(" ", 4<<10), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := filepath.Join(publicationPolicyTestDir(t), "policy.json")
			if err := os.WriteFile(name, []byte(test.raw), 0600); err != nil {
				t.Fatal(err)
			}
			rollback, err := ReadPublicationPolicy(name, "1.2.3")
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
			if test.accepted {
				spec, err := NewPublication("validation/nginxpanel", "1.2.3", strings.Repeat("a", 40), "Reviewed release", rollback)
				if err != nil || spec.Manifest.AutomaticRollback != test.rollback {
					t.Fatalf("generated rollback=%v, want %v: %v", spec.Manifest.AutomaticRollback, test.rollback, err)
				}
			}
		})
	}
}

func TestPublishRechecksIndependentPolicy(t *testing.T) {
	for _, test := range []struct {
		name                       string
		built, approved, fromBuild bool
		errorText                  string
	}{
		{"approval withdrawn", true, false, false, "与独立批准的版本策略不一致"},
		{"build declined rollback", false, true, false, "与独立批准的版本策略不一致"},
		{"artifact policy", true, true, true, "独立发布策略须位于构建输入与输出树之外"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := publicationPolicyTestDir(t)
			input := filepath.Join(root, "input")
			if err := os.Mkdir(input, 0700); err != nil {
				t.Fatal(err)
			}
			policy := filepath.Join(root, "approved.json")
			if test.fromBuild {
				policy = filepath.Join(input, "policy.json")
			}
			if err := os.WriteFile(policy, []byte(fmt.Sprintf(`{"version":"1.2.3","automatic_rollback":%t}`, test.approved)), 0600); err != nil {
				t.Fatal(err)
			}
			spec, err := NewPublication("validation/nginxpanel", "1.2.3", strings.Repeat("a", 40), "Reviewed release", test.built)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(input, "publication.json")
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			output := filepath.Join(root, "release")
			_, err = Publish(context.Background(), PublishInput{
				InputRoot: input, SpecPath: name, Output: output, PolicyPath: policy,
				Repository: spec.Manifest.Repository, Version: spec.Manifest.Version, Commit: spec.Commit,
				KeyPath: filepath.Join(root, "unopened.seed"), KeyID: "test",
				PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			})
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("want policy rejection %q, got %v", test.errorText, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("policy rejection created release output: %v", err)
			}
		})
	}
}
