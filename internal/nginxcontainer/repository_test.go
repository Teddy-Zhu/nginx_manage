package nginxcontainer

import "testing"

func TestDockerHubRepositoryDigestAliases(t *testing.T) {
	const canonical = "team/nginx@sha256:abc"
	for _, value := range []string{"team/nginx@sha256:abc", "docker.io/team/nginx@sha256:abc", "index.docker.io/team/nginx@sha256:abc", "docker.io/team/nginx:v1.0.0@sha256:abc"} {
		if got := repositoryDigest(value); got != canonical {
			t.Fatalf("%s normalized to %s", value, got)
		}
	}
	for _, value := range []string{"ghcr.io/team/nginx@sha256:abc", "registry.example:5000/team/nginx@sha256:abc", "team/nginx@sha256:other", "other/nginx@sha256:abc"} {
		if repositoryDigest(value) == canonical {
			t.Fatalf("different registry or content matched: %s", value)
		}
	}
}
