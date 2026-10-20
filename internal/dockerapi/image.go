package dockerapi

import "strings"

// MatchesImageID handles both daemon stores: classic image IDs are config
// digests, while containerd IDs are the manifest/index target digest. Callers
// must authenticate the digest reference and platform before using this match.
func MatchesImageID(reference, configDigest, actualID string) bool {
	if actualID == "" || configDigest == "" {
		return false
	}
	if actualID == configDigest {
		return true
	}
	_, target, ok := strings.Cut(reference, "@")
	return ok && actualID == target
}
