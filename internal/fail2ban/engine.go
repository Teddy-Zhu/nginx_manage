package fail2ban

import (
	"regexp"
	"strings"
)

// EngineIdentity identifies code provenance, never ownership of a jail or
// evidence that an action protects a particular traffic path.
type EngineIdentity struct {
	Owner          string `json:"owner"`
	InstallationID string `json:"installation_id"`
	PlanID         string `json:"plan_id"`
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	PythonPath     string `json:"python_path"`
	PythonSHA256   string `json:"python_sha256"`
}

var enginePython = regexp.MustCompile(`^/(usr/)?bin/python3(\.[0-9]{1,2})?$`)

func ValidEngineIdentity(e EngineIdentity) bool {
	if e.Owner != "managed" {
		return (e.Owner == "existing" || e.Owner == "none" || e.Owner == "unavailable") && e.InstallationID == "" && e.PlanID == "" && e.AssetID == "" && e.ManifestSHA256 == "" && e.PythonPath == "" && e.PythonSHA256 == ""
	}
	for _, hash := range []string{e.PlanID, e.ManifestSHA256, e.PythonSHA256} {
		if len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
			return false
		}
	}
	return policyID.MatchString(e.InstallationID) && e.AssetID != "" && len(e.AssetID) <= 128 && !strings.ContainsAny(e.AssetID, "/\\\x00") && enginePython.MatchString(e.PythonPath)
}
