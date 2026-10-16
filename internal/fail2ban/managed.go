package fail2ban

import (
	"regexp"
	"strings"
)

// Managed is an installation receipt. It does not attest to engine health,
// enabled jails, action readiness or traffic protection.
type Managed struct {
	Available     bool   `json:"available"`
	State         string `json:"state"`
	OperationID   string `json:"operation_id"`
	Version       string `json:"version"`
	PlanID        string `json:"plan_id"`
	AssetID       string `json:"asset_id"`
	Service       string `json:"service"`
	Socket        string `json:"socket"`
	PythonPath    string `json:"python_path"`
	PythonVersion string `json:"python_version"`
	ApprovedAt    int64  `json:"approved_at"`
	Reason        string `json:"reason"`
}

func UnknownManaged() Managed {
	return Managed{State: "unavailable", Reason: "受管引擎安装登记尚未读取"}
}

func ValidManaged(v Managed) bool {
	if len(v.Reason) > 1024 {
		return false
	}
	if !v.Available {
		return v.State == "unavailable" && v.OperationID == "" && v.Reason != ""
	}
	if v.State == "absent" {
		return v.OperationID == "" && v.ApprovedAt == 0
	}
	switch v.State {
	case "reserved", "ready", "installed", "interrupted", "rolling-back", "rolled-back":
	default:
		return false
	}
	return policyID.MatchString(v.OperationID) && v.Version == RegexVersion && len(v.PlanID) == 64 && strings.Trim(v.PlanID, "0123456789abcdef") == "" && v.AssetID != "" && len(v.AssetID) <= 128 && v.Service == "nginxpanel-fail2ban.service" && v.Socket == "/run/nginxpanel-fail2ban/fail2ban.sock" && regexp.MustCompile(`^/(usr/)?bin/python3(\.[0-9]{1,2})?$`).MatchString(v.PythonPath) && len(v.PythonVersion) <= 32 && v.ApprovedAt > 0
}
