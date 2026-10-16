package fail2ban

import (
	"time"

	"nginxpanel/internal/firewall"
)

// This is an observation of the owned kernel object, not a promise that a
// previously sampled engine set is still current or that automation is active.
type HostInputRuntimeView struct {
	At             int64  `json:"at"`
	State          string `json:"state"`
	Verified       bool   `json:"verified"`
	OperationID    string `json:"operation_id"`
	Action         string `json:"action"`
	OperationState string `json:"operation_state"`
	UpdatedAt      int64  `json:"updated_at"`
	BannedCount    int    `json:"banned_count"`
	ProtectedCount int    `json:"protected_count"`
	Reason         string `json:"reason"`
}

func EmptyHostInputRuntime(reason string) HostInputRuntimeView {
	return HostInputRuntimeView{At: time.Now().Unix(), State: "unavailable", Reason: reason}
}

func (v HostInputRuntimeView) Valid() bool {
	if v.At <= 0 || v.UpdatedAt < 0 || v.BannedCount < 0 || v.BannedCount > firewall.NFTBanLimit || v.ProtectedCount < 0 || v.ProtectedCount > firewall.NFTBanProtectionLimit {
		return false
	}
	if v.OperationID == "" {
		return (v.State == "unavailable" || v.State == "uninitialized") && !v.Verified && v.Action == "" && v.OperationState == "" && v.UpdatedAt == 0 && v.BannedCount == 0 && v.ProtectedCount == 0 && v.Reason != ""
	}
	if !policyID.MatchString(v.OperationID) || v.UpdatedAt == 0 || v.Action != "apply" && v.Action != "clear" {
		return false
	}
	switch v.OperationState {
	case "running", "recovery_required", "succeeded", "failed":
	default:
		return false
	}
	switch v.State {
	case "empty", "applied":
		return v.Verified && (v.OperationState == "succeeded" || v.OperationState == "failed") && (v.State != "empty" || v.BannedCount == 0 && v.ProtectedCount == 0)
	case "unavailable", "recovery_required", "missing", "drifted":
		return !v.Verified && v.BannedCount == 0 && v.ProtectedCount == 0 && v.Reason != ""
	}
	return false
}
