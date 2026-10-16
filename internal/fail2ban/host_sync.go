package fail2ban

import (
	"strings"
	"time"
)

type HostInputSyncView struct {
	At                int64  `json:"at"`
	ID                string `json:"id"`
	SessionID         string `json:"session_id"`
	Enabled           bool   `json:"enabled"`
	ApprovedAt        int64  `json:"approved_at"`
	State             string `json:"state"`
	Queued            bool   `json:"queued"`
	CollectedAt       int64  `json:"collected_at"`
	ConfirmedAt       int64  `json:"confirmed_at"`
	SourceHash        string `json:"source_hash"`
	KernelOperationID string `json:"kernel_operation_id"`
	Reason            string `json:"reason"`
}

func EmptyHostInputSync(reason string) HostInputSyncView {
	return HostInputSyncView{At: time.Now().Unix(), State: "unavailable", Reason: reason}
}

func (v HostInputSyncView) Valid() bool {
	if v.At <= 0 || v.ApprovedAt < 0 || v.CollectedAt < 0 || v.ConfirmedAt < 0 || v.KernelOperationID != "" && !policyID.MatchString(v.KernelOperationID) || v.SourceHash != "" && (len(v.SourceHash) != 64 || strings.Trim(v.SourceHash, "0123456789abcdef") != "") {
		return false
	}
	if v.ID == "" {
		return !v.Enabled && !v.Queued && v.SessionID == "" && v.ApprovedAt == 0 && (v.State == "unavailable" || v.State == "disabled") && v.Reason != "" && v.CollectedAt == 0 && v.ConfirmedAt == 0 && v.SourceHash == "" && v.KernelOperationID == ""
	}
	if !policyID.MatchString(v.ID) || !policyID.MatchString(v.SessionID) || v.ApprovedAt == 0 {
		return false
	}
	if !v.Enabled {
		return v.State == "disabled" && !v.Queued && v.Reason != "" && v.CollectedAt == 0 && v.ConfirmedAt == 0 && v.SourceHash == "" && v.KernelOperationID == ""
	}
	if v.ID != v.SessionID {
		return false
	}
	switch v.State {
	case "current":
		return v.CollectedAt > 0 && v.ConfirmedAt >= v.CollectedAt && len(v.SourceHash) == 64 && v.KernelOperationID != "" && v.Reason == ""
	case "collecting":
		return true
	case "waiting", "stopping", "paused", "failed", "recovery_required":
		return v.Reason != ""
	}
	return false
}
