package fail2ban

import (
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/firewall"
)

// Ready means a complete current engine sample, never a kernel enforcement
// receipt. Calendar strings from an existing server do not prove UTC expiry.
type HostInputSourcesView struct {
	Managed        bool     `json:"managed"`
	At             int64    `json:"at"`
	State          string   `json:"state"`
	ID             string   `json:"id"`
	ApprovedAt     int64    `json:"approved_at"`
	Jails          []string `json:"jails"`
	CollectedAt    int64    `json:"collected_at"`
	SourceHash     string   `json:"source_hash"`
	TimeBasis      string   `json:"time_basis"`
	BannedCount    int      `json:"banned_count"`
	ProtectedCount int      `json:"protected_count"`
	Reason         string   `json:"reason"`
}

func EmptyHostInputSources(reason string) HostInputSourcesView {
	return HostInputSourcesView{At: time.Now().Unix(), State: "unavailable", Jails: []string{}, TimeBasis: "engine-current", Reason: reason}
}

func (v HostInputSourcesView) Valid() bool {
	if v.At <= 0 || v.ApprovedAt < 0 || v.CollectedAt < 0 || v.TimeBasis != "engine-current" || v.Jails == nil || len(v.Jails) > MaxJails || v.BannedCount < 0 || v.ProtectedCount < 0 || v.BannedCount+v.ProtectedCount > firewall.NFTBanLimit || !sort.StringsAreSorted(v.Jails) {
		return false
	}
	for i, jail := range v.Jails {
		if len(jail) == 0 || len(jail) > 64 || i > 0 && jail == v.Jails[i-1] {
			return false
		}
	}
	switch v.State {
	case "unavailable", "unapproved", "stale", "revoked", "ready":
	default:
		return false
	}
	if v.State == "ready" {
		return policyID.MatchString(v.ID) && v.ApprovedAt > 0 && (len(v.Jails) > 0 || v.Managed) && v.CollectedAt > 0 && len(v.SourceHash) == 64 && strings.Trim(v.SourceHash, "0123456789abcdef") == "" && v.Reason == ""
	}
	if v.Reason == "" || v.CollectedAt != 0 || v.SourceHash != "" || v.BannedCount != 0 || v.ProtectedCount != 0 {
		return false
	}
	if v.ID == "" {
		return (v.State == "unavailable" || v.State == "unapproved") && v.ApprovedAt == 0 && len(v.Jails) == 0 && !v.Managed
	}
	return policyID.MatchString(v.ID) && v.ApprovedAt > 0 && (v.State == "revoked" && len(v.Jails) == 0 && !v.Managed || (v.State == "unavailable" || v.State == "stale") && (len(v.Jails) > 0 || v.Managed))
}
