package fail2ban

import (
	"context"
	"encoding/json"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

type UpgradeInput struct {
	Action        string `json:"action"`
	PlanID        string `json:"plan_id"`
	AssetID       string `json:"asset_id"`
	Prerelease    bool   `json:"prerelease"`
	Target        string `json:"target"`
	PreparationID string `json:"preparation_id"`
}

func (in UpgradeInput) Validate() error {
	if in.Action == "run" {
		if in.PlanID != "" || in.AssetID != "" || in.Prerelease || !policyID.MatchString(in.PreparationID) || !upgradeDigest(in.Target) {
			return fault.Invalid("升级须引用已完成的准备 UUID 和精确材料摘要")
		}
		return nil
	}
	if in.Action != "check" && in.Action != "prepare" || in.PreparationID != "" {
		return fault.Invalid("未知升级操作或准备引用无效")
	}
	if err := (LifecyclePreviewInput{EngineOwner: "managed", Action: "install", PlanID: in.PlanID, AssetID: in.AssetID, Prerelease: in.Prerelease}).Validate(); err != nil {
		return err
	}
	if in.Action == "check" && in.Target != "" || in.Action == "prepare" && !upgradeDigest(in.Target) {
		return fault.Invalid("升级检查或准备的目标摘要无效")
	}
	return nil
}
func upgradeDigest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

type UpgradeRequest struct {
	Protocol    int          `json:"protocol"`
	OperationID string       `json:"operation_id"`
	Input       UpgradeInput `json:"input"`
}

func (r UpgradeRequest) Valid() bool {
	return r.Protocol == protocol.Agent && policyID.MatchString(r.OperationID) && r.Input.Validate() == nil
}
func (r UpgradeRequest) Hash() string { raw, _ := json.Marshal(r); return secure.Hash(raw) }

type UpgradeBans struct {
	ObservedAt int64  `json:"observed_at"`
	Count      int    `json:"count"`
	SHA256     string `json:"sha256"`
}
type UpgradePlan struct {
	At               int64        `json:"at"`
	Target           string       `json:"target"`
	InstallationID   string       `json:"installation_id"`
	EventID          string       `json:"event_id"`
	SourceVersion    string       `json:"source_version"`
	CandidateVersion string       `json:"candidate_version"`
	Running          bool         `json:"running"`
	Jails            []string     `json:"jails"`
	Impacts          []string     `json:"impacts"`
	ScopeVerified    bool         `json:"scope_verified"`
	Blockers         []string     `json:"blockers"`
	NginxGrants      int          `json:"nginx_grants"`
	HostSources      bool         `json:"host_sources"`
	HostSync         bool         `json:"host_sync"`
	Bans             *UpgradeBans `json:"bans"`
}
type UpgradePreparation struct {
	ID               string `json:"id"`
	IntentSHA256     string `json:"intent_sha256"`
	CreatedAt        int64  `json:"created_at"`
	SourceVersion    string `json:"source_version"`
	CandidateVersion string `json:"candidate_version"`
}
type UpgradeRunResult struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Stage       string `json:"stage"`
	CompletedAt int64  `json:"completed_at"`
}
type UpgradeOperation struct {
	ID          string              `json:"id"`
	RequestHash string              `json:"request_hash"`
	Input       UpgradeInput        `json:"input"`
	ChildID     string              `json:"child_id"`
	State       string              `json:"state"`
	Stage       string              `json:"stage"`
	At          int64               `json:"at"`
	Error       string              `json:"error"`
	Plan        *UpgradePlan        `json:"plan"`
	Preparation *UpgradePreparation `json:"preparation"`
	Run         *UpgradeRunResult   `json:"run"`
}

func (o UpgradeOperation) Valid() bool {
	if !policyID.MatchString(o.ID) || !policyID.MatchString(o.ChildID) || o.ID == o.ChildID || !upgradeDigest(o.RequestHash) || o.Input.Validate() != nil || o.At <= 0 || o.Stage == "" || len(o.Error) > 1024 {
		return false
	}
	if o.State != "running" && o.State != "recovery_required" && o.State != "succeeded" && o.State != "failed" && o.State != "cancelled" {
		return false
	}
	if o.Plan != nil {
		p := o.Plan
		if o.Input.Action != "check" || p.At <= 0 || !upgradeDigest(p.Target) || !policyID.MatchString(p.InstallationID) || !policyID.MatchString(p.EventID) || p.SourceVersion == "" || p.CandidateVersion == "" || p.Jails == nil || len(p.Jails) > 64 || p.Impacts == nil || len(p.Impacts) > 16 || p.Blockers == nil || p.NginxGrants < 0 || p.NginxGrants > 64 {
			return false
		}
		if p.Bans != nil && (p.Bans.Count < 0 || p.Bans.ObservedAt <= 0 || !upgradeDigest(p.Bans.SHA256)) {
			return false
		}
	}
	if o.Preparation != nil {
		p := o.Preparation
		if o.Input.Action != "prepare" || p.ID != o.ChildID || !upgradeDigest(p.IntentSHA256) || p.CreatedAt <= 0 || p.SourceVersion == "" || p.CandidateVersion == "" {
			return false
		}
	}
	if o.Run != nil && (o.Input.Action != "run" || o.Run.ID != o.ChildID || o.Run.State != o.State || o.Run.Stage != o.Stage) {
		return false
	}
	if o.State == "succeeded" {
		switch o.Input.Action {
		case "check":
			return o.Stage == "candidate_checked" && o.Plan != nil
		case "prepare":
			return o.Stage == "upgrade_prepared" && o.Preparation != nil
		case "run":
			return o.Stage == "protection_verified" && o.Run != nil && o.Run.CompletedAt > 0
		}
	}
	if o.Stage == "original_protection_verified" && (o.State != "failed" || o.Run == nil || o.Run.CompletedAt <= 0) {
		return false
	}
	return true
}

type UpgradeTask = AddressTask
type UpgradeTaskStatus struct {
	ID          string            `json:"id"`
	OperationID string            `json:"operation_id"`
	State       string            `json:"state"`
	Stage       string            `json:"stage"`
	Error       string            `json:"error"`
	CreatedAt   int64             `json:"created_at"`
	Input       UpgradeInput      `json:"input"`
	Result      *UpgradeOperation `json:"result"`
}
type UpgradeExecutor interface {
	ChangeFail2banUpgrade(context.Context, UpgradeRequest) (UpgradeOperation, error)
	Fail2banUpgradeOperation(context.Context, string) (UpgradeOperation, error)
}
