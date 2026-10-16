package fail2ban

import (
	"context"
	"encoding/json"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

type LifecyclePreviewInput struct {
	Action     string `json:"action"`
	PlanID     string `json:"plan_id"`
	AssetID    string `json:"asset_id"`
	Prerelease bool   `json:"prerelease"`
}

func (in LifecyclePreviewInput) Validate() error {
	switch in.Action {
	case "install":
		if len(in.PlanID) != 64 || strings.Trim(in.PlanID, "0123456789abcdef") != "" || in.AssetID == "" || len(in.AssetID) > 128 || strings.ContainsAny(in.AssetID, "/\\\x00\r\n") {
			return fault.Invalid("安装须选择单个已准备的 Fail2ban 签名资产")
		}
	case "resume", "rollback", "start", "stop", "enable", "disable":
		if in.PlanID != "" || in.AssetID != "" || in.Prerelease {
			return fault.Invalid("服务和恢复操作不能更换签名资产")
		}
	default:
		return fault.Invalid("未知受管引擎操作")
	}
	return nil
}
func (in LifecyclePreviewInput) Scopes() []string {
	switch in.Action {
	case "install":
		return []string{"components.manage"}
	case "resume", "rollback":
		return []string{"components.manage", "security.write"}
	default:
		return []string{"security.write"}
	}
}

type LifecycleInput struct {
	LifecyclePreviewInput
	BaseID string `json:"base_id"`
	Target string `json:"target"`
	Start  bool   `json:"start"`
	Enable bool   `json:"enable"`
}

func (in LifecycleInput) Validate() error {
	if err := in.LifecyclePreviewInput.Validate(); err != nil {
		return err
	}
	if in.BaseID != "" && !policyID.MatchString(in.BaseID) || in.Action != "install" && in.BaseID == "" || len(in.Target) != 64 || strings.Trim(in.Target, "0123456789abcdef") != "" || in.Action != "resume" && (in.Start || in.Enable) {
		return fault.Invalid("受管引擎操作的实例、目标基准或恢复意图无效")
	}
	return nil
}
func (in LifecycleInput) NeedsEnabled() bool {
	return in.Action == "start" || in.Action == "enable" || in.Start || in.Enable
}

type LifecyclePlan struct {
	At      int64          `json:"at"`
	Input   LifecycleInput `json:"input"`
	Managed Managed        `json:"managed"`
	Service Service        `json:"service"`
	Jails   []string       `json:"jails"`
	Impacts []string       `json:"impacts"`
}
type LifecycleRequest struct {
	Protocol    int            `json:"protocol"`
	OperationID string         `json:"operation_id"`
	Input       LifecycleInput `json:"input"`
}

func (in LifecycleRequest) Valid() bool {
	return in.Protocol == protocol.Agent && policyID.MatchString(in.OperationID) && in.Input.Validate() == nil
}
func (in LifecycleRequest) Hash() string { raw, _ := json.Marshal(in); return secure.Hash(raw) }

type LifecycleOperation struct {
	ID          string         `json:"id"`
	RequestHash string         `json:"request_hash"`
	Input       LifecycleInput `json:"input"`
	State       string         `json:"state"`
	Stage       string         `json:"stage"`
	Submission  string         `json:"submission"`
	At          int64          `json:"at"`
	Managed     Managed        `json:"managed"`
	Service     Service        `json:"service"`
	Error       string         `json:"error"`
}
type LifecycleTask = AddressTask
type LifecycleTaskStatus struct {
	ID          string              `json:"id"`
	OperationID string              `json:"operation_id"`
	State       string              `json:"state"`
	Stage       string              `json:"stage"`
	Error       string              `json:"error"`
	CreatedAt   int64               `json:"created_at"`
	Input       LifecycleInput      `json:"input"`
	Result      *LifecycleOperation `json:"result"`
}
type LifecycleExecutor interface {
	PreviewFail2banLifecycle(context.Context, LifecyclePreviewInput) (LifecyclePlan, error)
	ChangeFail2banLifecycle(context.Context, LifecycleRequest) (LifecycleOperation, error)
	Fail2banLifecycleOperation(context.Context, string) (LifecycleOperation, error)
}
