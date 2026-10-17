package fail2ban

import (
	"context"
	"encoding/json"
	"slices"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

// ExistingPolicyRequest can change tuning only after a local root adoption.
// Preview and apply are durable jobs, so native proof never holds an HTTP call.
type ExistingPolicyRequest struct {
	Protocol    int                `json:"protocol"`
	OperationID string             `json:"operation_id"`
	Action      string             `json:"action"`
	AdoptionID  string             `json:"adoption_id"`
	Policy      ExistingJailPolicy `json:"policy"`
	PreviewID   string             `json:"preview_id"`
	Target      string             `json:"target"`
	ConfirmStop bool               `json:"confirm_stop"`
}

func (in ExistingPolicyRequest) Normalize() (ExistingPolicyRequest, error) {
	var err error
	in.Policy, err = in.Policy.Normalize()
	if err != nil {
		return in, err
	}
	if in.Protocol != protocol.Agent || !policyID.MatchString(in.OperationID) || !policyID.MatchString(in.AdoptionID) || in.OperationID == in.AdoptionID {
		return in, fault.Invalid("已有 jail 参数请求身份无效")
	}
	switch in.Action {
	case "preview":
		if in.PreviewID != "" || in.Target != "" || in.ConfirmStop {
			return in, fault.Invalid("参数预览不能携带应用或停用授权")
		}
	case "apply":
		if !policyID.MatchString(in.PreviewID) || in.PreviewID == in.OperationID || !validExistingPolicyDigest(in.Target) {
			return in, fault.Invalid("参数应用须绑定独立预览及目标摘要")
		}
	default:
		return in, fault.Invalid("已有 jail 参数动作无效")
	}
	return in, nil
}

func (in ExistingPolicyRequest) Hash() string {
	raw, _ := json.Marshal(in)
	return secure.Hash(append([]byte("nginxpanel:fail2ban-existing-policy-job:v1:"), raw...))
}

type ExistingPolicyPlan struct {
	At               int64              `json:"at"`
	AdoptionID       string             `json:"adoption_id"`
	BindingID        string             `json:"binding_id"`
	BaseID           string             `json:"base_id"`
	Name             string             `json:"name"`
	Target           string             `json:"target"`
	Before           ExistingJailPolicy `json:"before"`
	After            ExistingJailPolicy `json:"after"`
	BanCount         int                `json:"ban_count"`
	StopConfirmation bool               `json:"stop_confirmation"`
	Impacts          []string           `json:"impacts"`
}

func (p ExistingPolicyPlan) Valid() bool {
	before, e1 := p.Before.Normalize()
	after, e2 := p.After.Normalize()
	if p.At <= 0 || !policyID.MatchString(p.AdoptionID) || !policyID.MatchString(p.BindingID) || !policyID.MatchString(p.BaseID) || !existingJailName.MatchString(p.Name) || !validExistingPolicyDigest(p.Target) || e1 != nil || e2 != nil || !sameExistingPolicy(before, p.Before) || !sameExistingPolicy(after, p.After) || sameExistingPolicy(before, after) || p.BanCount < 0 || p.BanCount > 1024 || p.StopConfirmation != (before.Enabled && !after.Enabled) || len(p.Impacts) == 0 || len(p.Impacts) > 8 {
		return false
	}
	for _, impact := range p.Impacts {
		if impact == "" || len(impact) > 2048 {
			return false
		}
	}
	return true
}

type ExistingPolicyOperation struct {
	ID              string              `json:"id"`
	RequestHash     string              `json:"request_hash"`
	Action          string              `json:"action"`
	State           string              `json:"state"`
	Stage           string              `json:"stage"`
	AdoptionID      string              `json:"adoption_id"`
	Target          string              `json:"target"`
	Sent            bool                `json:"sent"`
	Submission      string              `json:"submission"`
	CancelRequested bool                `json:"cancel_requested"`
	CancelError     string              `json:"cancel_error"`
	Error           string              `json:"error"`
	Plan            *ExistingPolicyPlan `json:"plan,omitempty"`
}

func (o ExistingPolicyOperation) Valid() bool {
	if !policyID.MatchString(o.ID) || !policyID.MatchString(o.AdoptionID) || !validExistingPolicyDigest(o.RequestHash) || o.Action != "preview" && o.Action != "apply" || o.Stage == "" || o.Target != "" && !validExistingPolicyDigest(o.Target) || len(o.Error) > 8192 || len(o.CancelError) > 8192 {
		return false
	}
	switch o.State {
	case "running", "recovery_required", "succeeded", "failed":
	default:
		return false
	}
	if o.Plan != nil && (!o.Plan.Valid() || o.Plan.AdoptionID != o.AdoptionID || o.Plan.Target != o.Target) {
		return false
	}
	if o.Action == "preview" {
		return !o.Sent && o.Submission == "" && (o.State != "succeeded" || o.Stage == "preview_confirmed" && o.Plan != nil)
	}
	if !validExistingPolicyDigest(o.Target) || o.Sent && o.Plan == nil || o.State == "succeeded" && (o.Stage != "policy_confirmed" || !o.Sent || o.Plan == nil) {
		return false
	}
	if !o.Sent {
		return o.Submission == ""
	}
	return o.Submission == "pending" || o.Submission == "confirmed" || o.Submission == "unknown"
}

type ExistingPolicyExecutor interface {
	SubmitFail2banExistingPolicy(context.Context, ExistingPolicyRequest) (ExistingPolicyOperation, error)
	Fail2banExistingPolicyOperation(context.Context, string) (ExistingPolicyOperation, error)
	CancelFail2banExistingPolicy(context.Context, string) (ExistingPolicyOperation, error)
}

func sameExistingPolicy(a, b ExistingJailPolicy) bool {
	return a.Enabled == b.Enabled && a.BanTime == b.BanTime && a.FindTime == b.FindTime && a.MaxRetry == b.MaxRetry && slices.Equal(a.IgnoreIPs, b.IgnoreIPs)
}

func validExistingPolicyDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
