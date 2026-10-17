package fail2ban

import (
	"nginxpanel/internal/protocol"
)

type ExistingPolicyInput struct {
	Action      string             `json:"action"`
	AdoptionID  string             `json:"adoption_id"`
	Policy      ExistingJailPolicy `json:"policy"`
	PreviewID   string             `json:"preview_id"`
	Target      string             `json:"target"`
	ConfirmStop bool               `json:"confirm_stop"`
}

func (in ExistingPolicyInput) request(id string) ExistingPolicyRequest {
	return ExistingPolicyRequest{Protocol: protocol.Agent, OperationID: id, Action: in.Action, AdoptionID: in.AdoptionID, Policy: in.Policy, PreviewID: in.PreviewID, Target: in.Target, ConfirmStop: in.ConfirmStop}
}

type ExistingPolicyTask = AddressTask

type ExistingPolicyTaskStatus struct {
	ID              string                   `json:"id"`
	OperationID     string                   `json:"operation_id"`
	State           string                   `json:"state"`
	Stage           string                   `json:"stage"`
	Error           string                   `json:"error"`
	CreatedAt       int64                    `json:"created_at"`
	Input           ExistingPolicyInput      `json:"input"`
	Result          *ExistingPolicyOperation `json:"result"`
	CancelRequested bool                     `json:"cancel_requested"`
	CancelPending   bool                     `json:"cancel_pending"`
	CancelError     string                   `json:"cancel_error"`
}

type existingTaskPayload struct {
	Input            ExistingPolicyInput      `json:"input"`
	Request          ExistingPolicyRequest    `json:"request"`
	Result           *ExistingPolicyOperation `json:"result"`
	CancelGeneration int                      `json:"cancel_generation"`
	CancelObserved   int                      `json:"cancel_observed"`
	CancelError      string                   `json:"cancel_error"`
}

func (p existingTaskPayload) valid(id string) bool {
	r, err := p.Request.Normalize()
	in, inputErr := p.Input.request(id).Normalize()
	return err == nil && inputErr == nil && r.OperationID == id && r.Hash() == p.Request.Hash() && in.Hash() == r.Hash() && p.CancelGeneration >= 0 && p.CancelGeneration <= 32 && p.CancelObserved >= 0 && p.CancelObserved <= p.CancelGeneration && len(p.CancelError) <= 8192 && (p.CancelGeneration != 0 || p.CancelError == "") && (p.Result == nil || p.matches(*p.Result))
}

func (p existingTaskPayload) matches(out ExistingPolicyOperation) bool {
	return out.Valid() && out.ID == p.Request.OperationID && out.RequestHash == p.Request.Hash() && out.Action == p.Input.Action && out.AdoptionID == p.Input.AdoptionID && (p.Input.Target == "" || out.Target == p.Input.Target) && (out.Plan == nil || sameExistingPolicy(out.Plan.After, p.Input.Policy))
}

func (p existingTaskPayload) status(item ExistingPolicyTaskStatus) ExistingPolicyTaskStatus {
	item.Input, item.Result = p.Input, p.Result
	item.CancelRequested, item.CancelPending, item.CancelError = p.CancelGeneration > 0, p.CancelObserved < p.CancelGeneration, p.CancelError
	return item
}
