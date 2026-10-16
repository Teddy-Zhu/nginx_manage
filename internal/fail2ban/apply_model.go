package fail2ban

import (
	"context"
	"encoding/json"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

// JailTarget freezes installation, service generation, Nginx and authorization.
func JailTarget(engine, base, directory, manifest, registry, invocation, host string) string {
	raw, _ := json.Marshal([]string{engine, base, directory, manifest, registry, invocation, host})
	return secure.Hash(raw)
}

type JailsRequest struct {
	Protocol    int    `json:"protocol"`
	OperationID string `json:"operation_id"`
	BaseID      string `json:"base_id"`
	Target      string `json:"target"`
	Policy      Policy `json:"policy"`
}

func (in JailsRequest) Hash() string { raw, _ := json.Marshal(in); return secure.Hash(raw) }

type JailsOperation struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Stage       string `json:"stage"`
	BeforeID    string `json:"before_id"`
	AfterID     string `json:"after_id"`
	RequestHash string `json:"request_hash"`
	Target      string `json:"target"`
	Error       string `json:"error"`
}

type JailsRuntime struct {
	NginxReady  bool             `json:"nginx_ready"`
	NginxReason string           `json:"nginx_reason"`
	HostReady   bool             `json:"host_ready"`
	HostReason  string           `json:"host_reason"`
	Available   bool             `json:"available"`
	Target      string           `json:"target"`
	SelectedID  string           `json:"selected_id"`
	Policy      Policy           `json:"policy"`
	Resources   []string         `json:"resources"`
	Pending     []JailsOperation `json:"pending"`
	Reason      string           `json:"reason"`
}

type ApplyInput struct {
	Version    int64  `json:"version"`
	PolicyHash string `json:"policy_hash"`
	BaseID     string `json:"base_id"`
	Target     string `json:"target"`
}

type ApplyTask struct {
	TaskID      string `json:"task_id"`
	OperationID string `json:"operation_id"`
	Version     int64  `json:"version"`
}

type ApplyTaskStatus struct {
	ID          string `json:"id"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Stage       string `json:"stage"`
	Error       string `json:"error"`
	CreatedAt   int64  `json:"created_at"`
}

type JailsExecutor interface {
	ReadFail2banJailsRuntime(context.Context) (JailsRuntime, error)
	ApplyFail2banJails(context.Context, JailsRequest) (JailsOperation, error)
	Fail2banJailsOperation(context.Context, string) (JailsOperation, error)
}

func (in ApplyInput) Validate() error {
	if in.Version < 1 || len(in.PolicyHash) != 64 || len(in.Target) != 64 || in.BaseID != "" && !policyID.MatchString(in.BaseID) {
		return fault.Invalid("jail 应用版本或目标基准无效")
	}
	for _, value := range []string{in.PolicyHash, in.Target} {
		for _, c := range value {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return fault.Invalid("jail 应用摘要无效")
			}
		}
	}
	return nil
}

func (in JailsRequest) Valid() bool {
	return in.Protocol == protocol.Agent && policyID.MatchString(in.OperationID) && (in.BaseID == "" || policyID.MatchString(in.BaseID)) && len(in.Target) == 64
}
