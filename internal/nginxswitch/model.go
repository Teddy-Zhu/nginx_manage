// Package nginxswitch coordinates independently hosted native Nginx switches.
package nginxswitch

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

var sha256Value = regexp.MustCompile(`^[0-9a-f]{64}$`)
var assetValue = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Input struct {
	MaintenanceID      string `json:"maintenance_id"`
	PlanID             string `json:"plan_id"`
	AssetID            string `json:"asset_id"`
	ManifestSHA256     string `json:"manifest_sha256"`
	TrustSHA256        string `json:"trust_sha256"`
	Prerelease         bool   `json:"prerelease"`
	AllowDowntime      bool   `json:"allow_downtime"`
	ExpectedSHA256     string `json:"expected_sha256"`
	ExpectedRevision   string `json:"expected_revision"`
	ExpectedDeployment string `json:"expected_deployment"`
}

func (in Input) Validate() error {
	if !components.ValidID(in.MaintenanceID) || !sha256Value.MatchString(in.PlanID) || !assetValue.MatchString(in.AssetID) || !sha256Value.MatchString(in.ManifestSHA256) || !sha256Value.MatchString(in.TrustSHA256) || !in.AllowDowntime || !sha256Value.MatchString(in.ExpectedSHA256) || in.ExpectedRevision != "" && !components.ValidID(in.ExpectedRevision) || in.ExpectedDeployment != "" && !components.ValidID(in.ExpectedDeployment) {
		return fault.Invalid("组件切换须固定签名准备结果、当前程序和发布，并明确允许停机")
	}
	return nil
}

type Request struct {
	Protocol           int    `json:"protocol"`
	OperationID        string `json:"operation_id"`
	Epoch              string `json:"epoch"`
	Sequence           int    `json:"sequence"`
	Command            string `json:"command"`
	AuthorizationUntil int64  `json:"authorization_until"`
	Input              Input  `json:"input"`
}

func (r Request) Validate() error {
	if r.Protocol != protocol.Agent || !components.ValidID(r.OperationID) || !components.ValidID(r.Epoch) || r.Sequence < 1 || r.Sequence > 32 || r.AuthorizationUntil <= 0 || r.Command != "switch" && r.Command != "resume" && r.Command != "rollback" || (r.Sequence == 1) != (r.Command == "switch") {
		return fault.Invalid("组件切换协议、标识或授权序号无效")
	}
	return r.Input.Validate()
}

func Hash(id string, in Input) string {
	raw, _ := json.Marshal(struct {
		Protocol    int
		OperationID string
		Input       Input
	}{protocol.Agent, id, in})
	return secure.Hash(raw)
}

type Component struct {
	Owner   string `json:"owner"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}
type Confirmation struct {
	ConfirmedAt  int64  `json:"confirmed_at"`
	SHA256       string `json:"sha256"`
	Version      string `json:"version"`
	RevisionID   string `json:"revision_id"`
	DeploymentID string `json:"deployment_id"`
	AgentPID     int    `json:"agent_pid"`
	NginxPID     int    `json:"nginx_pid"`
}
type Operation struct {
	Protocol      int           `json:"protocol"`
	ID            string        `json:"id"`
	RequestHash   string        `json:"request_hash"`
	Input         Input         `json:"input"`
	Authorization Request       `json:"authorization"`
	Sequence      int           `json:"sequence"`
	Command       string        `json:"command"`
	State         string        `json:"state"`
	Stage         string        `json:"stage"`
	Error         string        `json:"error"`
	Active        bool          `json:"active"`
	UpdatedAt     int64         `json:"updated_at"`
	ChildID       string        `json:"child_id"`
	IntentSHA256  string        `json:"intent_sha256,omitempty"`
	Deadline      int64         `json:"deadline"`
	Before        *Component    `json:"before,omitempty"`
	Candidate     *Component    `json:"candidate,omitempty"`
	Confirmation  *Confirmation `json:"confirmation,omitempty"`
}

func Terminal(state string) bool {
	return state == "succeeded" || state == "rolled_back" || state == "failed"
}

func (o Operation) Validate(id string, in Input) error {
	a := o.Authorization
	if in.Validate() != nil || !components.ValidID(id) || o.Protocol != protocol.Agent || o.ID != id || o.RequestHash != Hash(id, in) || o.Input != in || a.Validate() != nil || a.Input != in || a.OperationID != id || a.Sequence != o.Sequence || a.Command != o.Command || !components.ValidID(o.ChildID) || o.ChildID == id || o.UpdatedAt <= 0 || o.Stage == "" {
		return errors.New("组件切换回执与原任务不一致")
	}
	switch o.State {
	case "queued", "running", "compensating", "recovery_required", "succeeded", "failed", "rolled_back":
	default:
		return errors.New("组件切换状态无效")
	}
	if o.IntentSHA256 == "" {
		if o.Before != nil || o.Candidate != nil || o.Confirmation != nil || o.Deadline != 0 || o.State == "succeeded" || o.State == "rolled_back" {
			return errors.New("组件切换缺少独立准入快照")
		}
		return nil
	}
	b, c := o.Before, o.Candidate
	if !sha256Value.MatchString(o.IntentSHA256) || b == nil || c == nil || b.Owner != "local" && b.Owner != "managed" || c.Owner != "managed" || b.SHA256 != in.ExpectedSHA256 || !sha256Value.MatchString(c.SHA256) || c.SHA256 == b.SHA256 || b.Version == "" || c.Version == "" || o.Deadline <= 0 {
		return errors.New("组件切换准入快照无效")
	}
	if o.State == "succeeded" || o.State == "rolled_back" {
		target := c
		if o.State == "rolled_back" {
			target = b
		}
		p := o.Confirmation
		if p == nil || p.ConfirmedAt <= 0 || p.SHA256 != target.SHA256 || p.Version != target.Version || p.RevisionID != in.ExpectedRevision || p.DeploymentID != in.ExpectedDeployment || p.AgentPID <= 1 || p.NginxPID <= 1 || o.State == "succeeded" && o.Error != "" {
			return errors.New("组件切换终态缺少目标运行确认")
		}
	}
	return nil
}

type Host interface {
	NginxSwitch(context.Context, string) (Operation, error)
	SubmitNginxSwitch(context.Context, Request) (Operation, error)
}
type CreateInput struct {
	MaintenanceID      string `json:"maintenance_id"`
	PrepareTaskID      string `json:"prepare_task_id"`
	AssetID            string `json:"asset_id"`
	AllowDowntime      bool   `json:"allow_downtime"`
	ExpectedSHA256     string `json:"expected_sha256"`
	ExpectedRevision   string `json:"expected_revision"`
	ExpectedDeployment string `json:"expected_deployment"`
}
type Task struct {
	ID                 string     `json:"id"`
	OperationID        string     `json:"operation_id"`
	PrepareTaskID      string     `json:"prepare_task_id"`
	Input              Input      `json:"input"`
	Sequence           int        `json:"sequence"`
	Command            string     `json:"command"`
	AuthorizationUntil int64      `json:"authorization_until"`
	State              string     `json:"state"`
	Stage              string     `json:"stage"`
	Error              string     `json:"error"`
	CreatedAt          int64      `json:"created_at"`
	UpdatedAt          int64      `json:"updated_at"`
	Result             *Operation `json:"result,omitempty"`
}
