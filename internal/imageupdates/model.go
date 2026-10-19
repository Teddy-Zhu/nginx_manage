// Package imageupdates coordinates durable panel and Nginx image replacement.
package imageupdates

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageReference = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,240}@sha256:[0-9a-f]{64}$`)

const Panel = "panel-launcher"
const Nginx = "nginx"

func Kind(component string) string {
	switch component {
	case Panel:
		return "panel.image"
	case Nginx:
		return "nginx.image"
	default:
		return ""
	}
}

type Input struct {
	Component     string `json:"component"`
	AllowDowntime bool   `json:"allow_downtime"`
	MaintenanceID string `json:"maintenance_id"`
	PlanID        string `json:"plan_id"`
	Prerelease    bool   `json:"prerelease"`
}

func (in Input) Validate() error {
	if Kind(in.Component) == "" || in.Component == Nginx && !in.AllowDowntime || !components.ValidID(in.MaintenanceID) || !digest.MatchString(in.PlanID) {
		return fault.Invalid("镜像替换须绑定原维护会话与签名暂存计划")
	}
	return nil
}

type Request struct {
	Actor              string `json:"actor"`
	RequestID          string `json:"request_id"`
	Protocol           int    `json:"protocol"`
	OperationID        string `json:"operation_id"`
	Input              Input  `json:"input"`
	Sequence           int    `json:"sequence"`
	Command            string `json:"command"`
	Epoch              string `json:"epoch"`
	AuthorizationUntil int64  `json:"authorization_until"`
}

func (r Request) Validate() error {
	if r.Protocol != protocol.Agent {
		return fault.Invalid("更新请求协议不匹配")
	}
	return r.ValidateStored()
}

// ValidateStored authenticates the original bounded authorization after a wire upgrade.
// New requests must pass Validate at the live IPC boundary.
func (r Request) ValidateStored() error {
	if r.Actor == "" || len(r.Actor) > 128 || strings.TrimSpace(r.Actor) != r.Actor || strings.ContainsAny(r.Actor, "\x00\r\n") || !components.ValidID(r.RequestID) {
		return fault.Invalid("镜像替换授权缺少有效的发起人或请求标识")
	}
	if r.Protocol <= 0 || !components.ValidID(r.OperationID) || r.OperationID == r.Input.MaintenanceID || !components.ValidID(r.Epoch) || r.Sequence < 1 || r.Sequence > 32 || r.AuthorizationUntil <= 0 || (r.Command != "upgrade" && r.Command != "resume") || (r.Command == "upgrade") != (r.Sequence == 1) {
		return fault.Invalid("镜像替换操作、授权序号或协议无效")
	}
	return r.Input.Validate()
}

func Hash(id string, in Input) string {
	raw, _ := json.Marshal(struct {
		Protocol int
		ID       string
		Input    Input
	}{protocol.Journal, id, in})
	return secure.Hash(raw)
}

func imageID(v string) bool {
	return strings.HasPrefix(v, "sha256:") && digest.MatchString(strings.TrimPrefix(v, "sha256:"))
}

type Operation struct {
	BeforeImage   string  `json:"before_image"`
	TargetImage   string  `json:"target_image"`
	Authorization Request `json:"authorization"`
	Protocol      int     `json:"protocol"`
	ID            string  `json:"id"`
	Input         Input   `json:"input"`
	RequestHash   string  `json:"request_hash"`
	IntentSHA256  string  `json:"intent_sha256"`
	Sequence      int     `json:"sequence"`
	Command       string  `json:"command"`
	State         string  `json:"state"`
	Stage         string  `json:"stage"`
	Error         string  `json:"error"`
	Failure       string  `json:"failure"`
	BeforeImageID string  `json:"before_image_id"`
	TargetImageID string  `json:"target_image_id"`
	TargetVersion string  `json:"target_version"`
	PanelID       string  `json:"panel_id"`
	ReadyEpoch    string  `json:"ready_epoch"`
	Deadline      int64   `json:"deadline"`
	UpdatedAt     int64   `json:"updated_at"`
	Active        bool    `json:"active"`
	Finalized     bool    `json:"finalized"`
}

func (o Operation) Validate(id string, in Input) error {
	if o.Authorization.ValidateStored() != nil || o.Authorization.OperationID != id || o.Authorization.Input != in || o.Authorization.Sequence != o.Sequence || o.Authorization.Command != o.Command || in.Validate() != nil || o.Protocol <= 0 || !components.ValidID(id) || o.ID != id || o.Input != in || o.RequestHash != Hash(id, in) || !digest.MatchString(o.IntentSHA256) || !imageID(o.BeforeImageID) || !imageID(o.TargetImageID) || o.BeforeImageID == o.TargetImageID || !imageReference.MatchString(o.BeforeImage) || !imageReference.MatchString(o.TargetImage) || !digest.MatchString(o.PanelID) || o.TargetVersion == "" || len(o.TargetVersion) > 96 || len(o.Error) > 4000 || len(o.Failure) > 4000 || o.Deadline <= 0 || o.UpdatedAt <= 0 || o.ReadyEpoch != "" && !components.ValidID(o.ReadyEpoch) {
		return errors.New("镜像替换回执与原任务不一致")
	}
	if o.Finalized {
		if !components.ValidID(o.ReadyEpoch) || in.Component == Panel && o.ReadyEpoch != o.Authorization.Epoch || o.State == "succeeded" && (o.Stage != "committed" || o.Failure != "" || o.Error != "") || o.State == "rolled_back" && (o.Stage != "compensated" || o.Failure == "") || o.State != "succeeded" && o.State != "rolled_back" && (in.Component != Nginx || o.State != "failed" || o.Stage != "rejected" || o.Failure == "") {
			return errors.New("镜像替换结果缺少就绪确认")
		}
		return nil
	}
	forward := []string{"authorized", "stopping", "removing", "selecting", "creating", "starting", "checking"}
	rollback := []string{"rollback_stopping", "rollback_selecting", "rollback_creating", "rollback_starting", "rollback_checking"}
	if in.Component == Nginx {
		forward = []string{"authorized", "check_creating", "checking", "check_removing", "stopping_agent", "stopping", "removing", "selecting", "creating", "starting", "confirming_nginx", "starting_agent", "confirming_agent"}
		rollback = []string{"rollback_stopping_agent", "rollback_stopping", "rollback_selecting", "rollback_creating", "rollback_starting", "rollback_confirming_nginx", "rollback_starting_agent", "rollback_confirming_agent"}
	}
	if slices.Contains(rollback, o.Stage) {
		if o.Failure != "" && (o.State == "compensating" || o.State == "recovery_required") {
			return nil
		}
	} else if slices.Contains(forward, o.Stage) && o.Failure == "" && (o.State == "running" || o.State == "recovery_required") {
		return nil
	}

	return errors.New("镜像替换阶段或恢复方向无效")
}

type Agent interface {
	SubmitImageUpgrade(context.Context, Request) (Operation, error)
	ImageUpgrade(context.Context, string, string) (Operation, error)
}

type CreateInput struct {
	AllowDowntime bool   `json:"allow_downtime"`
	MaintenanceID string `json:"maintenance_id"`
	PrepareTaskID string `json:"prepare_task_id"`
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
	Request            Request    `json:"-"`
	requestID          string
	dispatched         bool
}
