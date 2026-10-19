// Package imageupdates coordinates durable panel launcher image replacement.
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

type Input struct {
	MaintenanceID string `json:"maintenance_id"`
	PlanID        string `json:"plan_id"`
	Prerelease    bool   `json:"prerelease"`
}

func (in Input) Validate() error {
	if !components.ValidID(in.MaintenanceID) || !digest.MatchString(in.PlanID) {
		return fault.Invalid("面板镜像替换须绑定原维护会话与签名暂存计划")
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
	if r.Actor == "" || len(r.Actor) > 128 || strings.TrimSpace(r.Actor) != r.Actor || strings.ContainsAny(r.Actor, "\x00\r\n") || !components.ValidID(r.RequestID) {
		return fault.Invalid("面板镜像替换授权缺少有效的发起人或请求标识")
	}
	if r.Protocol != protocol.Agent || !components.ValidID(r.OperationID) || r.OperationID == r.Input.MaintenanceID || !components.ValidID(r.Epoch) || r.Sequence < 1 || r.Sequence > 32 || r.AuthorizationUntil <= 0 || (r.Command != "upgrade" && r.Command != "resume") || (r.Command == "upgrade") != (r.Sequence == 1) {
		return fault.Invalid("面板镜像替换操作、授权序号或协议无效")
	}
	return r.Input.Validate()
}

func Hash(id string, in Input) string {
	raw, _ := json.Marshal(struct {
		Protocol int
		ID       string
		Input    Input
	}{protocol.Agent, id, in})
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
	if o.Authorization.Validate() != nil || o.Authorization.OperationID != id || o.Authorization.Input != in || o.Authorization.Sequence != o.Sequence || o.Authorization.Command != o.Command || in.Validate() != nil || o.Protocol != protocol.Agent || !components.ValidID(id) || o.ID != id || o.Input != in || o.RequestHash != Hash(id, in) || !digest.MatchString(o.IntentSHA256) || !imageID(o.BeforeImageID) || !imageID(o.TargetImageID) || o.BeforeImageID == o.TargetImageID || !imageReference.MatchString(o.BeforeImage) || !imageReference.MatchString(o.TargetImage) || !digest.MatchString(o.PanelID) || o.TargetVersion == "" || len(o.TargetVersion) > 96 || len(o.Error) > 4000 || len(o.Failure) > 4000 || o.Deadline <= 0 || o.UpdatedAt <= 0 || o.ReadyEpoch != "" && !components.ValidID(o.ReadyEpoch) {
		return errors.New("面板镜像替换回执与原任务不一致")
	}
	if o.Finalized {
		if !components.ValidID(o.ReadyEpoch) || o.ReadyEpoch != o.Authorization.Epoch || o.State == "succeeded" && (o.Stage != "committed" || o.Failure != "" || o.Error != "") || o.State == "rolled_back" && (o.Stage != "compensated" || o.Failure == "") || o.State != "succeeded" && o.State != "rolled_back" {
			return errors.New("面板镜像替换结果缺少就绪确认")
		}
		return nil
	}
	if slices.Contains([]string{"rollback_stopping", "rollback_selecting", "rollback_creating", "rollback_starting", "rollback_checking"}, o.Stage) {
		if o.Failure != "" && (o.State == "compensating" || o.State == "recovery_required") {
			return nil
		}
	} else if slices.Contains([]string{"authorized", "stopping", "removing", "selecting", "creating", "starting", "checking"}, o.Stage) && o.Failure == "" && (o.State == "running" || o.State == "recovery_required") {
		return nil
	}
	return errors.New("面板镜像替换阶段或恢复方向无效")
}

type Agent interface {
	SubmitPanelImageUpgrade(context.Context, Request) (Operation, error)
	PanelImageUpgrade(context.Context, string) (Operation, error)
}

type CreateInput struct {
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
