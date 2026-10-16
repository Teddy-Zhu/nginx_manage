// Package panelupdates defines the contract for independently hosted updates.
package panelupdates

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Input struct {
	MaintenanceID string `json:"maintenance_id"`
	PlanID        string `json:"plan_id"`
	Prerelease    bool   `json:"prerelease"`
}

func (in Input) Validate() error {
	if !components.ValidID(in.MaintenanceID) || !digest.MatchString(in.PlanID) {
		return fault.Invalid("更新须绑定原维护会话与签名暂存计划")
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
		return fault.Invalid("更新授权缺少有效的发起人或请求标识")
	}
	if r.Protocol != protocol.Agent || !components.ValidID(r.OperationID) || r.OperationID == r.Input.MaintenanceID || !components.ValidID(r.Epoch) || r.Sequence < 1 || r.Sequence > 32 || r.AuthorizationUntil <= 0 || (r.Command != "update" && r.Command != "resume") || (r.Command == "update") != (r.Sequence == 1) {
		return fault.Invalid("更新操作、授权序号或协议无效")
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

type Operation struct {
	Authorization       Request `json:"authorization"`
	Protocol            int     `json:"protocol"`
	ID                  string  `json:"id"`
	Input               Input   `json:"input"`
	RequestHash         string  `json:"request_hash"`
	IntentSHA256        string  `json:"intent_sha256"`
	Sequence            int     `json:"sequence"`
	Command             string  `json:"command"`
	State               string  `json:"state"`
	Stage               string  `json:"stage"`
	Error               string  `json:"error"`
	Failure             string  `json:"failure"`
	BeforeID            string  `json:"before_id"`
	TargetID            string  `json:"target_id"`
	SnapshotID          string  `json:"snapshot_id"`
	BeforeSchema        int64   `json:"before_schema"`
	TargetSchema        int64   `json:"target_schema"`
	Deadline            int64   `json:"deadline"`
	UpdatedAt           int64   `json:"updated_at"`
	Active              bool    `json:"active"`
	Finalized           bool    `json:"finalized"`
	ReleaseAcknowledged bool    `json:"release_acknowledged"`
}

func (o Operation) Validate(id string, in Input) error {
	if o.Authorization.Validate() != nil || o.Authorization.OperationID != id || o.Authorization.Input != in || o.Authorization.Sequence != o.Sequence || o.Authorization.Command != o.Command {
		return errors.New("更新回执缺少匹配的原启动授权")
	}
	if in.Validate() != nil || o.Protocol != protocol.Agent || !components.ValidID(id) || o.ID != id || o.Input != in || o.RequestHash != Hash(id, in) || !digest.MatchString(o.IntentSHA256) || o.Sequence < 1 || o.Sequence > 32 || (o.Command != "update" && o.Command != "resume") || (o.Command == "update") != (o.Sequence == 1) || !digest.MatchString(o.BeforeID) || !digest.MatchString(o.TargetID) || o.BeforeID == o.TargetID || !components.ValidID(o.SnapshotID) || o.BeforeSchema <= 0 || o.TargetSchema < o.BeforeSchema || o.Deadline <= 0 || o.UpdatedAt <= 0 || len(o.Error) > 1024 || len(o.Failure) > 1024 {
		return errors.New("独立更新回执与原任务不一致")
	}
	outcome := map[string]string{"committed": "succeeded", "compensated": "rolled_back", "aborted": "failed"}[o.Stage]
	if outcome != "" {
		if !o.Finalized || o.ReleaseAcknowledged && o.State != outcome || !o.ReleaseAcknowledged && o.State != "waiting_confirmation" || outcome == "succeeded" && o.Failure != "" || outcome != "succeeded" && o.Failure == "" {
			return errors.New("更新结果与维护释放状态不一致")
		}
		return nil
	}
	if o.Finalized || o.ReleaseAcknowledged {
		return errors.New("更新阶段尚未结束")
	}
	switch o.Stage {
	case "capturing":
		if o.State == "queued" {
			return nil
		}
	case "stopping", "selecting", "starting", "checking":
	case "rollback_stopping", "rollback_selecting", "restoring", "rollback_starting", "rollback_checking":
		if o.Failure == "" {
			return errors.New("补偿缺少原失败原因")
		}
		if o.State == "compensating" || o.State == "recovery_required" {
			return nil
		}
		return errors.New("补偿状态无效")
	default:
		return errors.New("未知更新阶段")
	}
	if o.State != "running" && o.State != "recovery_required" {
		return errors.New("更新执行状态无效")
	}
	return nil
}

type Agent interface {
	SubmitPanelUpdate(context.Context, Request) (Operation, error)
	PanelUpdate(context.Context, string) (Operation, error)
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
