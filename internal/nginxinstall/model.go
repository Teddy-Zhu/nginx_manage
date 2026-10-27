// Package nginxinstall coordinates the first installation of a prepared Nginx.
package nginxinstall

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

var sha256Value = regexp.MustCompile(`^[0-9a-f]{64}$`)
var assetValue = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Input struct {
	MaintenanceID  string `json:"maintenance_id"`
	PlanID         string `json:"plan_id"`
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TrustSHA256    string `json:"trust_sha256"`
	Prerelease     bool   `json:"prerelease"`
	Start          bool   `json:"start"`
	Enable         bool   `json:"enable"`
}

func (in Input) Validate() error {
	if !components.ValidID(in.MaintenanceID) || !sha256Value.MatchString(in.PlanID) || !assetValue.MatchString(in.AssetID) || !sha256Value.MatchString(in.ManifestSHA256) || !sha256Value.MatchString(in.TrustSHA256) {
		return fault.Invalid("首次安装须绑定维护会话和完整的签名资产计划")
	}
	return nil
}

type Request struct {
	AuthorizationUntil int64  `json:"authorization_until"`
	Protocol           int    `json:"protocol"`
	OperationID        string `json:"operation_id"`
	Epoch              string `json:"epoch"`
	Sequence           int    `json:"sequence"`
	Command            string `json:"command"`
	Input              Input  `json:"input"`
}

func (r Request) Validate() error {
	if r.Protocol != protocol.Agent {
		return fault.Invalid("组件请求协议不匹配")
	}
	return r.ValidateStored()
}

func (r Request) ValidateStored() error {
	if r.AuthorizationUntil <= 0 {
		return fault.Invalid("安装授权期限无效")
	}
	if r.Protocol <= 0 || !components.ValidID(r.OperationID) || !components.ValidID(r.Epoch) || r.Sequence < 1 || r.Sequence > 32 || (r.Command != "install" && r.Command != "resume" && r.Command != "cancel") || (r.Command == "install") != (r.Sequence == 1) {
		return fault.Invalid("首次安装操作、授权序号或协议无效")
	}
	return r.Input.Validate()
}

func Hash(id string, in Input) string {
	raw, _ := json.Marshal(struct {
		Protocol    int
		OperationID string
		Input       Input
	}{protocol.Journal, id, in})
	return secure.Hash(raw)
}

type Operation struct {
	Protocol     int                        `json:"protocol"`
	ID           string                     `json:"id"`
	RequestHash  string                     `json:"request_hash"`
	Input        Input                      `json:"input"`
	Sequence     int                        `json:"sequence"`
	Command      string                     `json:"command"`
	State        string                     `json:"state"`
	Stage        string                     `json:"stage"`
	Error        string                     `json:"error"`
	Deadline     int64                      `json:"deadline"`
	UpdatedAt    int64                      `json:"updated_at"`
	Active       bool                       `json:"active"`
	Installation *nginxruntime.Installation `json:"installation,omitempty"`
	Running      bool                       `json:"running"`
}

func (o Operation) Validate(id string, in Input) error {
	if in.Validate() != nil || !components.ValidID(id) || o.Protocol <= 0 || o.ID != id || o.RequestHash != Hash(id, in) || Hash(id, o.Input) != o.RequestHash || o.Sequence < 1 || o.Sequence > 32 || o.Deadline <= 0 || o.UpdatedAt <= 0 || (o.Command != "install" && o.Command != "resume" && o.Command != "cancel") || (o.Command == "install") != (o.Sequence == 1) || o.Stage == "" {
		return errors.New("首次安装回执与原任务不一致")
	}
	switch o.State {
	case "queued", "running", "recovery_required":
	case "succeeded":
		x := o.Installation
		if x == nil || x.Owner != "managed" || x.PlanID != in.PlanID || x.AssetID != in.AssetID || !sha256Value.MatchString(x.SHA256) || x.Version == "" || o.Error != "" || (o.Stage != "installed" && o.Stage != "running") || in.Start && !o.Running {
			return errors.New("首次安装成功回执缺少来源或运行确认")
		}
	case "cancelled":
		if o.Stage != "cancelled_before_binding" || o.Installation != nil || o.Running {
			return errors.New("首次安装取消回执无效")
		}
	default:
		return errors.New("首次安装状态无效")
	}
	return nil
}

type Host interface {
	NginxInstallation(context.Context, string) (Operation, error)
	SubmitNginxInstallation(context.Context, Request) (Operation, error)
}

type CreateInput struct {
	MaintenanceID string `json:"-"`
	PrepareTaskID string `json:"prepare_task_id"`
	AssetID       string `json:"asset_id"`
	Start         bool   `json:"start"`
	Enable        bool   `json:"enable"`
}
type Task struct {
	AuthorizationUntil int64      `json:"authorization_until"`
	ID                 string     `json:"id"`
	OperationID        string     `json:"operation_id"`
	PrepareTaskID      string     `json:"prepare_task_id"`
	Input              Input      `json:"input"`
	Sequence           int        `json:"sequence"`
	Command            string     `json:"command"`
	State              string     `json:"state"`
	Stage              string     `json:"stage"`
	Error              string     `json:"error"`
	CreatedAt          int64      `json:"created_at"`
	UpdatedAt          int64      `json:"updated_at"`
	Result             *Operation `json:"result,omitempty"`
}
