package agent

import (
	"encoding/json"
	"errors"
	"nginxpanel/internal/protocol"

	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/secure"
)

const nginxInstallKind = "component.nginx.install"

type NginxInstallInput struct {
	API           *nginxinstall.Input     `json:"api,omitempty"`
	MaintenanceID string                  `json:"maintenance_id"`
	Source        nginxruntime.Input      `json:"source"`
	WorkerUser    string                  `json:"worker_user"`
	Policy        nginxconfig.Policy      `json:"policy"`
	Modules       []nginxmodules.Approval `json:"modules"`
	Start         bool                    `json:"start"`
	Enable        bool                    `json:"enable"`
}
type NginxInstallIntent struct {
	Sequence     int                        `json:"sequence,omitempty"`
	Command      string                     `json:"command,omitempty"`
	Input        NginxInstallInput          `json:"input"`
	Before       *nginxruntime.Binding      `json:"before,omitempty"`
	Candidate    *nginxruntime.Binding      `json:"candidate,omitempty"`
	Installation *nginxruntime.Installation `json:"installation,omitempty"`
	Running      bool                       `json:"running"`
}
type NginxInstallOptions struct {
	Input              NginxInstallInput
	OperationID, Epoch string
	Resume, Abort      bool
}

func installHash(id string, in NginxInstallInput) string {
	raw, _ := json.Marshal(struct {
		Protocol    int
		OperationID string
		Input       NginxInstallInput
	}{protocol.Journal, id, in})
	return secure.Hash(raw)
}
func validInstallRecord(r Record) error {
	if r.Kind != nginxInstallKind || r.NginxInstall == nil || r.NginxSwitch != nil || r.NginxSwitchJob != nil || !validID(r.OperationID) || !validID(r.NginxInstall.Input.MaintenanceID) || r.RequestHash != installHash(r.OperationID, r.NginxInstall.Input) || r.Deadline <= 0 {
		return errors.New("Nginx 安装记录无效")
	}
	in := r.NginxInstall.Input
	if api := in.API; api != nil {
		if api.Validate() != nil || api.MaintenanceID != in.MaintenanceID || api.PlanID != in.Source.PlanID || api.AssetID != in.Source.AssetID || api.Prerelease != in.Source.Prerelease || api.Start != in.Start || api.Enable != in.Enable || r.NginxInstall.Sequence < 1 || r.NginxInstall.Sequence > 32 || (r.NginxInstall.Command != "install" && r.NginxInstall.Command != "resume" && r.NginxInstall.Command != "cancel") || (r.NginxInstall.Sequence == 1) != (r.NginxInstall.Command == "install") {
			return errors.New("Nginx 安装 API 意图与原始记录不一致")
		}
	}
	switch r.State {
	case "queued", "running", "recovery_required", "succeeded", "failed", "cancelled":
	default:
		return errors.New("Nginx 安装状态无效")
	}
	switch r.Stage {
	case "queued", "validating", "initializing", "binding", "enabling", "starting", "restarting_agent", "confirming", "installed", "running", "cancelled_before_binding":
	default:
		return errors.New("Nginx 安装阶段无效")
	}
	return nil
}
func installTerminal(state string) bool {
	return state == "succeeded" || state == "failed" || state == "cancelled"
}
