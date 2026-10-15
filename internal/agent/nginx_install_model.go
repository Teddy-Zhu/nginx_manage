package agent

import (
	"encoding/json"
	"errors"

	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/secure"
)

const nginxInstallKind = "component.nginx.install"

type NginxInstallInput struct {
	MaintenanceID string                  `json:"maintenance_id"`
	Source        nginxruntime.Input      `json:"source"`
	WorkerUser    string                  `json:"worker_user"`
	Policy        nginxconfig.Policy      `json:"policy"`
	Modules       []nginxmodules.Approval `json:"modules"`
	Start         bool                    `json:"start"`
	Enable        bool                    `json:"enable"`
}
type NginxInstallIntent struct {
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
	}{Protocol, id, in})
	return secure.Hash(raw)
}
func validInstallRecord(r Record) error {
	if r.Kind != nginxInstallKind || r.NginxInstall == nil || !validID(r.OperationID) || !validID(r.NginxInstall.Input.MaintenanceID) || r.RequestHash != installHash(r.OperationID, r.NginxInstall.Input) || r.Deadline <= 0 {
		return errors.New("Nginx 安装记录无效")
	}
	switch r.State {
	case "running", "recovery_required", "succeeded", "failed", "cancelled":
	default:
		return errors.New("Nginx 安装状态无效")
	}
	switch r.Stage {
	case "validating", "initializing", "binding", "enabling", "starting", "restarting_agent", "confirming", "installed", "running", "cancelled_before_binding":
	default:
		return errors.New("Nginx 安装阶段无效")
	}
	return nil
}
func installTerminal(state string) bool {
	return state == "succeeded" || state == "failed" || state == "cancelled"
}
