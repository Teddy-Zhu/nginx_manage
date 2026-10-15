package migration

import (
	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
)

// Installation requires a separate explicit grant. Neither option permits
// system package installation, instance replacement or runtime module loading.
type DependencyInput struct {
	Tag        string                  `json:"tag"`
	Prerelease bool                    `json:"prerelease"`
	Install    *DependencyInstallInput `json:"install,omitempty"`
}

type DependencyInstallInput struct {
	Start  *bool `json:"start"`
	Enable *bool `json:"enable"`
}

func (in DependencyInput) validate() error {
	if in.Install != nil && (in.Install.Start == nil || in.Install.Enable == nil) {
		return fault.Invalid("首次安装须明确指定启动和开机启用选项")
	}
	return (components.Input{Action: "check", Tag: in.Tag, Prerelease: in.Prerelease, Components: []string{"nginx"}}).Validate()
}

type DependencyStatus struct {
	TaskID            string `json:"task_id"`
	State             string `json:"state"`
	Stage             string `json:"stage"`
	CheckTaskID       string `json:"check_task_id"`
	PrepareTaskID     string `json:"prepare_task_id"`
	MaintenanceTaskID string `json:"maintenance_task_id"`
	InstallTaskID     string `json:"install_task_id"`
	Error             string `json:"error"`
	Deadline          int64  `json:"deadline"`
	SettlementState   string `json:"-"`
	SettlementStage   string `json:"-"`
	SettlementError   string `json:"-"`
}
