package migration

import "nginxpanel/internal/components"

// This authorization permits signed asset preparation from local release trust.
// It never grants package installation, instance replacement or module loading.
type DependencyInput struct {
	Tag        string `json:"tag"`
	Prerelease bool   `json:"prerelease"`
}

func (in DependencyInput) validate() error {
	return (components.Input{Action: "check", Tag: in.Tag, Prerelease: in.Prerelease, Components: []string{"nginx"}}).Validate()
}

type DependencyStatus struct {
	TaskID        string `json:"task_id"`
	State         string `json:"state"`
	Stage         string `json:"stage"`
	CheckTaskID   string `json:"check_task_id"`
	PrepareTaskID string `json:"prepare_task_id"`
	Error         string `json:"error"`
	Deadline      int64  `json:"deadline"`
}
