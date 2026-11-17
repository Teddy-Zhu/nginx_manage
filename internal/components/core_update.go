package components

import (
	"errors"
	"slices"

	"nginxpanel/internal/releases"
)

var ErrRestartPending = errors.New("core restart in progress")

type CoreUpdateStatus struct {
	CurrentVersion string `json:"current_version"`
	State          string `json:"state"`
	Message        string `json:"message,omitempty"`
}

func isCoreRelease(release *Release) bool {
	if release != nil {
		for _, asset := range release.Assets {
			if asset.Component == "panel" && slices.Contains(release.Selected, asset.ID) {
				return true
			}
		}
	}
	return false
}

func coreUpdateStatus(current, target string) CoreUpdateStatus {
	out := CoreUpdateStatus{CurrentVersion: current}
	comparison, err := releases.CompareVersions(current, target)
	switch {
	case err != nil:
		out.State, out.Message = "unknown", "无法比较程序版本，请确认安装的是有效发行版本。"
	case comparison < 0:
		out.State = "available"
	case comparison == 0:
		out.State = "current"
	default:
		out.State = "older"
	}
	return out
}

func (s *Service) withCoreUpdate(task Task) Task {
	if task.Result != nil && isCoreRelease(task.Result.Release) {
		status := coreUpdateStatus(s.Version, task.Result.Release.Version)
		task.CoreUpdate = &status
	}
	return task
}
