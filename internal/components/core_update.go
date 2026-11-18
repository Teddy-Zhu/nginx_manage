package components

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/releases"
)

// PrepareCoreUpgrade authenticates the confirmed release and stages it without
// affecting the running service. A restarted core can reuse its original approval.
func PrepareCoreUpgrade(ctx context.Context, data, trust, token string, input Input, progress func(string)) error {
	online := input.coreOnline()
	source := panelruntime.StageInput{DataDir: data, PlanID: online.ExpectedPlanID, TrustPath: trust, AllowPrerelease: online.AllowPrerelease}
	staged, err := panelruntime.Staged(ctx, source)
	if errors.Is(err, os.ErrNotExist) {
		progress("正在下载并验证更新")
		online.TrustPath, online.TokenPath = trust, token
		host := platform.Detect()
		online.Host = releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: host.OS, Version: host.Version}
		online.Receiver = receiver()
		if _, err = releases.Online(ctx, online); err != nil {
			return err
		}
		progress("正在准备安装")
		staged, err = panelruntime.Stage(ctx, source)
	}
	if err != nil {
		return err
	}
	if staged.Approval.ManifestSHA256 != online.ExpectedManifestSHA256 || staged.Approval.TrustSHA256 != online.ExpectedTrustSHA256 {
		return releases.ErrReleaseChanged
	}
	return staged.RequireCurrent()
}

// CheckCoreUpgrade is the read-only check used by the host command when the web
// process is unavailable.
func CheckCoreUpgrade(ctx context.Context, trust, token, tag string, prerelease bool) (releases.Plan, error) {
	host := platform.Detect()
	result, err := releases.Online(ctx, releases.OnlineInput{
		TrustPath: trust, TokenPath: token, Tag: tag, AllowPrerelease: prerelease,
		PanelStaging: true, Components: []string{"panel"}, AllowedComponents: []string{"panel"},
		Host:     releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: host.OS, Version: host.Version},
		Receiver: receiver(),
	})
	return result.Plan, err
}

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
