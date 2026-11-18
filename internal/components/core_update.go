package components

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"slices"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/software"
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

// CheckCoreUpgrade verifies the release metadata without downloading the package.
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

type CoreUpdateCandidate struct {
	Release       Release `json:"release"`
	RuntimeReason string  `json:"runtime_reason"`
}

func (m *Manager) CheckCoreUpdate(ctx context.Context, prerelease bool) (CoreUpdateCandidate, error) {
	var out CoreUpdateCandidate
	if overview := m.Overview(); !overview.Available {
		return out, fault.Unavailable(overview.Reason)
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	plan, err := CheckCoreUpgrade(ctx, m.TrustPath, m.TokenPath, "", prerelease)
	if ctx.Err() != nil {
		return out, fault.Unavailable("检查更新超时，请稍后重试")
	}
	if err != nil {
		return out, fault.Unavailable("检查更新失败：" + bounded(err.Error()))
	}
	if panel, err := panelSelection(plan); err != nil || !panel || len(plan.Selected) != 1 {
		return out, fault.Unavailable("发行版缺少适用于本机的核心安装包")
	}
	out.Release = release(plan)
	if m.UpdatePanel == nil {
		out.RuntimeReason = "此安装暂不支持在线升级。"
	} else if err := releases.RuntimeReadiness(ctx, plan.Assets); err != nil {
		out.RuntimeReason = bounded(err.Error())
	}
	return out, nil
}

type CoreUpdateCheck struct {
	CoreUpdateStatus
	Version      string `json:"version"`
	Channel      string `json:"channel"`
	Notes        string `json:"notes"`
	ArchiveBytes int64  `json:"archive_bytes"`
	Confirmation []byte `json:"confirmation,omitempty"`
}

type coreUpdateSelection struct {
	Input     Input  `json:"input"`
	Version   string `json:"version"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Service) CheckCoreUpdate(ctx context.Context, p auth.Principal, channel string) (CoreUpdateCheck, error) {
	var out CoreUpdateCheck
	if err := p.Require("read", "components.manage"); err != nil {
		return out, err
	}
	if channel != "stable" && channel != "beta" {
		return out, fault.Invalid("请选择稳定版或 Beta 更新通道")
	}
	if s.Agent == nil {
		return out, fault.Unavailable("本机组件服务不可用")
	}
	candidate, err := s.Agent.CheckCoreUpdate(ctx, channel == "beta")
	if err != nil {
		return out, err
	}
	r := candidate.Release
	if !isCoreRelease(&r) || len(r.Selected) != 1 || r.ExpiresAt <= time.Now().Unix() {
		return out, fault.Unavailable("核心发行信息无效或已过期，请重新检查")
	}
	out = CoreUpdateCheck{
		CoreUpdateStatus: coreUpdateStatus(s.Version, r.Version),
		Version:          r.Version,
		Channel:          r.Channel,
		Notes:            r.Notes,
		ArchiveBytes:     r.ArchiveBytes,
	}
	if out.State != "available" {
		return out, nil
	}
	if candidate.RuntimeReason != "" {
		out.Message = candidate.RuntimeReason
		return out, nil
	}
	if p.Require("system.write") != nil {
		return out, nil
	}
	input := Input{Action: "software", Tag: r.Tag, Assets: r.Selected, ManifestSHA256: r.ManifestSHA256, TrustSHA256: r.TrustSHA256,
		Software: &software.Request{Action: "update-panel", PlanID: r.PlanID, Prerelease: channel == "beta"}}
	if err := input.Validate(); err != nil {
		return out, err
	}
	raw, err := json.Marshal(coreUpdateSelection{Input: input, Version: r.Version, ExpiresAt: r.ExpiresAt})
	if err != nil {
		return out, err
	}
	out.Confirmation = s.Vault.Seal(raw, "core-update:"+p.ID)
	return out, nil
}

func (s *Service) confirmedCoreUpdate(p auth.Principal, confirmation []byte, now int64) (Input, error) {
	raw, err := s.Vault.Open(confirmation, "core-update:"+p.ID)
	var selection coreUpdateSelection
	if err != nil || json.Unmarshal(raw, &selection) != nil || selection.ExpiresAt <= now ||
		coreUpdateStatus(s.Version, selection.Version).State != "available" {
		return Input{}, fault.Conflict("更新结果已失效，请重新检查")
	}
	return selection.Input, nil
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
