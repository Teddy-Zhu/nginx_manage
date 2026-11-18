package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/software"
)

// ApplyCoreUpgrade is also used from the host when the management UI is down.
func ApplyCoreUpgrade(ctx context.Context, data, trust, id string, in software.Request, progress software.Progress) (software.Result, error) {
	s := Server{DataDir: data, ReleaseTrust: trust, Journal: &Journal{Dir: filepath.Join(data, "agent", "operations")}}
	return s.updateSoftwarePanel(ctx, id, in, progress)
}

// The signed update is owned by a detached host worker. Cancellation during
// the core restart leaves this component task pending for the new core to
// reconcile, rather than reporting a failed or completed upgrade prematurely.
func (s *Server) updateSoftwarePanel(ctx context.Context, id string, in software.Request, progress software.Progress) (software.Result, error) {
	out := software.Result{}
	source := panelruntime.StageInput{DataDir: s.DataDir, PlanID: in.PlanID, TrustPath: s.ReleaseTrust, AllowPrerelease: in.Prerelease}
	prior, err := coreUpdateRecord(s.Journal, id, s.DataDir)
	if err == nil {
		if prior.CoreUpdate.Source != source {
			return out, errors.New("核心更新与原下载任务不一致")
		}
		if prior.State == "succeeded" {
			out.Message = "系统已更新并启动"
			return out, nil
		}
		if prior.State == "failed" {
			return out, errors.New(prior.Error)
		}
	} else if !os.IsNotExist(err) {
		return out, err
	}
	staged, err := panelruntime.Staged(ctx, source)
	if err != nil {
		return out, err
	}
	if err = staged.RequireCurrent(); err != nil {
		return out, err
	}
	before, err := panelruntime.Read(s.DataDir)
	if err != nil {
		return out, err
	}
	if before.Deployment.Mode != "native" || before.Deployment.UID != 0 {
		return out, errors.New("请重新安装为宿主机单服务后再更新核心程序")
	}
	if before.Release.ID == staged.Release.ID {
		if _, err = coreUpdateRecord(s.Journal, id, s.DataDir); os.IsNotExist(err) {
			out.Message = "当前已是此版本"
			return out, nil
		}
	}
	progress("正在准备核心更新，连接将短暂中断")
	if err = s.queueCoreUpdate(ctx, id, source); err != nil {
		return out, err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	stages := map[string]string{"queued": "等待更新执行", "stopping": "正在停止核心服务", "selecting": "正在替换核心程序", "starting": "正在启动核心服务并完成数据迁移"}
	previous := ""
	for {
		r, err := coreUpdateRecord(s.Journal, id, s.DataDir)
		if err != nil {
			if os.IsNotExist(err) {
				current, readErr := panelruntime.Read(s.DataDir)
				if readErr == nil && current.Release.ID == staged.Release.ID {
					out.Message = "当前已是此版本"
					return out, nil
				}
			}
			return out, err
		}
		if r.CoreUpdate.Source != source {
			return out, errors.New("核心更新与原下载任务不一致")
		}
		switch r.State {
		case "succeeded":
			out.Message = "系统已更新并启动"
			return out, nil
		case "failed":
			return out, errors.New(r.Error)
		}
		if text := stages[r.Stage]; text != "" && r.Stage != previous {
			progress(text)
			previous = r.Stage
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return out, components.ErrRestartPending
			}
			return out, fmt.Errorf("等待系统更新结果超时，请查看更新日志: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func panelreadyForSoftware(ctx context.Context, s panelruntime.Snapshot) (bool, int, error) {
	observation, err := observePanelService(ctx, s)
	if err != nil {
		return false, 0, err
	}
	parent, err := panelReadinessParent(ctx, s, observation)
	if err != nil {
		return false, 0, err
	}
	status, err := panelready.ReadHealthy(ctx, s, observation.PID, parent)
	if err != nil {
		return false, 0, err
	}
	if err = panelReadinessListener(ctx, observation.PID, s.Deployment.Listen); err != nil {
		return false, 0, err
	}
	if _, err = panelready.CheckListener(ctx, s, status.NodeID); err != nil {
		return false, 0, err
	}
	after, err := observePanelService(ctx, s)
	if err != nil {
		return false, 0, err
	}
	if after != observation {
		return false, 0, errors.New("核心服务在启动校验期间发生变化")
	}
	return status.DatabaseSchema == s.Release.DatabaseSchema, status.PID, nil
}
