package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"nginxpanel/internal/storage"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Updates run in the host Agent, so replacing the panel does not interrupt the
// job. Only the panel process is stopped; no maintenance lease is created.
func (s *Server) updateSoftwarePanel(ctx context.Context, in software.Request, progress software.Progress) (software.Result, error) {
	out := software.Result{}
	staged, err := panelruntime.Staged(ctx, panelruntime.StageInput{DataDir: s.DataDir, PlanID: in.PlanID, TrustPath: s.ReleaseTrust, AllowPrerelease: in.Prerelease})
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
	if before.Release.ID == staged.Release.ID {
		ready, _, readyErr := panelreadyForSoftware(ctx, before)
		if readyErr == nil && ready {
			out.Message = "当前已是此版本"
			return out, nil
		}
		if err = s.startSoftwarePanel(ctx, before.Deployment); err != nil {
			return out, err
		}
		return s.waitSoftwarePanel(ctx, staged.Release.ID, progress)
	}
	target := before.Deployment
	var oldCompose, newCompose bytes.Buffer
	if target.Mode == "docker" {
		progress("正在拉取面板镜像")
		source, err := releases.Prepared(ctx, releases.Input{PanelStaging: true, TrustPath: s.ReleaseTrust, Assets: []string{"panel-linux-" + runtime.GOARCH}, AllowedComponents: []string{"panel"}, AllowPrerelease: in.Prerelease, Host: staged.Approval.Host, Receiver: staged.Approval.Receiver}, in.PlanID)
		if err != nil {
			return out, err
		}
		image := ""
		for _, choice := range source.Plan.Manifest.Images {
			if choice.ID == "panel-launcher" {
				image = choice.Repository + "@" + choice.Digest
			}
		}
		if image == "" {
			return out, errors.New("此发行未提供面板镜像")
		}
		out.Log, err = software.Docker(ctx, progress, "pull", image)
		if err != nil {
			return out, err
		}
		signature := releases.ImageInput{TrustPath: s.ReleaseTrust, ManifestPath: filepath.Join(source.Directory, "release-manifest.json"), SignaturePath: filepath.Join(source.Directory, "release-manifest.sig"), ExpectedManifestSHA256: source.Plan.ManifestSHA256, AllowPrerelease: in.Prerelease, PanelStaging: true}
		approval, _, err := releases.AdmitImage(signature, "panel-launcher", image, nil)
		if err != nil {
			return out, err
		}
		if approval.ManifestSHA256 != staged.Approval.ManifestSHA256 || approval.Version != staged.Release.Version || approval.Image.Platform.LauncherSHA256 != staged.Release.BinarySHA256 {
			return out, errors.New("面板程序与镜像不属于同一发行")
		}
		imageID, err := nginxcontainer.InspectPanelImage(ctx, image, approval.Image.Platform.ConfigDigest, approval.Image.Platform.LauncherSHA256)
		if err != nil {
			return out, err
		}
		target.Image, target.ImageID, target.LauncherRelease, target.LauncherSHA256, target.SignedImage = image, imageID, staged.Release.ID, staged.Release.BinarySHA256, approval
		if err = panelruntime.ComposeDeployment(&oldCompose, before.Deployment); err != nil {
			return out, err
		}
		if err = panelruntime.ComposeDeployment(&newCompose, target); err != nil {
			return out, err
		}
	}
	progress("正在重启面板，连接将短暂中断")
	if target.Mode == "docker" {
		container, err := panelruntime.ReadDockerContainer(ctx, before.Deployment)
		if err != nil && !os.IsNotExist(err) {
			return out, err
		}
		if err == nil {
			if err = panelruntime.DockerAction(ctx, before.Deployment, container.Instance.ID, "stop"); err != nil {
				return out, err
			}
			if err = panelruntime.DockerAction(ctx, before.Deployment, container.Instance.ID, "remove"); err != nil {
				return out, err
			}
		}
	} else {
		raw, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", "nginxpanel.service").CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("停止面板失败：%s", raw)
		}
	}
	// The old process has exited before the writer lock and pointer change.
	unlock, err := storage.LockWriter(s.DataDir, before.Deployment.GID)
	if err != nil {
		return out, s.restartAfterUpdateError(ctx, target, err)
	}
	operation := secure.ID()
	if target.Mode == "docker" && target != before.Deployment {
		err = panelruntime.SelectDockerImage(before.Deployment, target, oldCompose.Bytes(), newCompose.Bytes())
	}
	if err == nil {
		err = panelruntime.SwitchCurrent(s.DataDir, before.Release.ID, staged.Release.ID, operation)
	}
	unlock()
	if err != nil {
		return out, s.restartAfterUpdateError(ctx, target, err)
	}
	if err = s.startSoftwarePanel(ctx, target); err != nil {
		return out, err
	}
	return s.waitSoftwarePanel(ctx, staged.Release.ID, progress)
}
func (s *Server) waitSoftwarePanel(ctx context.Context, releaseID string, progress software.Progress) (software.Result, error) {
	out := software.Result{}
	progress("正在等待面板启动并完成数据迁移")
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		current, err := panelruntime.Read(s.DataDir)
		if err == nil && current.Release.ID == releaseID {
			// Query the registered application through the existing local readiness
			// channel; startup runs database migrations before serving readiness.
			state, _, checkErr := panelreadyForSoftware(ctx, current)
			if checkErr == nil && state {
				out.Message = "面板已更新并启动"
				return out, nil
			}
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-deadline.C:
			return out, errors.New("面板未在预期时间内启动，请查看服务日志；数据已保留")
		case <-ticker.C:
		}
	}
}
func (s *Server) startSoftwarePanel(ctx context.Context, d panelruntime.Deployment) error {
	if d.Mode != "docker" {
		raw, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", "nginxpanel.service").CombinedOutput()
		if err != nil {
			return fmt.Errorf("启动面板失败：%s", raw)
		}
		return nil
	}
	current, err := panelruntime.ReadDockerContainer(ctx, d)
	if err == nil {
		if current.State == "running" {
			return nil
		}
		return panelruntime.DockerAction(ctx, d, current.Instance.ID, "start")
	}
	if !os.IsNotExist(err) {
		return err
	}
	labels, err := panelruntime.DockerImageLabels(ctx, d)
	if err != nil {
		return err
	}
	id, err := panelruntime.CreateDockerContainer(ctx, d, labels)
	if err != nil {
		return err
	}
	return panelruntime.DockerAction(ctx, d, id, "start")
}
func (s *Server) restartAfterUpdateError(ctx context.Context, d panelruntime.Deployment, cause error) error {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	current, err := panelruntime.ReadDeployment(s.DataDir)
	if err == nil {
		d = current
	}
	if err = s.startSoftwarePanel(recovery, d); err != nil {
		return fmt.Errorf("%w；恢复启动失败：%v", cause, err)
	}
	return cause
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
	return status.DatabaseSchema == s.Release.DatabaseSchema, status.PID, nil
}
