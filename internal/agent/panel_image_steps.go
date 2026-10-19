package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"nginxpanel/internal/launcher"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

func panelImageBaseline(ctx context.Context, j *Journal, s panelruntime.Snapshot, expected PanelServiceObservation, id, epoch string) (PanelReadiness, error) {
	parent, err := panelReadinessParent(ctx, s, expected)
	if err != nil {
		return PanelReadiness{}, err
	}
	status, _, err := panelready.Read(ctx, s, expected.PID, parent)
	if err != nil {
		return PanelReadiness{}, err
	}
	lease, err := j.Get(id)
	if err != nil {
		return PanelReadiness{}, err
	}
	return observePanelReadinessSource(ctx, s, id, lease.RequestHash, selectionValueHash(s.Deployment), id, epoch, expected, panelImageDatabase(status), func(ctx context.Context) error {
		current, err := panelruntime.Read(s.Deployment.DataDir)
		if err != nil {
			return err
		}
		if selectionValueHash(current) != selectionValueHash(s) {
			return errors.New("镜像替换授权期间原程序材料变化")
		}
		return ctx.Err()
	}, func(ctx context.Context, closing bool) error {
		return panelReadinessGrant(ctx, j, s.Deployment.DataDir, id, epoch, closing)
	})
}

func (w *panelImageWorker) labels(d panelruntime.Deployment, direction string) map[string]string {
	return panelImageLabels(w.r.PanelImage.Intent.Container.Labels, w.r.PanelImage.Intent.TargetLabels, w.r.OperationID, d, direction)
}
func panelImageLabels(original, imageLabels map[string]string, id string, d panelruntime.Deployment, direction string) map[string]string {
	labels := map[string]string{}
	if direction == "forward" {
		for k, v := range imageLabels {
			labels[k] = v
		}
	}
	for k, v := range original {
		labels[k] = v
	}
	labels[panelruntime.DockerOperationLabel] = id
	labels[panelruntime.DockerDirectionLabel] = direction
	labels[panelruntime.DockerBindingLabel] = selectionValueHash(d)
	return labels
}

// Only the frozen original instance or an instance created by this exact root
// operation can be stopped, adopted after a lost response, or removed.
func (w *panelImageWorker) container(ctx context.Context) (panelruntime.DockerContainer, panelruntime.Deployment, error) {
	p := w.r.PanelImage
	i := p.Intent
	var last error
	for _, d := range []panelruntime.Deployment{i.Before, i.Target} {
		c, err := panelruntime.ReadDockerContainer(ctx, d)
		if os.IsNotExist(err) {
			return c, d, err
		}
		if err != nil {
			last = err
			continue
		}
		if c.Instance.ID == i.Container.Instance.ID {
			expected := i.Container.Instance
			if p.ResumedOriginal != nil {
				expected = *p.ResumedOriginal
			}
			if d != i.Before || selectionValueHash(c.Labels) != selectionValueHash(i.Container.Labels) || c.Instance.StartedAt != expected.StartedAt || c.Instance.RestartCount != expected.RestartCount {
				return c, d, errors.New("原面板容器发生外部重建或重启")
			}
			return c, d, nil
		}
		direction, known := "forward", p.TargetContainerID
		if d == i.Before {
			direction, known = "rollback", p.RollbackContainerID
		}
		if selectionValueHash(c.Labels) != selectionValueHash(w.labels(d, direction)) || known != "" && c.Instance.ID != known {
			return c, d, errors.New("面板名称已被其他容器占用或原实例消失")
		}
		if known == "" {
			if d == i.Target && w.r.Stage != "creating" && w.r.Stage != "rollback_stopping" || d == i.Before && w.r.Stage != "rollback_creating" {
				return c, d, errors.New("当前阶段没有创建此容器的持久意图")
			}
			if d == i.Before {
				p.RollbackContainerID = c.Instance.ID
			} else {
				p.TargetContainerID = c.Instance.ID
			}
			if err = w.save(); err != nil {
				return c, d, err
			}
		}
		return c, d, nil
	}
	return panelruntime.DockerContainer{}, panelruntime.Deployment{}, last
}

func (w *panelImageWorker) stop(ctx context.Context, c panelruntime.DockerContainer, d panelruntime.Deployment) error {
	if c.State != "running" {
		return nil
	}
	// Docker's stop request can outlive the transport's bounded read. Reconcile
	// the exact ID until stopped; a timeout never means the stop was undone.
	requestErr := panelruntime.DockerAction(ctx, d, c.Instance.ID, "stop")
	wait, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	for {
		now, actual, err := w.container(wait)
		if err != nil {
			return errors.Join(requestErr, err)
		}
		if actual != d || now.Instance.ID != c.Instance.ID {
			return errors.New("停止期间面板容器实例变化")
		}
		if now.State != "running" {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.Join(requestErr, wait.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (w *panelImageWorker) selection(d panelruntime.Deployment, compose []byte) error {
	current, err := panelruntime.ReadDeployment(d.DataDir)
	if err != nil {
		return err
	}
	raw, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return err
	}
	if current != d || !bytes.Equal(raw, compose) {
		return errors.New("镜像运行绑定或 Compose 尚未完成切换")
	}
	return nil
}

func (w *panelImageWorker) create(ctx context.Context, d panelruntime.Deployment, direction string) error {
	p := w.r.PanelImage
	known := p.TargetContainerID
	if direction == "rollback" {
		known = p.RollbackContainerID
	}
	c, actual, err := w.container(ctx)
	if os.IsNotExist(err) {
		if known != "" {
			return errors.New("原事务已登记的容器丢失，禁止创建替代实例")
		}
		id, createErr := panelruntime.CreateDockerContainer(ctx, d, w.labels(d, direction))
		if id != "" {
			if direction == "rollback" {
				p.RollbackContainerID = id
			} else {
				p.TargetContainerID = id
			}
			if err = w.save(); err != nil {
				return errors.Join(createErr, err)
			}
		}
		if createErr != nil {
			return createErr
		}
		c, actual, err = w.container(ctx)
	}
	if err != nil {
		return err
	}
	if actual != d || c.State != "created" || selectionValueHash(c.Labels) != selectionValueHash(w.labels(d, direction)) {
		return errors.New("新容器尚未按原方向完成创建")
	}
	return nil
}

func (w *panelImageWorker) start(ctx context.Context, d panelruntime.Deployment, id string, compose []byte) error {
	if err := w.selection(d, compose); err != nil {
		return err
	}
	c, actual, err := w.container(ctx)
	if err != nil {
		return err
	}
	if actual != d || c.Instance.ID != id {
		return errors.New("待启动的容器不是原事务新实例")
	}
	if err = storage.ClearServiceHold(d.DataDir, w.hold()); err != nil {
		return err
	}
	return panelruntime.DockerAction(ctx, d, id, "start")
}

func (w *panelImageWorker) ready(ctx context.Context, d panelruntime.Deployment, id string) (PanelReadiness, error) {
	var zero PanelReadiness
	p := w.r.PanelImage
	i := p.Intent
	current, err := panelruntime.Read(d.DataDir)
	if err != nil {
		return zero, err
	}
	if current.Deployment != d {
		return zero, errors.New("就绪容器绑定不是原事务的选定镜像")
	}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var expected PanelServiceObservation
	for {
		if err = w.guard(wait, false); err != nil {
			return zero, err
		}
		c, actual, err := w.container(wait)
		if err != nil {
			return zero, err
		}
		if actual != d || c.Instance.ID != id || c.State != "running" {
			return zero, errors.New("新面板容器未运行或实际实例变化")
		}
		expected, err = observePanelService(wait, current)
		if err == nil && expected.State == "running" {
			break
		}
		// A fresh container may not yet have published its launcher socket.
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, panelready.ErrNotReady) && !errors.Is(err, launcher.ErrUnavailable) {
			return zero, err
		}
		select {
		case <-wait.Done():
			return zero, errors.Join(err, wait.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	material := func(ctx context.Context) error {
		if err := w.guard(ctx, false); err != nil {
			return err
		}
		c, actual, err := w.container(ctx)
		if err != nil {
			return err
		}
		if actual != d || c.Instance.ID != id || c.State != "running" {
			return errors.New("就绪期间实际容器变化")
		}
		compose := i.TargetCompose
		if d == i.Before {
			compose = i.BeforeCompose
		}
		return w.selection(d, compose)
	}
	grant := func(ctx context.Context, closing bool) error {
		if err := w.grant(ctx, closing); err != nil {
			return err
		}
		held, err := storage.ServiceHeld(d.DataDir)
		if err != nil {
			return err
		}
		if held {
			return errors.New("镜像替换仍保留停机标记")
		}
		fenced, err := storage.WriterFenced(d.DataDir)
		if err != nil {
			return err
		}
		if fenced {
			return errors.New("镜像替换期间数据恢复尚未完成")
		}
		return nil
	}
	out, err := observePanelReadinessSource(ctx, current, w.r.OperationID, w.r.RequestHash, selectionValueHash(d), i.Input.MaintenanceID, p.Epoch, expected, panelImageDatabase(i.Baseline.Application), material, grant)
	if err != nil {
		return out, err
	}
	if out.HTTPS != i.Baseline.HTTPS || out.Application.Configuration != i.Baseline.Application.Configuration {
		return zero, errors.New("镜像替换后的前端、TLS 或配置状态偏离原运行证据")
	}
	return out, nil
}

func (w *panelImageWorker) forward(ctx context.Context) error {
	p := w.r.PanelImage
	i := p.Intent
	for {
		if err := w.guard(ctx, true); err != nil {
			return err
		}
		switch w.r.Stage {
		case "authorized":
			if err := nginxcontainer.InspectPanelImage(ctx, i.Before.Image, i.Before.ImageID, i.Before.LauncherSHA256); err != nil {
				return err
			}
			if err := nginxcontainer.InspectPanelImage(ctx, i.Target.Image, i.Target.ImageID, i.Target.LauncherSHA256); err != nil {
				return err
			}
			if err := w.stage("stopping"); err != nil {
				return err
			}
		case "stopping":
			if err := storage.BindServiceHold(i.Before.DataDir, w.hold()); err != nil {
				return err
			}
			c, d, err := w.container(ctx)
			if err != nil {
				return err
			}
			if c.Instance.ID != i.Container.Instance.ID || d != i.Before {
				return errors.New("原面板容器不再是停止目标")
			}
			if err = w.stop(ctx, c, d); err != nil {
				return err
			}
			if err = w.stage("removing"); err != nil {
				return err
			}
		case "removing":
			c, d, err := w.container(ctx)
			if err == nil {
				if c.Instance.ID != i.Container.Instance.ID || d != i.Before {
					return errors.New("原面板容器不再是删除目标")
				}
				if err = panelruntime.DockerAction(ctx, d, c.Instance.ID, "remove"); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
			if err = w.stage("selecting"); err != nil {
				return err
			}
		case "selecting":
			if _, _, err := w.container(ctx); !os.IsNotExist(err) {
				return errors.Join(errors.New("切换镜像前固定容器名称必须空闲"), err)
			}
			if err := panelruntime.SelectDockerImage(i.Before, i.Target, i.BeforeCompose, i.TargetCompose); err != nil {
				return err
			}
			if err := w.stage("creating"); err != nil {
				return err
			}
		case "creating":
			if err := w.selection(i.Target, i.TargetCompose); err != nil {
				return err
			}
			if err := w.create(ctx, i.Target, "forward"); err != nil {
				return err
			}
			if err := w.stage("starting"); err != nil {
				return err
			}
		case "starting":
			if err := w.start(ctx, i.Target, p.TargetContainerID, i.TargetCompose); err != nil {
				return err
			}
			if err := w.stage("checking"); err != nil {
				return err
			}
		case "checking":
			ready, err := w.ready(ctx, i.Target, p.TargetContainerID)
			if err != nil {
				return err
			}
			if err = w.guard(ctx, true); err != nil {
				return err
			}
			p.Ready = &ready
			w.r.State, w.r.Stage, w.r.Error = "succeeded", "committed", ""
			return w.save()
		default:
			return errors.New("镜像替换前进阶段未知")
		}
	}
}

func (w *panelImageWorker) compensate(ctx context.Context) error {
	p := w.r.PanelImage
	i := p.Intent
	if err := w.guard(ctx, false); err != nil {
		return err
	}
	// Restoration needs the retained original image, never the target signature
	// or source files which may have caused the forward operation to fail.
	if err := nginxcontainer.InspectPanelImage(ctx, i.Before.Image, i.Before.ImageID, i.Before.LauncherSHA256); err != nil {
		return err
	}
	for {
		if err := w.guard(ctx, false); err != nil {
			return err
		}
		switch w.r.Stage {
		case "rollback_stopping":
			c, d, err := w.container(ctx)
			if err == nil && c.Instance.ID == i.Container.Instance.ID && c.State == "running" && w.selection(i.Before, i.BeforeCompose) == nil {
				if err = storage.ClearServiceHold(d.DataDir, w.hold()); err != nil {
					return err
				}
				ready, readyErr := w.ready(ctx, d, c.Instance.ID)
				if readyErr == nil {
					p.RollbackReady = &ready
					w.r.State, w.r.Stage, w.r.Error = "rolled_back", "compensated", ""
					return w.save()
				}
				return readyErr
			}
			if err = storage.BindServiceHold(i.Before.DataDir, w.hold()); err != nil {
				return err
			}
			c, d, err = w.container(ctx)
			if err == nil {
				if err = w.stop(ctx, c, d); err != nil {
					return err
				}
				if err = panelruntime.DockerAction(ctx, d, c.Instance.ID, "remove"); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
			if err = w.stage("rollback_selecting"); err != nil {
				return err
			}
		case "rollback_selecting":
			if _, _, err := w.container(ctx); !os.IsNotExist(err) {
				return errors.Join(errors.New("恢复原镜像前固定容器名称必须空闲"), err)
			}
			if err := panelruntime.SelectDockerImage(i.Target, i.Before, i.TargetCompose, i.BeforeCompose); err != nil {
				return err
			}
			if err := w.stage("rollback_creating"); err != nil {
				return err
			}
		case "rollback_creating":
			if err := w.selection(i.Before, i.BeforeCompose); err != nil {
				return err
			}
			if err := w.create(ctx, i.Before, "rollback"); err != nil {
				return err
			}
			if err := w.stage("rollback_starting"); err != nil {
				return err
			}
		case "rollback_starting":
			if err := w.start(ctx, i.Before, p.RollbackContainerID, i.BeforeCompose); err != nil {
				return err
			}
			if err := w.stage("rollback_checking"); err != nil {
				return err
			}
		case "rollback_checking":
			ready, err := w.ready(ctx, i.Before, p.RollbackContainerID)
			if err != nil {
				return err
			}
			p.RollbackReady = &ready
			w.r.State, w.r.Stage, w.r.Error = "rolled_back", "compensated", ""
			return w.save()
		default:
			return errors.New("镜像恢复阶段未知")
		}
	}
}
