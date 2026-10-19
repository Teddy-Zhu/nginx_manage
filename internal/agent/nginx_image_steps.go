package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func (w *nginxImageWorker) container(ctx context.Context) (nginxcontainer.Container, nginxcontainer.Binding, error) {
	p := w.r.NginxImage
	i := p.Intent
	var last error
	for _, b := range []nginxcontainer.Binding{i.Before, i.Target} {
		c, err := nginxcontainer.ReadContainer(ctx, b)
		if os.IsNotExist(err) {
			return c, b, err
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
			if b.ImageID != i.Before.ImageID || !reflect.DeepEqual(c.Labels, i.Container.Labels) || c.Instance.StartedAt != expected.StartedAt || c.Instance.RestartCount != expected.RestartCount {
				return c, b, errors.New("原 Nginx 容器发生外部重建或重启")
			}
			return c, b, nil
		}
		direction, known, submitted, start, generation := "forward", p.TargetContainerID, p.TargetCreateSubmitted, p.TargetStartSubmitted, p.TargetGeneration
		if b.ImageID == i.Before.ImageID {
			direction, known, submitted, start, generation = "rollback", p.RollbackContainerID, p.RollbackCreateSubmitted, p.RollbackStartSubmitted, p.RollbackGeneration
		}
		if !submitted || known != "" && known != c.Instance.ID || !reflect.DeepEqual(c.Labels, w.labels(b, direction)) || c.Instance.RestartCount != 0 {
			return c, b, errors.New("Nginx 容器不属于原镜像替换意图")
		}
		if generation != nil && (c.Instance.StartedAt != generation.StartedAt || c.Instance.RestartCount != generation.RestartCount) {
			return c, b, errors.New("替换后的 Nginx 容器发生外部重启")
		}
		changed := false
		if known == "" {
			if direction == "rollback" {
				p.RollbackContainerID = c.Instance.ID
			} else {
				p.TargetContainerID = c.Instance.ID
			}
			changed = true
		}
		if c.State == "running" {
			if !start {
				return c, b, errors.New("Nginx 容器运行但没有原启动意图")
			}
			if generation == nil {
				instance := c.Instance
				if direction == "rollback" {
					p.RollbackGeneration = &instance
				} else {
					p.TargetGeneration = &instance
				}
				changed = true
			}
		}
		if changed {
			if err = w.save(); err != nil {
				return c, b, err
			}
		}
		return c, b, nil
	}
	return nginxcontainer.Container{}, nginxcontainer.Binding{}, last
}
func (w *nginxImageWorker) agent(ctx context.Context, start bool) error {
	i := w.r.NginxImage.Intent
	if err := w.guard(ctx); err != nil {
		return err
	}
	actual, err := agentUpgradeObserve(ctx, i.Before.DataDir, w.r.OperationID, i.Agent)
	if err != nil {
		return err
	}
	state, action := "stopped", "stop"
	if start {
		state, action = "running", "start"
	}
	if actual.State == state {
		return nil
	}
	_, requestErr := installationSystemctl(ctx, action, "nginxpanel-agent.service")
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		actual, err = agentUpgradeObserve(wait, i.Before.DataDir, w.r.OperationID, i.Agent)
		if err == nil && actual.State == state {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.Join(requestErr, err, wait.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func (w *nginxImageWorker) stop(ctx context.Context, c nginxcontainer.Container, b nginxcontainer.Binding) error {
	if c.State != "running" {
		return nil
	}
	requestErr := nginxcontainer.ContainerAction(ctx, b, c.Instance.ID, "stop")
	wait, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	for {
		current, actual, err := w.container(wait)
		if err != nil {
			return errors.Join(requestErr, err)
		}
		if actual.ImageID != b.ImageID || current.Instance.ID != c.Instance.ID {
			return errors.New("停止期间 Nginx 容器发生替换")
		}
		if current.State != "running" {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.Join(requestErr, wait.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func (w *nginxImageWorker) selection(b nginxcontainer.Binding, compose []byte) error {
	actual, err := nginxcontainer.Read(b.DataDir)
	if err != nil {
		return err
	}
	raw, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, b) || !bytes.Equal(raw, compose) {
		return errors.New("Nginx 绑定与 Compose 尚未完成同向切换")
	}
	return nil
}
func (w *nginxImageWorker) create(ctx context.Context, b nginxcontainer.Binding, prefix string) error {
	p := w.r.NginxImage
	submitted, known := p.TargetCreateSubmitted, p.TargetContainerID
	direction := "forward"
	if p.Rollback {
		direction, submitted, known = "rollback", p.RollbackCreateSubmitted, p.RollbackContainerID
	}
	c, actual, err := w.container(ctx)
	if os.IsNotExist(err) {
		if submitted || known != "" {
			return errors.New("Nginx 创建回执或已登记实例丢失，禁止重复创建")
		}
		if p.Rollback {
			p.RollbackCreateSubmitted = true
		} else {
			p.TargetCreateSubmitted = true
		}
		if err = w.stage(prefix + "creating"); err != nil {
			return err
		}
		id, createErr := nginxcontainer.CreateContainer(ctx, b, w.labels(b, direction))
		if id != "" {
			if p.Rollback {
				p.RollbackContainerID = id
			} else {
				p.TargetContainerID = id
			}
			if err = w.save(); err != nil {
				return errors.Join(createErr, err)
			}
		}
		c, actual, err = w.container(ctx)
		if err != nil {
			return errors.Join(createErr, err)
		}
		if createErr != nil {
			return createErr
		}
	}
	if err != nil {
		return err
	}
	if actual.ImageID != b.ImageID || c.State != "created" || !reflect.DeepEqual(c.Labels, w.labels(b, direction)) {
		return errors.New("Nginx 新实例未按原方向完成创建")
	}
	return nil
}
func (w *nginxImageWorker) start(ctx context.Context, b nginxcontainer.Binding, prefix string) error {
	p := w.r.NginxImage
	c, actual, err := w.container(ctx)
	if err != nil {
		return err
	}
	if actual.ImageID != b.ImageID {
		return errors.New("Nginx 启动镜像与原方向不符")
	}
	if c.State == "running" {
		return nil
	}
	submitted := p.TargetStartSubmitted
	if p.Rollback {
		submitted = p.RollbackStartSubmitted
	}
	if submitted || c.State != "created" {
		return errors.New("原 Nginx 启动未确认或已经退出，禁止重复启动")
	}
	if p.Rollback {
		p.RollbackStartSubmitted = true
	} else {
		p.TargetStartSubmitted = true
	}
	if err = w.stage(prefix + "starting"); err != nil {
		return err
	}
	requestErr := nginxcontainer.ContainerAction(ctx, b, c.Instance.ID, "start")
	after, selected, err := w.container(ctx)
	if err != nil {
		return errors.Join(requestErr, err)
	}
	if selected.ImageID != b.ImageID || after.Instance.ID != c.Instance.ID || after.State != "running" {
		return errors.Join(requestErr, errors.New("Nginx 新实例尚未运行"))
	}
	return nil
}

// The independent executor owns the Nginx lock only while the Agent is stopped.
// It releases it before starting the Agent, which must reopen the selected
// binding and independently confirm its actual runtime through IPC.
func (w *nginxImageWorker) runtime(ctx context.Context) error {
	p := w.r.NginxImage
	i := p.Intent
	b, other, compose, otherCompose, prefix := i.Target, i.Before, i.TargetCompose, i.BeforeCompose, ""
	if p.Rollback {
		b, other, compose, otherCompose, prefix = i.Before, i.Target, i.BeforeCompose, i.TargetCompose, "rollback_"
	}
	if err := w.guard(ctx); err != nil {
		return err
	}
	if err := nginxcontainer.VerifyRetainedImage(ctx, b); err != nil {
		return err
	}
	if err := w.stage(prefix + "stopping_agent"); err != nil {
		return err
	}
	if err := w.agent(ctx, false); err != nil {
		return err
	}
	// Opening with the current binding is necessary even after a half-published
	// selection. The publication itself must match the frozen revision throughout.
	current, err := nginxcontainer.Read(b.DataDir)
	if err != nil {
		return err
	}
	n := w.nginx(current)
	if err = n.Open(); err != nil {
		return err
	}
	err = func() error {
		defer n.Close()
		if _, err := w.publication(n); err != nil {
			return err
		}
		c, actual, inspectErr := w.container(ctx)
		if inspectErr != nil && !os.IsNotExist(inspectErr) {
			return inspectErr
		}
		keep := inspectErr == nil && actual.ImageID == b.ImageID && c.State == "running"
		if inspectErr == nil && !keep && (actual.ImageID != b.ImageID || c.State != "created" || c.Instance.ID == i.Container.Instance.ID) {
			if err := w.stage(prefix + "stopping"); err != nil {
				return err
			}
			if err := w.stop(ctx, c, actual); err != nil {
				return err
			}
			c, actual, err = w.container(ctx)
			if err != nil {
				return err
			}
			if err = nginxcontainer.ContainerAction(ctx, actual, c.Instance.ID, "remove"); err != nil {
				if _, _, readErr := w.container(ctx); !os.IsNotExist(readErr) {
					return errors.Join(err, readErr)
				}
			}
			if _, _, readErr := w.container(ctx); !os.IsNotExist(readErr) {
				if readErr == nil {
					readErr = errors.New("原 Nginx 容器删除尚未确认")
				}
				return readErr
			}
		}
		if err := w.stage(prefix + "selecting"); err != nil {
			return err
		}
		if err := w.guard(ctx); err != nil {
			return err
		}
		if err := panelruntime.SelectNginxImage(other, b, otherCompose, compose); err != nil {
			return err
		}
		if err := w.selection(b, compose); err != nil {
			return err
		}
		n.Container = &nginxcontainer.Runtime{Binding: b}
		if !keep {
			if err := w.create(ctx, b, prefix); err != nil {
				return err
			}
			if err := w.start(ctx, b, prefix); err != nil {
				return err
			}
		}
		if err := w.stage(prefix + "confirming_nginx"); err != nil {
			return err
		}
		m, err := w.publication(n)
		if err != nil {
			return err
		}
		wait, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		return n.waitObserved(wait, m)
	}()
	if err != nil {
		return err
	}
	if err = w.stage(prefix + "starting_agent"); err != nil {
		return err
	}
	if err = w.agent(ctx, true); err != nil {
		return err
	}
	if err = w.stage(prefix + "confirming_agent"); err != nil {
		return err
	}
	return w.confirm(ctx, b, compose)
}
func (w *nginxImageWorker) confirm(ctx context.Context, b nginxcontainer.Binding, compose []byte) error {
	i := w.r.NginxImage.Intent
	if err := w.guard(ctx); err != nil {
		return err
	}
	if err := w.selection(b, compose); err != nil {
		return err
	}
	c, actual, err := w.container(ctx)
	if err != nil {
		return err
	}
	if actual.ImageID != b.ImageID || c.State != "running" {
		return errors.New("Nginx 实际容器尚未按原方向运行")
	}
	n := w.nginx(b)
	m, err := w.publication(n)
	if err != nil {
		return err
	}
	if err = n.observe(ctx, m); err != nil {
		return err
	}
	process, err := agentUpgradeObserve(ctx, b.DataDir, w.r.OperationID, i.Agent)
	if err != nil {
		return err
	}
	if process.State != "running" {
		return errors.New("Agent 尚未恢复运行")
	}
	probe, err := waitNginxInstallationProbe(ctx, b.DataDir, true, i.RevisionID, i.DeploymentID, func(info *nginxruntime.Installation) bool {
		return info != nil && info.Owner == "docker" && info.SHA256 == b.BinarySHA256 && info.Version == b.Capabilities.Version && info.SourceURL == b.Image
	})
	if err != nil {
		return err
	}
	lease, err := probeAgentUpgrade(ctx, b.DataDir, i.Input.MaintenanceID, i.Agent)
	if err != nil {
		return err
	}
	after, _, err := w.container(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(after, c) {
		return errors.New("联合确认期间 Nginx 容器代次变化")
	}
	agent, err := agentUpgradeObserve(ctx, b.DataDir, w.r.OperationID, i.Agent)
	if err != nil {
		return err
	}
	if agent != process {
		return errors.New("联合确认期间 Agent 代次变化")
	}
	if err = w.guard(ctx); err != nil {
		return err
	}
	if err = w.selection(b, compose); err != nil {
		return err
	}
	p := w.r.NginxImage
	p.Confirmation = &NginxImageConfirmation{ConfirmedAt: time.Now().Unix(), ContainerID: c.Instance.ID, ImageID: c.Instance.ImageID, NginxPID: c.Instance.PID, Agent: process, ReadyEpoch: lease.Epoch, Runtime: probe.Runtime}
	return w.save()
}
