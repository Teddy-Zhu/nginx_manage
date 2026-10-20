package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
)

func (w *nginxImageWorker) labels(b nginxcontainer.Binding, direction string) map[string]string {
	i := w.r.NginxImage.Intent
	out := map[string]string{}
	if direction != "rollback" {
		for k, v := range i.TargetLabels {
			out[k] = v
		}
	}
	if direction != "check" {
		for k, v := range i.Container.Labels {
			out[k] = v
		}
	}
	out[panelruntime.DockerOperationLabel] = w.r.OperationID
	out[panelruntime.DockerDirectionLabel] = direction
	out[panelruntime.DockerBindingLabel] = selectionValueHash(b)
	return out
}
func (w *nginxImageWorker) checkContainer(ctx context.Context) (nginxcontainer.CandidateCheck, error) {
	p := w.r.NginxImage
	i := p.Intent
	c, err := nginxcontainer.ReadCandidateCheck(ctx, i.Target, i.Directory, w.r.OperationID)
	if err != nil {
		return c, err
	}
	if !p.CheckCreateSubmitted || !reflect.DeepEqual(c.Container.Labels, w.labels(i.Target, "check")) || p.CheckContainerID != "" && c.Container.Instance.ID != p.CheckContainerID {
		return c, errors.New("候选校验容器不属于原持久意图")
	}
	if p.CheckContainerID == "" {
		p.CheckContainerID = c.Container.Instance.ID
		if err = w.save(); err != nil {
			return c, err
		}
	}
	return c, nil
}
func (w *nginxImageWorker) removeCheck(ctx context.Context) error {
	p := w.r.NginxImage
	i := p.Intent
	c, err := w.checkContainer(ctx)
	if os.IsNotExist(err) {
		return nginxcontainer.RemoveCandidateCheckBinding(ctx, i.Target, i.Directory, w.r.OperationID)
	}
	if err != nil {
		return err
	}
	if c.Container.State == "running" {
		requestErr := nginxcontainer.CandidateCheckAction(ctx, i.Target, i.Directory, w.r.OperationID, c.Container.Instance.ID, "stop")
		wait, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		for {
			c, err = w.checkContainer(wait)
			if err != nil {
				return errors.Join(requestErr, err)
			}
			if c.Container.State != "running" {
				break
			}
			select {
			case <-wait.Done():
				return errors.Join(requestErr, wait.Err())
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	requestErr := nginxcontainer.CandidateCheckAction(ctx, i.Target, i.Directory, w.r.OperationID, c.Container.Instance.ID, "remove")
	_, err = w.checkContainer(ctx)
	if !os.IsNotExist(err) {
		if err == nil {
			err = errors.New("候选校验容器移除未确认")
		}
		return errors.Join(requestErr, err)
	}
	return nginxcontainer.RemoveCandidateCheckBinding(ctx, i.Target, i.Directory, w.r.OperationID)
}
func (w *nginxImageWorker) candidate(ctx context.Context) error {
	p := w.r.NginxImage
	i := p.Intent
	if p.CheckPassed {
		return w.removeCheck(ctx)
	}
	if err := w.guard(ctx); err != nil {
		return err
	}
	c, err := w.checkContainer(ctx)
	if os.IsNotExist(err) {
		if p.CheckCreateSubmitted {
			return errors.New("候选校验创建回执不明，禁止重复派发")
		}
		p.CheckCreateSubmitted = true
		if err = w.stage("check_creating"); err != nil {
			return err
		}
		id, createErr := nginxcontainer.CreateCandidateCheck(ctx, i.Target, i.Directory, w.r.OperationID, w.labels(i.Target, "check"))
		if id != "" {
			p.CheckContainerID = id
			if err = w.save(); err != nil {
				return errors.Join(createErr, err)
			}
		}
		c, err = w.checkContainer(ctx)
		if err != nil {
			return errors.Join(createErr, err)
		}
		if createErr != nil {
			return createErr
		}
	} else if err != nil {
		return err
	}
	if c.Container.State == "created" {
		if p.CheckSubmitted {
			return errors.New("原候选校验启动回执不明，禁止重复运行")
		}
		p.CheckSubmitted = true
		if err = w.stage("checking"); err != nil {
			return err
		}
		requestErr := nginxcontainer.CandidateCheckAction(ctx, i.Target, i.Directory, w.r.OperationID, c.Container.Instance.ID, "start")
		c, err = w.checkContainer(ctx)
		if err != nil {
			return errors.Join(requestErr, err)
		}
		if c.Container.State == "created" {
			return errors.Join(requestErr, errors.New("候选校验启动未确认"))
		}
	}
	if !p.CheckSubmitted {
		return errors.New("候选校验进程没有原启动意图")
	}
	wait, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for c.Container.State == "running" {
		select {
		case <-wait.Done():
			return wait.Err()
		case <-time.After(250 * time.Millisecond):
		}
		c, err = w.checkContainer(wait)
		if err != nil {
			return err
		}
	}
	if c.Container.State != "exited" || c.FinishedAt == "" {
		return errors.New("候选配置校验未确认退出")
	}
	exit := c.ExitCode
	p.CheckExitCode = &exit
	p.CheckFinishedAt = c.FinishedAt
	if err = w.save(); err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("候选镜像未通过当前完整 Nginx 配置校验（退出码 %d）", exit)
	}
	if err := w.guard(ctx); err != nil {
		return err
	}
	p.CheckPassed = true
	if err = w.stage("check_removing"); err != nil {
		return err
	}
	return w.removeCheck(ctx)
}
