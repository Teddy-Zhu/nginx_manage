package components

import (
	"context"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/software"
)

func (m *Manager) Control(ctx context.Context, in software.Request) (software.Result, error) {
	if err := in.Validate(); err != nil {
		return software.Result{}, fault.Invalid(err.Error())
	}
	if !in.Immediate() {
		return software.Result{}, fault.Invalid("此操作需要通过软件任务执行")
	}
	if m.Dev || m.Scope != "host" {
		return software.Result{}, fault.Unavailable("当前环境不允许修改宿主机软件")
	}
	m.mu.Lock()
	if m.closed || m.poisoned || m.ctx == nil || m.ctx.Err() != nil {
		m.mu.Unlock()
		return software.Result{}, fault.Unavailable("组件执行器暂不可用")
	}
	if m.active {
		m.mu.Unlock()
		return software.Result{}, fault.Conflict("已有软件操作正在执行")
	}
	m.active = true
	m.workers.Add(1)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.active = false
		m.mu.Unlock()
		m.workers.Done()
	}()

	ctx, cancel := context.WithTimeout(ctx, software.ControlTimeout)
	stop := context.AfterFunc(m.ctx, cancel)
	defer cancel()
	defer stop()

	run := m.BuiltinAction
	switch in.Action {
	case "container":
		run = m.ContainerAction
	case "fail2ban":
		run = m.Fail2banAction
	}
	if run == nil {
		return software.Result{}, fault.Unavailable("当前软件操作不可用")
	}
	return run(ctx, in, func(string) {})
}
