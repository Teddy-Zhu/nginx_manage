package firewall

import (
	"context"
	"errors"

	"nginxpanel/internal/fault"
)

type Executor interface {
	PlanFirewall(context.Context, RuntimeInput, string) (Plan, error)
	ApplyFirewall(context.Context, string, ApplyInput, string, string) (Operation, error)
	FirewallOperation(context.Context, string) (Operation, error)
}

func (s *Service) executor(ctx context.Context) (Executor, error) {
	var enabled bool
	if err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='firewall'").Scan(&enabled); err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fault.Conflict("请先启用防火墙模块")
	}
	executor, ok := s.Agent.(Executor)
	if !ok {
		return nil, fault.Unavailable("未连接宿主机防火墙执行器")
	}
	return executor, nil
}
func (s *Service) Plan(ctx context.Context, version int64, connection string) (Plan, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out Plan
	executor, err := s.executor(ctx)
	if err != nil {
		return out, err
	}
	view, err := s.Policy(ctx)
	if err != nil {
		return out, err
	}
	if version < 1 || view.Version != version {
		return out, fault.Conflict("期望策略版本变化，请重新读取并生成计划")
	}
	return executor.PlanFirewall(ctx, RuntimeInput{Version: version, Policy: view.Policy}, connection)
}
func (s *Service) Apply(ctx context.Context, id string, in ApplyInput, connection string) (Operation, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out Operation
	// An admitted operation remains queryable/repeatable after the module is
	// disabled or its next desired policy is edited; neither revokes recovery.
	executor, ok := s.Agent.(Executor)
	if !ok {
		return out, fault.Unavailable("未连接宿主机防火墙执行器")
	}
	old, err := executor.FirewallOperation(ctx, id)
	if err == nil {
		if old.PlanID != in.PlanID || old.Version != in.Version {
			return out, fault.Conflict("幂等键已用于其他请求")
		}
		return old, nil
	}
	var known *fault.Error
	if !errors.As(err, &known) || known.Status != 404 {
		return out, err
	}
	if _, err = s.executor(ctx); err != nil {
		return out, err
	}
	view, err := s.Policy(ctx)
	if err != nil {
		return out, err
	}
	if in.Version < 1 || view.Version != in.Version {
		return out, fault.Conflict("期望策略版本变化，请重新生成计划")
	}
	hash, err := PolicyDigest(view.Policy)
	if err != nil {
		return out, err
	}
	return executor.ApplyFirewall(ctx, id, in, hash, connection)
}
