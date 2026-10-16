package firewall

import (
	"context"
	"errors"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/modules"
)

type Executor interface {
	PlanFirewall(context.Context, RuntimeInput, string) (Plan, error)
	ApplyFirewall(context.Context, string, ApplyInput, string, string) (Operation, error)
	FirewallOperation(context.Context, string) (Operation, error)
	FirewallRuntime(context.Context) (RuntimeView, error)
}

func (s *Service) executor(ctx context.Context, requireEnabled bool) (Executor, error) {
	if err := s.migrationIdle(ctx, s.DB); err != nil {
		return nil, err
	}
	if requireEnabled {
		var enabled bool
		if err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='firewall'").Scan(&enabled); err != nil {
			return nil, err
		}
		if !enabled {
			return nil, fault.Conflict("请先启用防火墙模块")
		}
	}
	executor, ok := s.Agent.(Executor)
	if !ok {
		return nil, fault.Unavailable("未连接宿主机防火墙执行器")
	}
	return executor, nil
}
func (s *Service) Plan(ctx context.Context, in PlanInput, connection string) (Plan, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out Plan
	if in.Version < 1 || in.Action != "apply" && in.Action != "remove" {
		return out, fault.Invalid("防火墙计划动作或版本无效")
	}
	executor, err := s.executor(ctx, in.Action == "apply")
	if err != nil {
		return out, err
	}
	input := RuntimeInput{Action: in.Action, Version: in.Version, Policy: DefaultPolicy()}
	if in.Action == "apply" {
		view, err := s.Policy(ctx)
		if err != nil {
			return out, err
		}
		if view.Version != in.Version {
			return out, fault.Conflict("期望策略版本变化，请重新读取并生成计划")
		}
		input.Policy = view.Policy
	} else {
		view, err := executor.FirewallRuntime(ctx)
		if err != nil {
			return out, err
		}
		if view.ConfirmedAction != "apply" || view.ConfirmedVersion != in.Version {
			return out, fault.Conflict("待移除的已确认策略已变化或不存在")
		}
	}
	return executor.PlanFirewall(ctx, input, connection)
}
func (s *Service) Apply(ctx context.Context, id string, in ApplyInput, connection string) (Operation, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out Operation
	if in.Version < 1 || in.Action != "apply" && in.Action != "remove" {
		return out, fault.Invalid("防火墙执行动作或版本无效")
	}
	// An admitted operation remains queryable/repeatable after module changes.
	executor, ok := s.Agent.(Executor)
	if !ok {
		return out, fault.Unavailable("未连接宿主机防火墙执行器")
	}
	old, err := executor.FirewallOperation(ctx, id)
	if err == nil {
		if old.PlanID != in.PlanID || old.Version != in.Version || old.Action != in.Action {
			return out, fault.Conflict("幂等键已用于其他请求")
		}
		return old, nil
	}
	var known *fault.Error
	if !errors.As(err, &known) || known.Status != 404 {
		return out, err
	}
	if _, err = s.executor(ctx, in.Action == "apply"); err != nil {
		return out, err
	}
	var hash string
	if in.Action == "apply" {
		view, err := s.Policy(ctx)
		if err != nil {
			return out, err
		}
		if view.Version != in.Version {
			return out, fault.Conflict("期望策略版本变化，请重新生成计划")
		}
		hash, err = PolicyDigest(view.Policy)
		if err != nil {
			return out, err
		}
	} else {
		view, err := executor.FirewallRuntime(ctx)
		if err != nil {
			return out, err
		}
		if view.ConfirmedAction != "apply" || view.ConfirmedVersion != in.Version {
			return out, fault.Conflict("待移除的已确认策略已变化，请重新生成计划")
		}
		hash = view.ConfirmedPolicyHash
	}
	return executor.ApplyFirewall(ctx, id, in, hash, connection)
}

// Serializing module admission with Apply prevents a new application from
// racing the final disable after the referenced removal was confirmed.
func (s *Service) SetManagement(ctx context.Context, p auth.Principal, enabled bool, rules, operationID string) error {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if err := p.Require("system.write"); err != nil {
		return err
	}
	if enabled {
		if rules != "" || operationID != "" {
			return fault.Invalid("启用防火墙模块时不接受停用规则选项")
		}
	} else {
		switch rules {
		case "keep":
			if operationID != "" {
				return fault.Invalid("保留规则时不接受移除操作 ID")
			}
		case "remove":
			if err := p.Require("security.write", "read"); err != nil {
				return err
			}
			executor, err := s.executor(ctx, false)
			if err != nil {
				return err
			}
			view, err := executor.FirewallRuntime(ctx)
			if err != nil {
				return err
			}
			if !view.Available {
				return fault.Conflict("防火墙运行状态不可核对，不能按移除方式停用")
			}
			empty := view.ConfirmedAction == "none" && view.Kernel.Available && view.Kernel.TableExists && view.Kernel.Chains == 0 && view.Kernel.Rules == 0
			if empty {
				if operationID != "" {
					return fault.Invalid("尚无已确认规则时不接受移除操作 ID")
				}
			} else {
				if view.ConfirmedAction != "remove" || operationID == "" || operationID != view.ConfirmedOperationID {
					return fault.Conflict("须先独立移除并通过新连接确认，再引用原操作停用模块")
				}
				op, err := executor.FirewallOperation(ctx, operationID)
				if err != nil {
					return err
				}
				if op.ID != operationID || op.Action != "remove" || op.State != "succeeded" || view.ConfirmedPlanID != op.PlanID || view.ConfirmedVersion != op.Version || view.ConfirmedPolicyHash != op.PolicyHash {
					return fault.Conflict("移除回执不再是当前确认状态，禁止按旧操作停用")
				}
			}
		default:
			return fault.Invalid("停用防火墙模块须明确选择保留或移除本应用规则")
		}
	}
	return modules.Set(ctx, s.DB, p, "firewall", enabled)
}
