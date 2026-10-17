package firewall

import (
	"slices"
	"strconv"
)

func inspectFirewalldPreview(out *Preview, observed Observation) {
	errors, warnings := FirewalldEnvironment(observed)
	out.Errors = append(out.Errors, errors...)
	out.Warnings = append(out.Warnings, warnings...)
}

// Shared by the logical preview and the root protection plan; callers still
// need fresh ownership/configuration proof before using a plan for any write.
func FirewalldEnvironment(observed Observation) (errors, warnings []string) {
	out := Preview{Errors: []string{}, Warnings: []string{}}
	if observed.Manager != "firewalld" || observed.Firewalld.Running == nil || !*observed.Firewalld.Running {
		out.Errors = append(out.Errors, "目标未确认由单一 firewalld 管理，不能切换或接管管理器")
	}
	if observed.Firewalld.Panic == nil || *observed.Firewalld.Panic {
		out.Errors = append(out.Errors, "firewalld panic 状态未排除，不能确认入站策略环境")
	}
	if observed.Backend == "mixed" {
		out.Errors = append(out.Errors, "观察到混合内核后端，须先核对规则所有权")
	}
	complete := len(observed.Rulesets) == 5
	for _, set := range observed.Rulesets {
		complete = complete && set.Available
	}
	if !complete {
		out.Errors = append(out.Errors, "部分内核后端视图不完整，不能排除其他规则体系")
	}
	inventory := observed.Firewalld.PolicyInventory
	if !inventory.Available {
		out.Errors = append(out.Errors, "firewalld runtime/permanent policy 清单无法完整核对")
		return out.Errors, out.Warnings
	}
	registration := observed.Firewalld.Registration
	if registration.State == "recovery_required" || registration.State == "missing" || registration.State == "drifted" {
		out.Errors = append(out.Errors, "firewalld root 登记尚未核对完成："+registration.Reason)
	}
	for _, policy := range inventory.Policies {
		if policy.Name == FirewalldHostPolicy {
			if !registration.Verified || registration.State != "registered" {
				out.Errors = append(out.Errors, "固定目标 policy 已存在；独立登记未核对通过，禁止接管")
			}
			continue
		}
		// ANY excludes HOST. Forwarding/output policies cannot contend with
		// this ANY -> HOST policy merely by sharing a numeric priority.
		if !policy.Active || policy.Runtime == nil || !slices.Contains(policy.ActiveEgressZones, "HOST") {
			continue
		}
		if policy.Runtime.Priority == nil {
			out.Errors = append(out.Errors, "活动 policy "+policy.Name+" 的优先级未知，不能确定策略关系")
		} else if *policy.Runtime.Priority == FirewalldHostPriority {
			out.Errors = append(out.Errors, "活动 policy "+policy.Name+" 与目标优先级同为 "+strconv.Itoa(FirewalldHostPriority)+"，顺序不确定")
		} else if *policy.Runtime.Priority < FirewalldHostPriority {
			out.Warnings = append(out.Warnings, "活动 policy "+policy.Name+" 的优先级早于目标，可能先行结束匹配；需核对其流量范围")
		}
	}
	return out.Errors, out.Warnings
}
