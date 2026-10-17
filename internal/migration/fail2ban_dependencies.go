package migration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
)

// Jail restoration saves desired configuration only. Its target prerequisites
// are reported separately so an offline engine cannot block Nginx restoration
// or be mistaken for installed, running protection.
func (s *Service) inspectFail2banDependencies(ctx context.Context, policy fail2ban.Policy, add func(string, string, string, string)) error {
	if len(policy.Jails) == 0 {
		return nil
	}
	step := func(resource, state, message string) {
		add("fail2ban-dependency", "fail2ban:"+resource, state, message)
	}
	var enabled bool
	if err := s.DB.QueryRowContext(ctx, "SELECT enabled FROM module_settings WHERE id='fail2ban'").Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		step("module", "ready", "目标 Fail2ban 管理模块已启用；迁入后须单独预览并应用 jail")
	} else {
		step("module", "review", "目标 Fail2ban 管理模块停用；须在目标启用后单独应用 jail")
	}
	if s.Agent == nil {
		step("observation", "review", "目标宿主机 Agent 未连接，尚不能确认引擎、Python 和实例接入；请在目标 Fail2ban 页面核对")
		return nil
	}
	needsHost, needsNginx := false, false
	for _, jail := range policy.Jails {
		if !jail.Enabled {
			continue
		}
		if jail.Template == fail2ban.PanelLoginTemplate {
			needsHost = true
		} else if jail.Action == "nginx-client" {
			needsNginx = true
		} else {
			step(jail.ID, "review", "该站点 jail 的动作尚无可用执行适配；须在目标选择适用的动作并重新预览")
		}
	}
	call, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var inventory fail2ban.Observation
	var instance fail2ban.Instance
	var runtime fail2ban.JailsRuntime
	var inventoryErr, instanceErr, runtimeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); inventory, inventoryErr = s.Agent.ReadFail2ban(call) }()
	go func() { defer wg.Done(); instance, instanceErr = s.Agent.ReadFail2banInstance(call) }()
	if needsHost || needsNginx {
		wg.Add(1)
		go func() { defer wg.Done(); runtime, runtimeErr = s.Agent.ReadFail2banJailsRuntime(call) }()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	instanceKnown := instanceErr == nil && instance.Source == "host-agent" && instance.Scope == "host"
	instanceReady := instanceKnown && instance.Available && instance.Binding.State == "bound"
	inventoryKnown := inventoryErr == nil && inventory.Available && inventory.Source == "host-agent" && inventory.Scope == "host"
	bound := instanceKnown && instance.Binding.State == "bound" || !instanceKnown && inventoryKnown && inventory.Binding.State == "bound"
	if instanceReady {
		if instance.ServerVersion == fail2ban.RegexVersion {
			step("engine", "ready", "目标已接入的 Fail2ban 实例版本与受管模板匹配；迁入 jail 尚未应用")
		} else {
			step("engine", "review", "目标实例版本与受管模板不匹配；须在目标准备匹配版本并核对实例接入")
		}
		step("python", "ready", "已确认目标现有实例运行；保留该实例的运行环境")
	} else if bound {
		step("engine", "review", "目标已登记 Fail2ban 实例；须先恢复原实例并核对版本及组件状态")
		step("python", "review", "目标实例已固定运行环境；须通过原实例恢复核对 Python 及其运行依赖")
	} else if inventoryKnown {
		inspectFail2banEngine(inventory, step)
		if inventory.Managed.Available && inventory.Managed.State != "absent" && inventory.Managed.State != "rolled-back" {
			step("python", "review", "原受管引擎操作已固定 Python；须通过原实例的状态和恢复流程核对其可用性")
		} else {
			python := inventory.Python
			switch {
			case python.Executable.Trusted && python.StandardLibrary != nil && *python.StandardLibrary:
				step("python", "ready", "目标系统 Python 版本和标准库满足基础要求；安装时仍须核对所选签名组件的运行要求")
			case python.Executable.Present != nil && !*python.Executable.Present:
				step("python", "review", "目标缺少默认系统 Python；可在目标 Fail2ban 页面生成并明确授权系统依赖安装计划")
			default:
				step("python", "review", "目标系统 Python 的版本、标准库或可信来源未确认；须在目标 Fail2ban 页面核对依赖计划")
			}
		}
	} else {
		step("engine", "review", "目标引擎和 Python 诊断暂不可读取，尚不能确认是否需要安装；请在目标 Fail2ban 页面重新读取")
	}
	switch {
	case !instanceKnown:
		step("instance", "review", "目标 Fail2ban 实例状态暂不可读取，须重新核对实例接入和服务状态")
	case instanceReady:
		step("instance", "ready", "目标已接入实例可读取；日志来源、动作授权及迁入 jail 的应用结果须独立核对")
	case instance.Binding.State == "unbound":
		step("instance", "review", "目标尚未接入 Fail2ban 实例；须明确接入已有实例，或安装并接入受管引擎")
	case instance.Binding.State == "bound":
		step("instance", "review", "目标已接入实例尚未确认运行；须在目标核对服务状态并恢复原实例。"+instance.Reason)
	default:
		step("instance", "review", "目标 Fail2ban 实例接入授权不可确认；须在目标核对原接入记录")
	}
	if !needsHost && !needsNginx {
		return nil
	}
	if runtimeErr != nil {
		step("actions", "review", "目标 jail 执行基准暂不可读取，须重新核对日志入口、动作接入和未完成任务")
		return nil
	}
	if len(runtime.Pending) != 0 {
		step("actions", "review", "目标仍有未结束的 jail 操作；须先在目标核对并恢复原操作")
	}
	if needsHost {
		if runtime.Available && runtime.HostReady && len(runtime.Pending) == 0 {
			step("host-input", "ready", "目标宿主机动作接入就绪；须重新核对本机保护来源、登录日志及迁入 jail")
		} else {
			step("host-input", "review", "须在目标完成宿主机动作接入和本机保护授权，并核对面板登录日志。"+runtime.HostReason)
		}
	}
	if needsNginx {
		if !runtime.Available || !runtime.NginxReady || len(runtime.Pending) != 0 {
			step("nginx-client", "review", "须在目标恢复 Nginx 客户端动作接入，并发布站点日志、客户端拒绝入口和可信代理配置。"+runtime.NginxReason)
		} else {
			boundResources := map[string]bool{}
			for _, id := range runtime.Resources {
				boundResources[id] = true
			}
			missing := map[string]bool{}
			for _, jail := range policy.Jails {
				if jail.Enabled && jail.Action == "nginx-client" && !boundResources[jail.ResourceID] {
					missing[jail.ResourceID] = true
				}
			}
			if len(missing) > 0 {
				step("nginx-client", "review", fmt.Sprintf("%d 个目标站点尚无已发布的客户端拒绝入口；须发布迁入配置并核对站点结构化日志和可信代理", len(missing)))
			} else {
				step("nginx-client", "ready", "目标站点已接入客户端拒绝入口；发布迁入配置后仍须重新检查结构化日志、可信代理和 jail")
			}
		}
	}
	return nil
}

func inspectFail2banEngine(in fail2ban.Observation, step func(string, string, string)) {
	if !in.Managed.Available {
		step("engine", "review", "目标受管引擎安装登记无法读取；须先核对原记录，再决定安装或恢复")
		return
	}
	switch in.Managed.State {
	case "installed":
		step("engine", "ready", "目标已有受管引擎安装记录；原实例运行状态仍须核对")
		return
	case "absent", "rolled-back":
	default:
		step("engine", "review", "目标受管引擎安装尚未结束或需要恢复；须在目标核对原操作")
		return
	}
	trusted, missing := 0, false
	for _, tool := range in.Tools {
		if tool.Trusted {
			trusted++
		}
		missing = missing || tool.Present != nil && !*tool.Present
	}
	if trusted == 3 && in.ClientVersion == fail2ban.RegexVersion {
		step("engine", "ready", "目标已有匹配版本的系统引擎工具；须明确核对实例接入和受管模板")
	} else if missing {
		step("engine", "review", "目标未登记受管引擎且缺少完整系统引擎工具；须核对已有实例，需新建时准备可信组件并明确授权首次安装，Docker 部署也使用宿主机引擎")
	} else {
		step("engine", "review", "目标系统引擎工具的版本或可信来源未确认；须先核对已有实例，或准备匹配的受管组件")
	}
}
