package agent

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

func (f *hostFirewall) ufwViewLocked() firewall.RuntimeView {
	registered, registrationErr := ufwRegistrationAuthority(f.dataDir)
	pending := ufwRestorePending(f.dataDir)
	out := firewall.RuntimeView{Backend: "ufw", CanPlan: f.ufwPlanning && f.problem == "" && registrationErr == nil && !pending, Reason: f.problem, Protections: []firewall.Protection{}, ConfirmedAction: "none", ProtectionObservation: f.protectionObservationLocked(), Kernel: firewall.KernelView{Reason: "UFW 计划不提供直接 nftables 事务证明"}}
	if out.Reason == "" {
		out.Reason = "UFW 本机授权已核对，可准备保护计划；正常应用、确认及持久化尚未开放"
		if !f.ufwPlanning {
			out.Reason = "须由本机 root 确认 UFW、宿主机范围及 SSH 保护配置后准备计划"
		} else if registrationErr != nil {
			out.Reason = "UFW 本机授权登记尚未完成或无法核对，请本机检查 ufw-registration 并恢复原操作"
		} else if pending {
			out.Reason = "UFW 原重载进程或业务操作尚未完成，保持只读"
		}
	}
	if registrationErr != nil {
		return out
	}
	v, err := loadUFWChange(f.dataDir)
	if err == nil && v != nil {
		var receipt Record
		receipt, err = loadUFWReceipt(f.dataDir, v.Operation.ID)
		if err == nil && !ufwChangeReceiptMatches(receipt, v) {
			err = errors.New("UFW 原业务回执无法完整核对")
		}
		if err == nil && v.Transition.Owner == registered.NextClaim.Owner {
			operation := v.Operation
			out.Operation = &operation
			if record := v.Confirmed; record != nil {
				out.ConfirmedAction, out.ConfirmedPlanID, out.ConfirmedOperationID = record.Action, record.PlanID, record.OperationID
				out.ConfirmedVersion, out.ConfirmedPolicyHash = record.Version, record.PolicyHash
				if record.Action == "apply" {
					out.Protections = append(out.Protections, record.Protections...)
					out.ProtectionObservation = protectionObservation("unavailable", record.PlanID, "保护来源尚未完成当前核对，请刷新状态")
				}
			}
		} else if err == nil && v.Confirmed != nil && v.Confirmed.Action == "apply" {
			err = errors.New("UFW 已确认受管规则属于其他本机授权")
		}
	}
	if err != nil {
		out.CanPlan = false
		out.Reason = "UFW 原业务记录无法完整核对，请恢复原操作"
		out.ProtectionObservation = protectionObservation("unavailable", "", "独立策略不可核对，保护状态未知")
	}
	return out
}

func (f *hostFirewall) planUFWLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var out firewall.Plan
	if !f.ufwPlanning || f.problem != "" || f.state.Schema != 0 || f.firewalldState != nil || os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return out, fault.Unavailable("UFW 计划须由本机 root 明确确认宿主机范围、所有者及 SSH 保护配置")
	}
	if !slices.Contains([]string{"apply", "remove"}, in.Action) || in.Version < 1 {
		return out, fault.Invalid("UFW 策略动作、版本或后端无效")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	if ufwRestorePending(f.dataDir) {
		return out, fault.Conflict("UFW 原重载进程或业务操作尚未完成，请先恢复原操作")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return out, fault.Conflict("其他防火墙登记或执行器占用宿主机，未准备 UFW 计划")
		}
		return out, fault.Unavailable("宿主机防火墙登记锁不可用，未准备 UFW 计划")
	}
	defer unlock()
	registered, err := ufwRegistrationAuthority(f.dataDir)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	observed := (&firewallObserver{ctx: ctx, scope: "host", dataDir: f.dataDir}).collect(ctx)
	if !observed.Available || observed.Scope != "host" || observed.Manager != "ufw" || observed.Backend == "mixed" || observed.UFW.Active == nil || !*observed.UFW.Active || observed.UFW.Enabled == nil || !*observed.UFW.Enabled || observed.UFW.IPv6 == nil || !observed.UFW.RuleInventory.Available {
		return out, fault.Unavailable("UFW 管理器、启用/IPv6 配置及完整用户规则报告无法核对，保持只读")
	}
	if len(observed.Rulesets) != 5 {
		return out, fault.Unavailable("内核后端视图不完整，未准备 UFW 计划")
	}
	for _, view := range observed.Rulesets {
		if !view.Available {
			return out, fault.Unavailable("内核后端视图不完整，未准备 UFW 计划")
		}
	}
	policy, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	confirmed, err := ufwCurrentConfirmed(f.dataDir, registered.NextClaim.Owner)
	if err != nil {
		return out, fault.Conflict(err.Error())
	}
	if in.Action == "remove" {
		if policy.Hash() != firewall.DefaultPolicy().Hash() {
			return out, fault.Invalid("移除计划不能附带新的期望策略")
		}
		if confirmed == nil || confirmed.Action != "apply" || confirmed.Version != in.Version {
			return out, fault.Conflict("UFW 待移除策略与原确认版本不一致")
		}
		policy = confirmed.Policy
	}
	if policy.Backend != "ufw" {
		return out, fault.Conflict("期望策略后端与本机 UFW 选择不一致")
	}
	hash, err := firewall.PolicyDigest(policy)
	if err != nil {
		return out, err
	}
	previous, err := ufwPolicyProgram(confirmed, registered.NextClaim.Owner)
	if err != nil {
		return out, fault.Conflict(err.Error())
	}
	effect := policy
	if in.Action == "remove" {
		effect = firewall.DefaultPolicy()
	}
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	id := secure.ID()
	program, err := firewall.CompileUFWRuntime(policy, protections, in.Action, registered.NextClaim.Owner, id)
	if err != nil {
		return out, err
	}
	for _, entry := range program.Entries {
		if entry.Family == "ipv6" && !*observed.UFW.IPv6 || entry.Interface != "" && !slices.Contains(observed.Interfaces, entry.Interface) {
			return out, fault.Unavailable("UFW IPv6 未启用或规则绑定接口未观察到")
		}
	}
	binary, err := ufwTool()
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	before, err := readUFWConfiguration(ctx, binary, *observed.UFW.IPv6)
	if err != nil {
		return out, fault.Unavailable("UFW 固定配置及工具基线无法完整读取")
	}
	dryRun, err := checkUFWDryRun(ctx, binary, program, previous, before, *observed.UFW.IPv6)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	reload := dryRun.Reload
	if reload.Backend != observed.Backend {
		return out, fault.Conflict("UFW 声明的后端工具与完整观察不一致，请核对本机工具及 alternatives")
	}
	current, err := ufwTool()
	if err != nil || current != binary {
		return out, fault.Conflict("UFW 工具路径在预演期间变化，请重新准备计划")
	}
	after, err := readUFWConfiguration(ctx, binary, *observed.UFW.IPv6)
	if err != nil || before.Hash != after.Hash {
		return out, fault.Conflict("UFW 配置或工具在预演期间变化，请重新准备计划")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	currentRegistration, err := ufwRegistrationAuthority(f.dataDir)
	if err != nil || currentRegistration.RequestHash != registered.RequestHash {
		return out, fault.Conflict("UFW 本机授权登记在计划期间变化")
	}
	currentConfirmed, err := ufwCurrentConfirmed(f.dataDir, registered.NextClaim.Owner)
	if err != nil || !sameUFWPolicyRecord(currentConfirmed, confirmed) {
		return out, fault.Conflict("UFW 原确认策略在预演期间变化，请重新准备计划")
	}
	entries := append([]firewall.PreviewEntry{}, program.Entries[:min(128, len(program.Entries))]...)
	for index := range entries {
		entries[index].Expression = "ufw --dry-run prepend " + strings.Join(program.Rules[index].Arguments, " ")
	}
	warnings := []string{"UFW 插入和删除可能重载全部已启用地址族的用户链；原运行规则与持久文件已核对，候选尚未生效", "仅替换原确认回执对应的完整受管规则，其他用户规则保持原内容与相对顺序"}
	if in.Action == "apply" {
		warnings = append(warnings, "入口保护优先；与保护条件完全相同的业务条目由保护项覆盖，其余生成条目保持期望顺序")
	} else {
		warnings = append(warnings, "移除会一并撤销原受管入口保护，保留 UFW 及其他来源规则")
	}
	warnings = append(warnings, dryRun.Warnings...)
	out = firewall.Plan{Backend: "ufw", CanApply: false, Action: in.Action, ID: id, Version: in.Version, PolicyHash: hash, ProgramHash: program.Hash,
		Baseline:    firewall.KernelView{Reason: "UFW 计划核对固定配置及 dry-run，不提供直接 nftables 事务证明"},
		Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source,
		ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, GeneratedRules: len(program.Rules),
		UFW: &firewall.UFWPlan{RegistrationOperationID: registered.NextClaim.OperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, ToolchainHash: dryRun.ToolchainHash, PythonVersion: dryRun.PythonVersion, DryRunHash: dryRun.Hash, NativeProgramHash: dryRun.NativeHash, BatchHash: dryRun.BatchHash, ReloadBackend: reload.Backend, ReloadHash: reload.Hash, ReloadChains: reload.Chains, ReloadRules: reload.Rules, PreservedRules: dryRun.PreservedRules, DryRunCommands: dryRun.Commands, ProtectionRules: program.ProtectionRules, ProtectionOverrides: program.ProtectionOverrides, Entries: entries, Truncated: len(entries) < len(program.Entries),
			Warnings: warnings,
			Reason:   "本机授权、受信工具、原重载范围及批次候选已核对；正常应用、新连接确认及确认后持久化尚未开放"},
	}
	record := &firewallPolicyRecord{Action: in.Action, PlanID: id, Version: in.Version, Policy: policy, PolicyHash: hash, ProgramHash: program.Hash, Protections: protections, Marker: firewall.UFWCommentPrefix + registered.NextClaim.Owner + ":" + id + ":",
		ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: out.Listener, AllowedSources: append([]string{}, f.remote.state.Confirmed.AllowedSources...), ControlSource: source}}
	transition, err := newUFWTransition(registered, before, dryRun, *observed.UFW.IPv6, *record, confirmed)
	if err != nil {
		return firewall.Plan{}, fault.Unavailable(err.Error())
	}
	if err = f.storePlanLocked(out, record); err != nil {
		return out, err
	}
	private := f.plans[id]
	private.ufw = transition
	f.plans[id] = private
	return out, nil
}
