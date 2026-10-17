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

func (f *hostFirewall) planUFWLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var out firewall.Plan
	if !f.ufwPlanning || f.problem != "" || f.state.Schema != 0 || f.firewalldState != nil || os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return out, fault.Unavailable("UFW 计划须由本机 root 明确确认宿主机范围、所有者及 SSH 保护配置")
	}
	if in.Action != "apply" || in.Version < 1 || in.Policy.Backend != "ufw" {
		return out, fault.Invalid("UFW 当前仅准备已保存期望策略的应用计划，尚无可移除的已确认规则")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的可达性变更")
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
	protections, listeners, source, err := firewallProtections(ctx, policy, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	id := secure.ID()
	program, err := firewall.CompileUFWOwned(policy, protections, registered.NextClaim.Owner, id)
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
	if before.HasManagedMarkers {
		return out, fault.Conflict("UFW 存在本应用标记但无规则写入回执，禁止接管")
	}
	dryRun, err := checkUFWDryRun(ctx, binary, program, before)
	if err != nil {
		return out, fault.Unavailable(err.Error())
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
	hash, err := firewall.PolicyDigest(policy)
	if err != nil {
		return out, err
	}
	entries := append([]firewall.PreviewEntry{}, program.Entries[:min(128, len(program.Entries))]...)
	for index := range entries {
		entries[index].Expression = "ufw --dry-run prepend " + strings.Join(program.Rules[index].Arguments, " ")
	}
	warnings := []string{"每条 prepend 命令单独基于同一源配置预演，不构成批次累积效果、内核或第三方规则所有权证明", "入口保护优先；与保护条件完全相同的业务条目由保护项覆盖，其余生成条目保持期望顺序", "注释已绑定原本机授权和计划，但尚无规则写入回执；不能据此接管或删除任何既有规则"}
	warnings = append(warnings, dryRun.Warnings...)
	out = firewall.Plan{Backend: "ufw", CanApply: false, Action: "apply", ID: id, Version: in.Version, PolicyHash: hash, ProgramHash: program.Hash,
		Baseline:    firewall.KernelView{Reason: "UFW 计划核对固定配置及 dry-run，不提供直接 nftables 事务证明"},
		Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source,
		ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, GeneratedRules: len(program.Rules),
		UFW: &firewall.UFWPlan{RegistrationOperationID: registered.NextClaim.OperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, DryRunHash: dryRun.Hash, NativeProgramHash: dryRun.NativeHash, PreservedRules: dryRun.PreservedRules, DryRunCommands: len(program.Rules), ProtectionRules: program.ProtectionRules, ProtectionOverrides: program.ProtectionOverrides, Entries: entries, Truncated: len(entries) < len(program.Entries),
			Warnings: warnings,
			Reason:   "本机授权、保护计划及逐条候选的新增原生表达式和既有用户规则保留已核对；实际应用、新连接确认和独立恢复尚未接入"},
	}
	return out, f.storePlanLocked(out, nil)
}
