package agent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

func (f *hostFirewall) ufwViewLocked() firewall.RuntimeView {
	registered, registrationErr := ufwRegistrationAuthority(f.dataDir)
	pending := ufwRestorePending(f.dataDir)
	out := firewall.RuntimeView{Backend: "ufw", Preparation: f.ufwPreparationViewLocked(), CanPlan: f.ufwPlanning && f.recovering && !f.policyUncertain && !f.ufwPreparingLocked() && f.problem == "" && registrationErr == nil && !pending, Reason: f.problem, Protections: []firewall.Protection{}, ConfirmedAction: "none", ProtectionObservation: f.protectionObservationLocked(), Kernel: firewall.KernelView{Reason: "UFW 使用独立的用户规则与运行状态核对"}}
	if out.Reason == "" {
		if !f.ufwPlanning {
			out.Reason = "须由本机 root 确认 UFW、宿主机范围及 SSH 保护配置后准备计划"
		} else if !f.recovering || f.policyUncertain {
			out.Reason = "UFW 控制器或独立策略状态尚未核对，保持只读"
		} else if registrationErr != nil {
			out.Reason = "UFW 本机授权登记尚未完成或无法核对，请本机检查 ufw-registration 并恢复原操作"
		} else if pending {
			out.Reason = "UFW 原业务、确认规则修复或子进程尚未完成，保持只读"
		} else if f.ufwPreparingLocked() {
			out.Reason = "UFW 计划正在准备，尚未更改规则"
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
			f.ufwState = v
			f.ufwLastRescue = v.LastRescue
			operation := v.Operation
			out.Operation = &operation
			if record := v.Confirmed; record != nil {
				out.ConfirmedAction, out.ConfirmedPlanID, out.ConfirmedOperationID = record.Action, record.PlanID, record.OperationID
				out.ConfirmedVersion, out.ConfirmedPolicyHash = record.Version, record.PolicyHash
				if record.Action == "apply" {
					out.Protections = append(out.Protections, record.Protections...)
				}
			}
		} else if err == nil && v.Confirmed != nil && v.Confirmed.Action == "apply" {
			err = errors.New("UFW 已确认受管规则属于其他本机授权")
		}
	}
	out.ProtectionObservation = f.protectionObservationLocked()
	if err != nil {
		out.CanPlan = false
		out.Reason = "UFW 原业务记录无法完整核对，请恢复原操作"
		out.ProtectionObservation = protectionObservation("unavailable", "", "独立策略不可核对，保护状态未知")
	}
	if out.CanPlan {
		// A ready view must also prove the current owned scope. In particular,
		// an initial/removal receipt alone cannot authorize module removal.
		call, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		observed := readUFW(call)
		registration := ufwRegistrationView(call, f.dataDir, observed)
		out.Available = call.Err() == nil && registration.Verified && observed.Active != nil && *observed.Active && observed.Enabled != nil && *observed.Enabled
		if !out.Available {
			out.Reason = registration.Reason
			if registration.Verified {
				out.Reason = "UFW 当前运行或持久启用状态无法核对，请本机检查"
			}
		}
	}
	return out
}

type ufwPreparationBasis struct {
	View              firewall.Plan
	Record            firewallPolicyRecord
	Registration      *ufwRegistrationCheckpoint
	Confirmed         *firewallPolicyRecord
	Previous, Program *firewall.UFWProgram
}

// Expensive private dry-runs do not hold the DNS/listener/firewall mutexes.
// The current controller reserves admission separately, and rechecks its live
// protection basis when publishing the completed immutable plan.
func prepareUFWPlan(ctx context.Context, dataDir string, basis ufwPreparationBasis, progress func(int) error) (firewallPrivatePlan, error) {
	var empty firewallPrivatePlan
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return empty, fault.Conflict("其他防火墙登记或执行器占用宿主机，未准备 UFW 计划")
		}
		return empty, fault.Unavailable("宿主机防火墙登记锁不可用，未准备 UFW 计划")
	}
	defer unlock()
	if err := forbidIPTablesRegistration(dataDir); err != nil {
		return empty, fault.Conflict(err.Error())
	}
	registered, err := ufwRegistrationAuthority(dataDir)
	if err != nil || registered.RequestHash != basis.Registration.RequestHash {
		return empty, fault.Conflict("UFW 本机授权登记已变化")
	}
	confirmed, err := ufwCurrentConfirmed(dataDir, registered.NextClaim.Owner)
	if err != nil || !sameUFWPolicyRecord(confirmed, basis.Confirmed) || ufwRestorePending(dataDir) {
		return empty, fault.Conflict("UFW 原确认策略或恢复状态已变化")
	}
	observed := (&firewallObserver{ctx: ctx, scope: "host", dataDir: dataDir}).collect(ctx)
	if !observed.Available || observed.Scope != "host" || observed.Manager != "ufw" || observed.Backend == "mixed" || observed.UFW.Active == nil || !*observed.UFW.Active || observed.UFW.Enabled == nil || !*observed.UFW.Enabled || observed.UFW.IPv6 == nil || !observed.UFW.RuleInventory.Available {
		return empty, fault.Unavailable("UFW 管理器、启用/IPv6 配置及完整用户规则报告无法核对，保持只读")
	}
	if len(observed.Rulesets) != 5 {
		return empty, fault.Unavailable("内核后端视图不完整，未准备 UFW 计划")
	}
	for _, view := range observed.Rulesets {
		if !view.Available {
			return empty, fault.Unavailable("内核后端视图不完整，未准备 UFW 计划")
		}
	}
	program := basis.Program
	for _, entry := range program.Entries {
		if entry.Family == "ipv6" && !*observed.UFW.IPv6 || entry.Interface != "" && !slices.Contains(observed.Interfaces, entry.Interface) {
			return empty, fault.Unavailable("UFW IPv6 未启用或规则绑定接口未观察到")
		}
	}
	binary, err := ufwTool()
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	before, err := readUFWConfiguration(ctx, binary, *observed.UFW.IPv6)
	if err != nil {
		return empty, fault.Unavailable("UFW 固定配置及工具基线无法完整读取")
	}
	dryRun, err := checkUFWDryRun(ctx, binary, program, basis.Previous, before, *observed.UFW.IPv6, progress)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	reload := dryRun.Reload
	if reload.Backend != observed.Backend {
		return empty, fault.Conflict("UFW 声明的后端工具与完整观察不一致，请核对本机工具及 alternatives")
	}
	current, err := ufwTool()
	if err != nil || current != binary {
		return empty, fault.Conflict("UFW 工具路径在预演期间变化，请重新准备计划")
	}
	after, err := readUFWConfiguration(ctx, binary, *observed.UFW.IPv6)
	if err != nil || before.Hash != after.Hash {
		return empty, fault.Conflict("UFW 配置或工具在预演期间变化，请重新准备计划")
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	currentRegistration, err := ufwRegistrationAuthority(dataDir)
	if err != nil || currentRegistration.RequestHash != registered.RequestHash {
		return empty, fault.Conflict("UFW 本机授权登记在计划期间变化")
	}
	currentConfirmed, err := ufwCurrentConfirmed(dataDir, registered.NextClaim.Owner)
	if err != nil || !sameUFWPolicyRecord(currentConfirmed, confirmed) {
		return empty, fault.Conflict("UFW 原确认策略在预演期间变化，请重新准备计划")
	}
	entries := append([]firewall.PreviewEntry{}, program.Entries[:min(128, len(program.Entries))]...)
	for index := range entries {
		entries[index].Expression = "ufw --dry-run prepend " + strings.Join(program.Rules[index].Arguments, " ")
	}
	warnings := []string{"UFW 插入和删除可能重载全部已启用地址族的用户链；原运行规则与持久文件已核对，候选尚未生效", "仅替换原确认回执对应的完整受管规则，其他用户规则保持原内容与相对顺序"}
	if basis.Record.Action == "apply" {
		warnings = append(warnings, "入口保护优先；与保护条件完全相同的业务条目由保护项覆盖，其余生成条目保持期望顺序")
	} else {
		warnings = append(warnings, "移除会一并撤销原受管入口保护，保留 UFW 及其他来源规则")
	}
	warnings = append(warnings, dryRun.Warnings...)
	out := basis.View
	out.CanApply = true
	out.Baseline = firewall.KernelView{Reason: "UFW 原用户链及候选配置已核对"}
	out.ExpiresAt = time.Now().Unix() + 300
	out.UFW = &firewall.UFWPlan{RegistrationOperationID: registered.NextClaim.OperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, ToolchainHash: dryRun.ToolchainHash, PythonVersion: dryRun.PythonVersion, DryRunHash: dryRun.Hash, NativeProgramHash: dryRun.NativeHash, BatchHash: dryRun.BatchHash, ReloadBackend: reload.Backend, ReloadHash: reload.Hash, ReloadChains: reload.Chains, ReloadRules: reload.Rules, PreservedRules: dryRun.PreservedRules, DryRunCommands: dryRun.Commands, ProtectionRules: program.ProtectionRules, ProtectionOverrides: program.ProtectionOverrides, Entries: entries, Truncated: len(entries) < len(program.Entries), Warnings: warnings, Reason: "受信工具、当前配置及全部候选预演已核对，应用前须重新核对保护依据"}
	transition, err := newUFWTransition(registered, before, dryRun, *observed.UFW.IPv6, basis.Record, confirmed)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	return firewallPrivatePlan{view: out, record: &basis.Record, ufw: transition}, nil
}
