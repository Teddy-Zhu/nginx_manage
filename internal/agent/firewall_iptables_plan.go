package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type iptablesInitialTransition struct {
	Owner, MachineHash                                                            string
	RegistrationOperationID, RegistrationRequestHash, ConfigurationHash, ToolHash string
	Program                                                                       *firewall.IPTablesRuntimeProgram
	Materials                                                                     []iptablesInitialMaterial
	Tools                                                                         *iptablesToolBinding
	DryRun                                                                        *iptablesDryRunProof
}

func (f *hostFirewall) iptablesPlannerLocked() bool {
	return validIPTablesBackend(f.owner) && f.state.Schema == 0 && f.ufwState == nil && f.firewalldState == nil
}

func (f *hostFirewall) openIPTablesPlanner(v *iptablesChangeCheckpoint) error {
	f.available = false
	f.iptablesState = v
	if v != nil && (iptablesBusinessPending(f.dataDir) || !validIPTablesBackend(f.owner)) {
		f.owner = v.Policy.Policy.Backend
	}
	if os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		f.problem, f.policyUncertain = "iptables 计划须在真实宿主机 root 范围准备", true
		return nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-agent.lock")
	if err != nil {
		return errors.Join(errors.New("其他 iptables Agent 正在维护原操作"), err)
	}
	f.unlock, f.recovering, f.policyUncertain = unlock, true, false
	call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = f.recoverIPTablesLocked(call)
	return nil
}

func (f *hostFirewall) iptablesViewLocked() firewall.RuntimeView {
	registration, err := iptablesRegistrationAuthority(f.dataDir)
	pending := iptablesRegistrationPending(f.dataDir)
	out := firewall.RuntimeView{Backend: f.owner, CanPlan: f.iptablesPlanning && !f.policyUncertain && f.problem == "" && err == nil && !pending, Reason: f.problem, ConfirmedAction: "none", Protections: []firewall.Protection{}, ProtectionObservation: protectionObservation("not_applicable", "", "尚无已确认的 iptables 业务策略"), Kernel: firewall.KernelView{Reason: "iptables 使用独立的原生规则与代际链核对"}}
	if f.iptablesState != nil {
		op := f.iptablesState.Operation
		out.Operation = &op
	}
	if out.Reason == "" {
		switch {
		case !f.iptablesPlanning:
			out.Reason = "须由本机 root 明确确认显式 iptables 后端、宿主机范围及 SSH 保护配置"
		case err != nil:
			out.Reason = "iptables 本机授权尚未完成或无法核对，请检查 iptables-registration"
		case pending:
			out.Reason = "iptables 本机授权、原业务或子进程仍待恢复核对"
		case registration.NextClaim.Backend != f.owner:
			out.CanPlan, out.Reason = false, "本机授权后端与 Agent 显式选择不一致，不能切换系统 alternatives"
		default:
			out.Reason = "可准备代际计划；正常确认及已确认策略恢复尚未接入，保持只读"
		}
	}
	return out
}

func (f *hostFirewall) planIPTablesLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var empty firewall.Plan
	if !f.iptablesPlanning || f.policyUncertain || f.problem != "" || !f.iptablesPlannerLocked() || iptablesRegistrationPending(f.dataDir) {
		return empty, fault.Unavailable("iptables 计划须由本机确认宿主机范围、显式后端及 SSH 保护配置")
	}
	if in.PreparationID != "" || in.CancelPreparation || in.Version < 1 || in.Action != "apply" {
		return empty, fault.Invalid("当前 iptables 计划要求明确的应用动作及期望版本；尚无可移除的已确认业务策略")
	}
	if f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) || f.remote.pendingLocked() {
		return empty, fault.Conflict("存在未完成的可达性变更")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return empty, fault.Conflict("其他防火墙登记或执行器占用宿主机，未生成 iptables 计划")
	}
	defer unlock()
	registered, err := iptablesRegistrationAuthority(f.dataDir)
	if err != nil || registered.NextClaim.Backend != f.owner {
		return empty, fault.Unavailable("iptables 本机授权与显式后端无法核对")
	}
	policy, err := in.Policy.Normalize()
	if err != nil {
		return empty, err
	}
	if policy.Backend != f.owner {
		return empty, fault.Conflict("iptables 期望后端与本机授权选择不一致")
	}
	protections, listeners, source, err := firewallProtections(ctx, policy, f.sshMode, f.remote, connection)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	id := secure.ID()
	program, err := firewall.CompileIPTablesRuntime(policy, protections, registered.NextClaim.Owner, id)
	if err != nil {
		return empty, err
	}
	before, err := inspectIPTablesRegistration(ctx, f.dataDir, f.owner, true)
	if err != nil {
		return empty, fault.Unavailable("iptables 初始空命名空间、工具及完整环境无法核对：" + err.Error())
	}
	wanted := &firewall.IPTablesProgram{Backend: f.owner, Families: []firewall.IPTablesFamilyProgram{}}
	for _, generation := range program.Families {
		wanted.Families = append(wanted.Families, firewall.IPTablesFamilyProgram{Family: generation.Family})
	}
	problems, warnings := firewall.IPTablesEnvironment(before.Observed, wanted)
	if len(problems) != 0 {
		return empty, fault.Unavailable(strings.Join(problems, "；"))
	}
	for _, rule := range policy.Rules {
		if rule.Enabled && rule.Interface != "" && !slices.Contains(before.Observed.Interfaces, rule.Interface) {
			return empty, fault.Unavailable("iptables 规则绑定接口未在目标观察到")
		}
	}
	transition := &iptablesInitialTransition{Owner: registered.NextClaim.Owner, MachineHash: registered.NextClaim.MachineHash, RegistrationOperationID: registered.NextClaim.OperationID, RegistrationRequestHash: registered.RequestHash, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, Program: program, Materials: []iptablesInitialMaterial{}}
	summary := &firewall.IPTablesPlan{RegistrationOperationID: registered.NextClaim.OperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, LogicalHash: program.LogicalHash, ProtectionRules: program.ProtectionRules, Families: []firewall.IPTablesFamilyPlan{}, Warnings: warnings, Reason: "候选及正反向批次已通过官方 --test；正常确认及已确认策略恢复尚未接入，不可应用"}
	generated, transactionBytes := 0, 0
	for _, generation := range program.Families {
		var image *iptablesImage
		for index := range before.Images {
			if before.Images[index].Family == generation.Family {
				image = &before.Images[index]
			}
		}
		if image == nil {
			return empty, fault.Unavailable("iptables 当前地址族的完整导出缺失")
		}
		material, err := initialIPTablesMaterial(*image, generation)
		if err != nil {
			return empty, fault.Unavailable(err.Error())
		}
		preserved := 0
		for _, table := range image.Tables {
			for _, chain := range table.Chains {
				preserved += len(chain.Rules)
			}
		}
		transition.Materials = append(transition.Materials, material)
		summary.Families = append(summary.Families, firewall.IPTablesFamilyPlan{Family: generation.Family, Binary: generation.Binary, Chain: generation.Chain, HookPosition: 1, GeneratedRules: len(generation.Rules) + 2, PreservedRules: preserved, BeforeHash: material.BeforeHash, AfterHash: material.AfterHash, CandidateHash: material.CandidateHash, PreviousHash: material.PreviousHash, CandidateBytes: len(material.Candidate), PreviousBytes: len(material.Previous)})
		generated += len(generation.Rules) + 2
		transactionBytes += len(material.Candidate)
	}
	transition.Tools, err = bindIPTablesTools(ctx, f.owner)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	transition.DryRun, err = preflightIPTables(ctx, transition)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	summary.ToolchainHash, summary.DryRunHash, summary.DryRunCommands = transition.Tools.Hash, transition.DryRun.Hash, len(transition.DryRun.Calls)
	after, err := inspectIPTablesRegistration(ctx, f.dataDir, f.owner, true)
	if err != nil || after.Hash != before.Hash {
		return empty, fault.Conflict("iptables 工具、后端或完整规则在计划期间变化，请重新生成")
	}
	current, err := iptablesRegistrationAuthority(f.dataDir)
	if err != nil || current.RequestHash != registered.RequestHash {
		return empty, fault.Conflict("iptables 本机授权在计划期间变化")
	}
	if err = transition.Tools.verify(ctx); err != nil {
		return empty, fault.Conflict(err.Error())
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	raw, err := json.Marshal(transition)
	if err != nil || len(raw) > 16<<20 {
		return empty, errors.New("iptables 完整私有计划超过 16 MiB 或无法编码")
	}
	policyHash, err := firewall.PolicyDigest(policy)
	if err != nil {
		return empty, err
	}
	summary.Warnings = append(summary.Warnings, "INPUT 跳转计划插入首位；本应用 ACCEPT 可能结束后续 INPUT 判断，云安全组及其他过滤路径仍可拒绝", "IPv4/IPv6 分别处理，不保证跨地址族原子性；只生成本应用链及精确规则操作，不恢复第三方历史快照", "官方 --test 不安装规则，也不证明端口可达；系统共享库及扩展仍由宿主机提供")
	view := firewall.Plan{Backend: f.owner, CanApply: false, IPTables: summary, Action: in.Action, ID: id, Version: in.Version, PolicyHash: policyHash, ProgramHash: program.Hash, Baseline: firewall.KernelView{Reason: "完整 iptables 规则摘要见地址族代际计划"}, Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source, ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, TransactionHash: secure.Hash(append([]byte("iptables:initial-plan:v1:\x00"), raw...)), TransactionBytes: transactionBytes, GeneratedRules: generated}
	record := &firewallPolicyRecord{Action: in.Action, PlanID: id, Version: in.Version, Policy: policy, PolicyHash: policyHash, ProgramHash: program.Hash, Protections: protections, Marker: program.Marker, ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: view.Listener, AllowedSources: slices.Clone(f.remote.state.Confirmed.AllowedSources), ControlSource: source}}
	if err = f.storePlanLocked(view, record); err != nil {
		return empty, err
	}
	private := f.plans[id]
	private.iptables = transition
	f.plans[id] = private
	return view, nil
}
