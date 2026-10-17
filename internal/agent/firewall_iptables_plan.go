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

type iptablesTransition struct {
	Previous                                                                      *iptablesPolicySource
	Owner, MachineHash                                                            string
	RegistrationOperationID, RegistrationRequestHash, ConfigurationHash, ToolHash string
	Program                                                                       *firewall.IPTablesRuntimeProgram
	Materials                                                                     []iptablesChangeMaterial
	Tools                                                                         *iptablesToolBinding
	DryRun                                                                        *iptablesDryRunProof
}

func (f *hostFirewall) iptablesPlannerLocked() bool {
	return validIPTablesBackend(f.owner) && f.state.Schema == 0 && f.ufwState == nil && f.firewalldState == nil
}

func (f *hostFirewall) openIPTablesPlanner(v *iptablesChangeCheckpoint) error {
	f.available = false
	f.iptablesState = v
	if v != nil {
		f.iptablesLastRescue = v.LastRescue
	}
	if v != nil && (iptablesBusinessPending(f.dataDir) || v.Confirmed != nil && v.Confirmed.Action == "apply" || !validIPTablesBackend(f.owner)) {
		f.iptablesPlanning = f.iptablesPlanning && f.owner == v.Policy.Policy.Backend
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
	if err = f.rescueIPTablesLocked(call); err != nil {
		f.problem = "iptables 本机救援请求尚未完成核对"
	}
	return nil
}

func (f *hostFirewall) iptablesViewLocked() firewall.RuntimeView {
	registration, err := iptablesRegistrationAuthority(f.dataDir)
	pending := iptablesRegistrationPending(f.dataDir)
	out := firewall.RuntimeView{Backend: f.owner, CanPlan: f.iptablesPlanning && !f.policyUncertain && f.problem == "" && err == nil && !pending, Reason: f.problem, ConfirmedAction: "none", Protections: []firewall.Protection{}, ProtectionObservation: protectionObservation("not_applicable", "", "尚无已确认的 iptables 业务策略"), Kernel: firewall.KernelView{Reason: "iptables 使用独立的原生规则与代际链核对"}}
	if f.iptablesState != nil && (err != nil || f.iptablesState.Transition.Owner == registration.NextClaim.Owner && f.iptablesState.Transition.RegistrationOperationID == registration.NextClaim.OperationID) {
		op := f.iptablesState.Operation
		out.Operation = &op
		if record := f.iptablesState.Confirmed; record != nil {
			out.ConfirmedAction, out.ConfirmedPlanID, out.ConfirmedOperationID = record.Action, record.PlanID, record.OperationID
			out.ConfirmedVersion, out.ConfirmedPolicyHash = record.Version, record.PolicyHash
			if record.Action == "apply" {
				out.Protections = append(out.Protections, record.Protections...)
			}
		}
	} else if f.iptablesState != nil && f.iptablesState.Confirmed != nil && f.iptablesState.Confirmed.Action == "apply" {
		out.CanPlan, out.Reason = false, "iptables 原确认策略属于其他本机授权，请恢复原操作"
	}
	out.ProtectionObservation = f.protectionObservationLocked()
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
			out.Reason = "可准备应用或移除代际计划；完整执行准入尚未完成，保持只读"
		}
	}
	return out
}

func iptablesProtectionPolicy(record firewallPolicyRecord) firewall.Policy {
	if record.Action != "remove" {
		return record.Policy
	}
	policy := firewall.DefaultPolicy()
	policy.Backend = record.Policy.Backend
	return policy
}

func (f *hostFirewall) planIPTablesLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var empty firewall.Plan
	if !f.iptablesPlanning || f.policyUncertain || f.problem != "" || !f.iptablesPlannerLocked() || iptablesRegistrationPending(f.dataDir) {
		return empty, fault.Unavailable("iptables 计划须由本机确认宿主机范围、显式后端及 SSH 保护配置")
	}
	if in.PreparationID != "" || in.CancelPreparation || in.Version < 1 || in.Action != "apply" && in.Action != "remove" {
		return empty, fault.Invalid("iptables 计划要求明确的动作及策略版本")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) || f.remote.pendingLocked() {
		return empty, fault.Conflict("存在未完成的可达性变更")
	}
	businessUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return empty, err
	}
	defer businessUnlock()
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return empty, fault.Conflict("其他防火墙登记或执行器占用宿主机，未生成 iptables 计划")
	}
	defer unlock()
	registered, err := iptablesRegistrationAuthority(f.dataDir)
	if err != nil || registered.NextClaim.Backend != f.owner {
		return empty, fault.Unavailable("iptables 本机授权与显式后端无法核对")
	}
	if err = f.refreshIPTablesStateLocked(); err != nil {
		return empty, err
	}
	previous := iptablesPlanPrevious(f.iptablesState, registered.NextClaim.Owner, registered.NextClaim.OperationID)
	if previous != nil {
		if err = verifyIPTablesSource(f.dataDir, previous); err != nil {
			return empty, err
		}
	}
	policy, err := in.Policy.Normalize()
	if err != nil {
		return empty, err
	}
	if in.Action == "remove" {
		if policy.Hash() != firewall.DefaultPolicy().Hash() {
			return empty, fault.Invalid("移除计划不能附带新的期望策略")
		}
		if previous == nil || previous.Policy.Action != "apply" || previous.Policy.Version != in.Version {
			return empty, fault.Conflict("待移除的已确认策略已变化或不存在")
		}
		policy = previous.Policy.Policy
	}
	if policy.Backend != f.owner {
		return empty, fault.Conflict("iptables 期望后端与本机授权选择不一致")
	}
	effect := iptablesProtectionPolicy(firewallPolicyRecord{Action: in.Action, Policy: policy})
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	id := secure.ID()
	program, err := firewall.CompileIPTablesRuntime(policy, protections, registered.NextClaim.Owner, id, in.Action)
	if err != nil {
		return empty, err
	}
	var before iptablesRegistrationSnapshot
	var tools *iptablesToolBinding
	if previous != nil {
		before, err = inspectIPTablesSource(ctx, f.dataDir, previous, false)
		tools = &previous.Tools
		if err == nil {
			for _, state := range before.States {
				if state != "candidate" && state != "empty" {
					err = errors.New("iptables 原确认代际无法完整核对")
				}
			}
		}
		prior := iptablesPreviousProgram(&iptablesTransition{Previous: previous})
		if err == nil {
			for _, generation := range prior.Families {
				if before.States[generation.Family] != "candidate" {
					err = errors.New("iptables 原确认代际缺失，请先恢复")
				}
			}
		}
	} else {
		before, err = inspectIPTablesRegistration(ctx, f.dataDir, f.owner, true)
		if err == nil {
			tools, err = bindIPTablesTools(ctx, f.owner)
		}
	}
	if err != nil {
		return empty, fault.Unavailable("iptables 原受管范围、工具及完整环境无法核对：" + err.Error())
	}
	wanted := &firewall.IPTablesProgram{Backend: f.owner, Families: []firewall.IPTablesFamilyProgram{}}
	if previous == nil {
		for _, generation := range program.Families {
			wanted.Families = append(wanted.Families, firewall.IPTablesFamilyProgram{Family: generation.Family})
		}
	}
	problems, warnings := firewall.IPTablesEnvironment(before.Observed, wanted)
	if len(problems) != 0 {
		return empty, fault.Unavailable(strings.Join(problems, "；"))
	}
	if in.Action == "apply" {
		if err = checkIPTablesInterfaces(policy, before.Observed); err != nil {
			return empty, fault.Unavailable(err.Error())
		}
	}
	transition := &iptablesTransition{Previous: previous, Owner: registered.NextClaim.Owner, MachineHash: registered.NextClaim.MachineHash, RegistrationOperationID: registered.NextClaim.OperationID, RegistrationRequestHash: registered.RequestHash, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, Program: program, Tools: tools, Materials: []iptablesChangeMaterial{}}
	summary := &firewall.IPTablesPlan{RegistrationOperationID: registered.NextClaim.OperationID, ConfigurationHash: before.Hash, ToolHash: before.ToolHash, LogicalHash: program.LogicalHash, ProtectionRules: program.ProtectionRules, Families: []firewall.IPTablesFamilyPlan{}, Warnings: warnings, Reason: "候选及正反向批次已通过官方 --test；完整执行准入尚未完成，不可应用"}
	generated, transactionBytes := 0, 0
	prior := iptablesPreviousProgram(transition)
	for _, family := range iptablesTransitionFamilies(transition) {
		var image *iptablesImage
		for i := range before.Images {
			if before.Images[i].Family == family {
				image = &before.Images[i]
			}
		}
		if image == nil {
			return empty, fault.Unavailable("iptables 当前地址族的完整导出缺失")
		}
		old, next := iptablesGeneration(prior, family), iptablesGeneration(program, family)
		material, err := makeIPTablesChangeMaterial(*image, old, next)
		if err != nil {
			return empty, fault.Unavailable(err.Error())
		}
		foreign, _, err := iptablesForeignImage(*image, old)
		if err != nil {
			return empty, err
		}
		preserved := 0
		for _, table := range foreign.Tables {
			for _, chain := range table.Chains {
				preserved += len(chain.Rules)
			}
		}
		chain, count, position := "", 0, 0
		if next != nil {
			chain, count, position = next.Chain, len(next.Rules)+2, 1
		} else {
			chain = old.Chain
		}
		transition.Materials = append(transition.Materials, material)
		summary.Families = append(summary.Families, firewall.IPTablesFamilyPlan{Family: family, Binary: material.Binary, Chain: chain, HookPosition: position, GeneratedRules: count, PreservedRules: preserved, BeforeHash: material.BeforeHash, AfterHash: material.AfterHash, CandidateHash: material.CandidateHash, PreviousHash: material.PreviousHash, CandidateBytes: len(material.Candidate), PreviousBytes: len(material.Previous)})
		generated += count
		transactionBytes += len(material.Candidate)
	}
	if err = before.admitReadback(program, prior); err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	transition.DryRun, err = preflightIPTables(ctx, transition)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	summary.ToolchainHash, summary.DryRunHash, summary.DryRunCommands = tools.Hash, transition.DryRun.Hash, len(transition.DryRun.Calls)
	after, err := inspectIPTablesBound(ctx, f.dataDir, f.owner, transition.ToolHash, tools, prior, nil, false, false, false)
	if err != nil || after.Hash != before.Hash {
		return empty, fault.Conflict("iptables 工具、后端或完整规则在计划期间变化，请重新生成")
	}
	if err = after.admitReadback(program, prior); err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	for _, image := range before.Images {
		for _, actual := range after.Images {
			if image.Family == actual.Family && image.hash() != actual.hash() {
				return empty, fault.Conflict("iptables 原完整规则在计划期间变化")
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	policyHash, err := firewall.PolicyDigest(policy)
	if err != nil {
		return empty, err
	}
	record := &firewallPolicyRecord{Action: in.Action, PlanID: id, Version: in.Version, Policy: policy, PolicyHash: policyHash, ProgramHash: program.Hash, Protections: protections, Marker: program.Marker, ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: f.remote.state.Confirmed.Listen, AllowedSources: slices.Clone(f.remote.state.Confirmed.AllowedSources), ControlSource: source}}
	if err = validateIPTablesTransition(transition, *record); err != nil {
		return empty, err
	}
	raw, err := json.Marshal(transition)
	if err != nil || len(raw) > 16<<20 {
		return empty, errors.New("iptables 完整私有计划超过 16 MiB 或无法编码")
	}
	summary.Warnings = append(summary.Warnings, "INPUT 受管跳转位于首位；本应用 ACCEPT 可能结束后续 INPUT 判断，云安全组及其他过滤路径仍可拒绝", "IPv4/IPv6 分别处理，不保证跨地址族原子性；只操作本应用链及精确规则，不恢复第三方历史快照", "官方 --test 不安装规则，也不证明端口可达；系统共享库及扩展仍由宿主机提供")
	view := firewall.Plan{Backend: f.owner, CanApply: false, IPTables: summary, Action: in.Action, ID: id, Version: in.Version, PolicyHash: policyHash, ProgramHash: program.Hash, Baseline: firewall.KernelView{Reason: "完整 iptables 规则摘要见地址族代际计划"}, Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source, ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, TransactionHash: secure.Hash(append([]byte("iptables:plan:v2:\x00"), raw...)), TransactionBytes: transactionBytes, GeneratedRules: generated}
	if err = f.storePlanLocked(view, record); err != nil {
		return empty, err
	}
	private := f.plans[id]
	private.iptables = transition
	f.plans[id] = private
	return view, nil
}
