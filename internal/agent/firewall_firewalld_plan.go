package agent

import (
	"context"
	"errors"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const firewalldPlanningReason = "当前节点支持 firewalld 保护计划核对，尚未启用策略应用"

func (f *hostFirewall) openFirewalldPlanner() error {
	if !f.available {
		return nil
	}
	f.policyUncertain = true
	if _, _, err := firewalldHostIdentity(); err != nil {
		f.problem = "firewalld 计划须在真实宿主机 root 范围执行"
		return nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	f.unlock = unlock
	v, err := loadFirewalldRegistration(f.dataDir)
	if err != nil || v == nil || v.State != "registered" {
		f.problem = "须先停止 Agent 并由本机 root 完成 firewalld 空 policy 登记"
		return nil
	}
	f.firewalldRegistration = v
	if _, err = f.firewalldEmptySnapshot(context.Background()); err != nil {
		f.problem = "firewalld 空 policy 独立登记无法完整核对"
		return nil
	}
	f.policyUncertain = false
	return nil
}

func (f *hostFirewall) firewalldEmptySnapshot(ctx context.Context) (firewalldRegistrationSnapshot, error) {
	var out firewalldRegistrationSnapshot
	registered := f.firewalldRegistration
	if registered == nil {
		return out, errors.New("firewalld 未登记")
	}
	b, err := openFirewalldBus(ctx)
	if err != nil {
		return out, err
	}
	defer b.close()
	out, err = b.registrationSnapshot()
	if err != nil {
		return out, err
	}
	view := firewalldRegistrationView(f.dataDir, out.Inventory)
	if !view.Verified || view.OperationID != registered.OperationID || out.Policy.Runtime == nil || out.Policy.Permanent == nil || out.Policy.Runtime.Hash != registered.SettingsHash || out.Policy.Permanent.Hash != registered.SettingsHash || !firewalldEmptyMatches(out.Runtime, registered.Owner) || !firewalldEmptyMatches(out.Permanent, registered.Owner) {
		return out, errors.New("firewalld 原登记、完整空配置或活动绑定发生变化")
	}
	return out, nil
}

func (f *hostFirewall) planFirewalldLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var out firewall.Plan
	if !f.available || f.problem != "" || f.firewalldRegistration == nil {
		return out, fault.Unavailable("firewalld 计划尚未由本机确认或原空策略需要恢复")
	}
	if in.Action != "apply" || in.Version < 1 {
		return out, fault.Invalid("firewalld 当前仅支持有效版本的应用准备计划")
	}
	if f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的 DNS 可达性变更")
	}
	// Same fresh manager and full-backend admission as local registration;
	// neither the public observation cache nor a policy name grants authority.
	observed, err := inspectFirewalldRegistration(ctx, f.dataDir, "host")
	if err != nil {
		return out, fault.Unavailable("firewalld 管理器或内核后端状态无法完整核对")
	}
	issues, warnings := firewall.FirewalldEnvironment(observed)
	if len(issues) != 0 {
		return out, fault.Conflict(issues[0])
	}
	normalized, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	if normalized.Backend != "firewalld" {
		return out, fault.Conflict("期望策略后端与本机 firewalld 选择不一致")
	}
	protections, listeners, source, err := firewallProtections(ctx, normalized, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	program, err := firewall.CompileFirewalldProtected(normalized, protections)
	if err != nil {
		return out, err
	}
	snapshot, err := f.firewalldEmptySnapshot(ctx)
	if err != nil {
		return out, fault.Conflict("firewalld 原空策略基线发生变化，请本机核对")
	}
	hash, err := firewall.PolicyDigest(normalized)
	if err != nil {
		return out, err
	}
	entries := append([]firewall.PreviewEntry{}, program.Entries[:min(128, len(program.Entries))]...)
	out = firewall.Plan{Backend: "firewalld", CanApply: false, Action: "apply", ID: secure.ID(), Version: in.Version, PolicyHash: hash, ProgramHash: program.Hash,
		Baseline:    firewall.KernelView{Reason: "firewalld 计划使用运行和永久配置基线，不提供内核事务证明"},
		Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source,
		ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, GeneratedRules: len(program.Entries),
		Firewalld: &firewall.FirewalldPlan{RuntimeHash: snapshot.Policy.Runtime.Hash, PermanentHash: snapshot.Policy.Permanent.Hash, RegistrationOperationID: f.firewalldRegistration.OperationID,
			Settings: *program.Preview(), ProtectionRules: program.ProtectionRules, Entries: entries, Truncated: len(entries) < len(program.Entries), Warnings: warnings, Reason: firewalldPlanningReason},
	}
	return out, f.storePlanLocked(out, nil)
}
