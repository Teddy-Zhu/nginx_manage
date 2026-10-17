package agent

import (
	"context"
	"errors"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

func (f *hostFirewall) openFirewalldExecutor(saved *firewalldCheckpoint) error {
	if !f.available && saved == nil {
		return nil
	}
	f.policyUncertain = true
	machine, _, err := firewalldHostIdentity()
	if err != nil {
		f.problem = "firewalld 执行及恢复须在真实宿主机 root 范围执行"
		return nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	f.unlock = unlock
	if err := forbidUFWRegistration(); err != nil {
		if saved == nil {
			f.problem = err.Error()
			return nil
		}
		f.available = false
	}
	v, err := loadFirewalldRegistration(f.dataDir)
	if err != nil || v == nil || v.State != "registered" || v.MachineHash != machine || firewalldRegistrationReceipt(f.dataDir, v) != nil {
		f.problem = "须先停止 Agent 并由本机 root 完成 firewalld 空 policy 登记"
		return nil
	}
	f.firewalldRegistration = v
	if saved == nil {
		s, err := f.firewalldEmptySnapshot(context.Background())
		if err != nil {
			f.problem = "firewalld 空 policy 独立登记无法完整核对"
			return nil
		}
		f.firewalldState = &firewalldCheckpoint{Schema: 1, Owner: v.Owner, MachineHash: machine, RegistrationOperationID: v.OperationID, RuntimeHash: s.Policy.Runtime.Hash, PermanentHash: s.Policy.Permanent.Hash}
	} else {
		if saved.Owner != v.Owner || saved.MachineHash != machine || saved.RegistrationOperationID != v.OperationID {
			f.problem = "firewalld 恢复材料与本机原登记身份不一致"
			return nil
		}
		f.firewalldState = saved
		// Repair publication from the original root checkpoint before recovery.
		if err = f.saveFirewalld(); err != nil {
			return nil
		}
	}
	f.policyUncertain = false
	f.recovering = true
	if f.firewalldState.Candidate != nil {
		if err = f.rollbackFirewalldLocked("Agent 重启，恢复最后确认的运行和永久配置"); err != nil {
			f.problem = "firewalld 启动恢复未完成"
		}
	} else if err = f.reconcileFirewalldConfirmed(); err != nil {
		f.problem = "firewalld 已确认配置无法核对或恢复"
	}
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
	if !f.available || f.problem != "" || f.firewalldState == nil {
		return out, fault.Unavailable("firewalld 执行尚未由本机确认或原策略需要恢复")
	}
	if in.Action != "apply" && in.Action != "remove" || in.Version < 1 {
		return out, fault.Invalid("firewalld 动作或版本无效")
	}
	if f.activeLocked() || f.firewalldState.Call != nil || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	// Same fresh manager and full-backend admission as local registration;
	// neither the public observation cache nor a policy name grants authority.
	warnings, err := f.checkFirewalldEnvironment(ctx)
	if err != nil {
		return out, err
	}
	normalized, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	effect := normalized
	if in.Action == "remove" {
		if normalized.Hash() != firewall.DefaultPolicy().Hash() {
			return out, fault.Invalid("移除计划不能附带新的期望策略")
		}
		r := f.firewalldState.Confirmed
		if r == nil || r.Action != "apply" || r.Version != in.Version {
			return out, fault.Conflict("待移除的策略已变化或不存在")
		}
		normalized = r.Policy
		effect = firewall.DefaultPolicy()
	}
	if normalized.Backend != "firewalld" {
		return out, fault.Conflict("期望策略后端与本机 firewalld 选择不一致")
	}
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	program, err := firewall.CompileFirewalldRuntime(normalized, protections, in.Action)
	if err != nil {
		return out, err
	}
	snapshot, err := f.firewalldConfirmedSnapshot(ctx)
	if err != nil {
		return out, fault.Conflict("firewalld 原确认策略基线发生变化，请本机核对")
	}
	b, err := openFirewalldBus(ctx)
	if err != nil {
		return out, err
	}
	err = b.policyWriteSupported(firewalldRoot, firewalldName+".policy", "setPolicySettings", "sa{sv}")
	if err == nil {
		err = b.policyWriteSupported(snapshot.Path, firewalldName+".config.policy", "update", "a{sv}")
	}
	b.close()
	if err != nil {
		return out, fault.Unavailable("firewalld 运行或永久 policy 写入接口不受支持")
	}
	hash, err := firewall.PolicyDigest(normalized)
	if err != nil {
		return out, err
	}
	entries := append([]firewall.PreviewEntry{}, program.Entries[:min(128, len(program.Entries))]...)
	out = firewall.Plan{Backend: "firewalld", CanApply: true, Action: in.Action, ID: secure.ID(), Version: in.Version, PolicyHash: hash, ProgramHash: program.Hash,
		Baseline:    firewall.KernelView{Reason: "firewalld 计划使用运行和永久配置基线，不提供内核事务证明"},
		Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source,
		ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, GeneratedRules: len(program.Entries),
		Firewalld: &firewall.FirewalldPlan{RuntimeHash: snapshot.Policy.Runtime.Hash, PermanentHash: snapshot.Policy.Permanent.Hash, RegistrationOperationID: f.firewalldRegistration.OperationID,
			Settings: *program.Preview(), ProtectionRules: program.ProtectionRules, Entries: entries, Truncated: len(entries) < len(program.Entries), Warnings: warnings, Reason: "先应用运行规则，通过新连接确认后才写入永久配置；未确认时独立恢复原配置"},
	}
	record := &firewallPolicyRecord{Action: in.Action, PlanID: out.ID, Version: in.Version, Policy: normalized, PolicyHash: hash, ProgramHash: program.Hash, Protections: protections, Marker: "nginxpanel:firewalld:v1:" + f.firewalldState.Owner,
		ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: out.Listener, AllowedSources: append([]string{}, f.remote.state.Confirmed.AllowedSources...), ControlSource: source}}
	return out, f.storePlanLocked(out, record)
}
