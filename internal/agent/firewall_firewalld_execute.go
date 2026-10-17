package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

func (f *hostFirewall) checkFirewalldEnvironment(ctx context.Context) ([]string, error) {
	observed, err := inspectFirewalldRegistration(ctx, f.dataDir, "host")
	if err != nil {
		return nil, fault.Unavailable("firewalld 管理器或内核后端无法完整核对")
	}
	issues, warnings := firewall.FirewalldEnvironment(observed)
	if f.firewalldState != nil && f.firewalldState.Candidate != nil {
		issues, warnings = firewall.FirewalldManagerEnvironment(observed)
	}
	if len(issues) != 0 {
		return warnings, fault.Conflict(issues[0])
	}
	return warnings, nil
}
func (f *hostFirewall) applyFirewalldLocked(ctx context.Context, id, planID string, version int64, hash, action, connection string) (firewall.Operation, error) {
	var out firewall.Operation
	v := f.firewalldState
	if !f.available || f.problem != "" || v == nil {
		return out, fault.Unavailable("firewalld 执行尚未就绪")
	}
	if v.Candidate != nil || v.Call != nil || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成可达性变更")
	}
	plan, ok := f.plans[planID]
	if !ok || time.Now().Unix() >= plan.view.ExpiresAt {
		return out, fault.Conflict("计划不存在或已过期")
	}
	if !plan.view.CanApply || plan.record == nil || plan.view.Backend != "firewalld" || plan.view.Firewalld == nil || plan.view.Version != version || plan.view.PolicyHash != hash || plan.view.Action != action {
		return out, fault.Conflict("已保存策略与 firewalld 计划不一致")
	}
	if action == "remove" && (v.Confirmed == nil || v.Confirmed.Action != "apply" || v.Confirmed.Version != version || v.Confirmed.PolicyHash != hash) {
		return out, fault.Conflict("待移除的策略已变化")
	}
	if f.remote.state.Version != plan.view.ListenerVersion || f.remote.state.Confirmed.Listen != plan.view.Listener {
		return out, fault.Conflict("管理监听变化，请重新计划")
	}
	effect := plan.record.Policy
	if action == "remove" {
		effect = firewall.DefaultPolicy()
	}
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	actual, _ := json.Marshal(struct {
		P []firewall.Protection
		L []string
		S string
	}{protections, listeners, source})
	expected, _ := json.Marshal(struct {
		P []firewall.Protection
		L []string
		S string
	}{plan.view.Protections, plan.view.SSHListeners, plan.view.ControlSource})
	if string(actual) != string(expected) {
		return out, fault.Conflict("SSH、控制来源或保护配置变化，请重新计划")
	}
	if _, err = f.checkFirewalldEnvironment(ctx); err != nil {
		return out, err
	}
	baseline, err := f.firewalldConfirmedSnapshot(ctx)
	if err != nil || baseline.Policy.Runtime.Hash != plan.view.Firewalld.RuntimeHash || baseline.Policy.Permanent.Hash != plan.view.Firewalld.PermanentHash || v.RegistrationOperationID != plan.view.Firewalld.RegistrationOperationID {
		return out, fault.Conflict("firewalld 配置基线已变化，请重新计划")
	}
	candidate := *plan.record
	candidate.OperationID = id
	op := &firewall.Operation{Action: action, ID: id, PlanID: planID, Version: version, PolicyHash: hash, ProgramHash: candidate.ProgramHash, State: "running", Stage: "submitting_runtime", Deadline: time.Now().Unix() + firewall.ConfirmationSeconds, UpdatedAt: time.Now().Unix(), VerificationScope: "controlled-listener"}
	v.Operation, v.Candidate, v.RequestHash, v.Rollback, v.Call = op, &candidate, firewallRequestHash(planID, action), false, nil
	f.deadline, f.protectionObservedAt = time.Now().Add(firewall.ConfirmationSeconds*time.Second), time.Time{}
	if err = f.saveFirewalld(); err != nil {
		v.Rollback = true
		return *op, err
	}
	delete(f.plans, planID)
	if err = f.writeFirewalld("runtime", "candidate", baseline); err != nil {
		recoveryErr := f.rollbackFirewalldLocked("运行配置提交未取得完整回执，恢复最后确认配置")
		return *v.Operation, errors.Join(err, recoveryErr)
	}
	post, err := f.firewalldSnapshot(context.Background())
	program, programErr := firewalldProgram(v.Candidate)
	previous, previousErr := firewalldProgram(v.Confirmed)
	if err != nil || programErr != nil || previousErr != nil || !firewalldSettingsMatch(post.Runtime, v.Owner, program) || !firewalldSettingsMatch(post.Permanent, v.Owner, previous) || f.expiredLocked() {
		err = f.rollbackFirewalldLocked("候选运行配置或原永久配置未完整核对，恢复最后确认配置")
		return *v.Operation, err
	}
	op.State, op.Stage, op.UpdatedAt = "waiting_confirmation", "awaiting_new_connection", time.Now().Unix()
	v.RuntimeHash, v.PermanentHash = post.Policy.Runtime.Hash, post.Policy.Permanent.Hash
	if err = f.saveFirewalld(); err != nil {
		recoveryErr := f.rollbackFirewalldLocked("候选回执未保存，恢复最后确认配置")
		return *v.Operation, errors.Join(err, recoveryErr)
	}
	f.remote.stopListening()
	if err = f.remote.reconcile(); err != nil {
		recoveryErr := f.rollbackFirewalldLocked("无法建立新的确认监听，恢复最后确认配置")
		return *v.Operation, errors.Join(err, recoveryErr, f.remote.reconcile())
	}
	f.proofListener = f.remote.listener
	for socketID, socket := range f.remote.connections {
		if socketID != connection {
			shutdownListenerConn(socket.conn)
			delete(f.remote.connections, socketID)
		}
	}
	return *op, nil
}

func (f *hostFirewall) decideFirewalldLocked(ctx context.Context, id, action, connection string) (firewall.Operation, error) {
	v := f.firewalldState
	out, err := f.operationLocked(id)
	if err != nil || v.Candidate == nil || v.Operation.ID != id {
		return out, err
	}
	if action == "rollback" || f.expiredLocked() {
		err = f.rollbackFirewalldLocked("已请求恢复或确认期限已到")
		return *v.Operation, err
	}
	if v.Rollback || out.State != "waiting_confirmation" || f.problem != "" {
		return out, fault.Conflict("当前操作仅允许继续恢复")
	}
	socket, ok := f.remote.connections[connection]
	if !ok || f.proofListener == nil || socket.listener != f.proofListener || f.remote.listener != f.proofListener || socket.version != f.remote.state.Version || f.remote.web == nil {
		return out, fault.Conflict("须通过规则生效后新建的 TCP/TLS 连接确认")
	}
	peer := net.ParseIP(socket.source)
	if peer == nil || peer.IsLoopback() || peer.IsUnspecified() {
		return out, fault.Conflict("须从非回环的管理连接确认")
	}
	deadline := time.Unix(out.Deadline, 0)
	if !f.deadline.IsZero() && f.deadline.Before(deadline) {
		deadline = f.deadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	observed := f.observeProtectionsLocked(ctx, v.Candidate)
	if f.expiredLocked() || observed.State == "changed" {
		err = f.rollbackFirewalldLocked("确认期限已到或保护依据变化，恢复最后确认配置")
		return *v.Operation, err
	}
	if observed.State == "unavailable" {
		return out, fault.Unavailable(observed.Reason)
	}
	if _, err = f.checkFirewalldEnvironment(ctx); err != nil {
		return out, err
	}
	if err = f.firewalldCallEnded(); err != nil {
		return out, fault.Unavailable(err.Error())
	}
	current, err := f.firewalldSnapshot(ctx)
	candidate, candidateErr := firewalldProgram(v.Candidate)
	previous, previousErr := firewalldProgram(v.Confirmed)
	if err != nil || candidateErr != nil || previousErr != nil || !firewalldSettingsMatch(current.Runtime, v.Owner, candidate) || !firewalldSettingsMatch(current.Permanent, v.Owner, previous) {
		return out, fault.Conflict("运行候选或原永久配置发生变化，禁止确认")
	}
	if f.expiredLocked() || ctx.Err() != nil {
		err = f.rollbackFirewalldLocked("确认核对期限已到")
		return *v.Operation, err
	}
	v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "running", "persisting_confirmed", time.Now().Unix()
	if err = f.saveFirewalld(); err != nil {
		return *v.Operation, err
	}
	if err = f.writeFirewalld("permanent", "candidate", current); err != nil {
		recoveryErr := f.rollbackFirewalldLocked("永久配置写入未完整核对，恢复最后确认配置")
		return *v.Operation, errors.Join(err, recoveryErr)
	}
	post, err := f.firewalldSnapshot(context.Background())
	if err != nil || !firewalldSettingsMatch(post.Runtime, v.Owner, candidate) || !firewalldSettingsMatch(post.Permanent, v.Owner, candidate) || f.expiredLocked() {
		err = f.rollbackFirewalldLocked("永久配置回读或确认期限未通过，恢复最后确认配置")
		return *v.Operation, err
	}
	before := *v
	confirmed := *v.Operation
	confirmed.State, confirmed.Stage, confirmed.ConfirmedSource, confirmed.Error, confirmed.UpdatedAt = "succeeded", "confirmed", socket.source, "", time.Now().Unix()
	if confirmed.Action == "remove" {
		confirmed.Stage = "rules_removed"
	}
	v.Confirmed, v.Candidate, v.Operation, v.Rollback, v.Call = v.Candidate, nil, &confirmed, false, nil
	v.RuntimeHash, v.PermanentHash = post.Policy.Runtime.Hash, post.Policy.Permanent.Hash
	written, err := f.persistFirewalld()
	if err != nil {
		if !written {
			*v = before
		}
		return *v.Operation, err
	}
	f.problem, f.proofListener, f.policyUncertain = "", nil, false
	f.protectionObservation, f.protectionObservedAt = observed, time.Now()
	return confirmed, nil
}

func (f *hostFirewall) rollbackFirewalldLocked(reason string) error {
	v := f.firewalldState
	if v.Candidate == nil {
		return nil
	}
	op := *v.Operation
	op.State, op.Stage, op.Error, op.UpdatedAt = "compensating", "restoring_confirmed", reason, time.Now().Unix()
	v.Operation, v.Rollback = &op, true
	if err := f.saveFirewalld(); err != nil {
		return err
	}
	if err := f.firewalldCallEnded(); err != nil {
		return f.firewalldFailure(err.Error())
	}
	if err := f.restoreFirewalldConfirmed(); err != nil {
		return f.firewalldFailure("firewalld 原运行/永久配置尚未恢复核对；" + err.Error())
	}
	before := *v
	rolledBack := *v.Operation
	rolledBack.State, rolledBack.Stage, rolledBack.Error, rolledBack.UpdatedAt = "rolled_back", "confirmed_restored", reason, time.Now().Unix()
	v.Operation, v.Candidate, v.Call, v.Rollback = &rolledBack, nil, nil, false
	written, err := f.persistFirewalld()
	if err != nil {
		if !written {
			*v = before
		}
		return err
	}
	f.problem, f.proofListener, f.policyUncertain = "", nil, false
	return nil
}

func (f *hostFirewall) restoreFirewalldConfirmed() error {
	v := f.firewalldState
	if err := f.firewalldCallEnded(); err != nil {
		return err
	}
	p, err := firewalldProgram(v.Confirmed)
	if err != nil {
		return err
	}
	for _, plane := range []string{"runtime", "permanent"} {
		current, err := f.firewalldSnapshot(context.Background())
		if err != nil {
			return err
		}
		if !f.firewalldRecoverable(current.Runtime) || !f.firewalldRecoverable(current.Permanent) {
			return errors.New("目标含未登记配置或第三方规则，禁止覆盖")
		}
		settings := current.Runtime
		if plane == "permanent" {
			settings = current.Permanent
		}
		if firewalldSettingsMatch(settings, v.Owner, p) {
			continue
		}
		if v.Operation == nil {
			return errors.New("初始空 policy 漂移，须停止 Agent 后由本机 root 核对")
		}
		if err = f.writeFirewalld(plane, "confirmed", current); err != nil {
			return err
		}
	}
	post, err := f.firewalldConfirmedSnapshot(context.Background())
	if err == nil {
		v.RuntimeHash, v.PermanentHash = post.Policy.Runtime.Hash, post.Policy.Permanent.Hash
	}
	return err
}
