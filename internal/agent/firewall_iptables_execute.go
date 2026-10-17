package agent

import (
	"context"
	"errors"
	"slices"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

var errIPTablesProtectionChanged = fault.Conflict("iptables 保护依据已变化，请恢复原操作")

func checkIPTablesInterfaces(policy firewall.Policy, observed firewall.Observation) error {
	for _, rule := range policy.Rules {
		if rule.Enabled && rule.Interface != "" && !slices.Contains(observed.Interfaces, rule.Interface) {
			return errors.New("iptables 规则绑定接口未在当前目标观察到")
		}
	}
	return nil
}

// Parent business lock is held by the caller; registry and execution guards
// cover the complete read-back and the resulting durable publication.
func withIPTablesCandidateProof(ctx context.Context, dataDir string, v *iptablesChangeCheckpoint, publish func() error) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer unlock()
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return err
	}
	defer guard.Close()
	parent, err := loadIPTablesReceipt(dataDir, v.Operation.ID)
	if err != nil || !iptablesChangeReceiptMatches(parent, v) || iptablesRestorePending(dataDir) {
		return errors.New("iptables 原业务或执行回执尚未完整核对")
	}
	current, err := inspectIPTablesChange(ctx, dataDir, v)
	if err != nil {
		return err
	}
	if v.Policy.Action == "apply" {
		if err = checkIPTablesInterfaces(v.Policy.Policy, current.Observed); err != nil {
			return err
		}
	}
	for _, material := range v.Transition.Materials {
		if current.States[material.Family] != "candidate" {
			return errors.New("iptables 候选代际未完整生效")
		}
		if err = iptablesCandidateReceipt(dataDir, v, material.Family); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if time.Now().Unix() >= v.Operation.Deadline {
		return errors.New("iptables 原确认期限已到")
	}
	if publish != nil {
		return publish()
	}
	return nil
}

func (f *hostFirewall) applyIPTablesLocked(ctx context.Context, id, planID string, version int64, hash, action, connection string) (firewall.Operation, error) {
	var out firewall.Operation
	if !f.iptablesPlanning || !f.recovering || f.problem != "" || f.policyUncertain {
		return out, fault.Unavailable("iptables 本机授权或独立恢复尚未就绪")
	}
	if f.activeLocked() || iptablesBusinessPending(f.dataDir) || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) || f.remote.pendingLocked() {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	plan, ok := f.plans[planID]
	if !ok || time.Now().Unix() >= plan.view.ExpiresAt {
		return out, fault.Conflict("iptables 计划不存在或已过期，请重新生成")
	}
	if !plan.view.CanApply || plan.iptables == nil || plan.record == nil || plan.view.Backend != f.owner || plan.view.Version != version || plan.view.PolicyHash != hash || plan.view.Action != action {
		return out, fault.Unavailable("iptables 计划尚不具备完整应用条件")
	}
	if f.remote.state.Version != plan.view.ListenerVersion || f.remote.state.Confirmed.Listen != plan.view.Listener || f.sshMode != plan.view.SSHProfile {
		return out, fault.Conflict("管理监听或 SSH 保护方式变化，请重新计划")
	}
	protections, listeners, source, err := firewallProtections(ctx, iptablesProtectionPolicy(*plan.record), f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	if !sameIPTablesValue(protections, plan.view.Protections) || !slices.Equal(listeners, plan.view.SSHListeners) || source != plan.view.ControlSource {
		return out, fault.Conflict("SSH、控制来源或保护配置变化，请重新计划")
	}
	v, err := f.submitIPTablesPlanLocked(ctx, id, plan, connection)
	if err == nil {
		return v.Operation, nil
	}
	if refreshErr := f.refreshIPTablesStateLocked(); refreshErr != nil {
		if v != nil {
			return v.Operation, errors.Join(err, refreshErr)
		}
		return out, errors.Join(err, refreshErr)
	}
	if current := f.iptablesState; current != nil && current.Operation.ID == id {
		if !iptablesChangeTerminal(current) {
			err = errors.Join(err, f.rollbackIPTablesLocked())
		}
		return f.iptablesState.Operation, err
	}
	if v != nil {
		return v.Operation, err
	}
	return out, err
}

func (f *hostFirewall) submitIPTablesPlanLocked(ctx context.Context, id string, plan firewallPrivatePlan, connection string) (*iptablesChangeCheckpoint, error) {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	v, err := acceptIPTablesChangeLocked(ctx, f.dataDir, id, plan)
	if err != nil {
		return v, err
	}
	f.iptablesState, f.protectionObservedAt = v, time.Time{}
	if f.iptablesLastRescue != "" {
		v.LastRescue = f.iptablesLastRescue
		if err = saveIPTablesChange(f.dataDir, v); err != nil {
			return v, err
		}
	}
	f.deadline = time.Now().Add(time.Until(time.Unix(v.Operation.Deadline, 0)))
	delete(f.plans, plan.view.ID)
	call, cancel := context.WithDeadline(context.Background(), f.deadline)
	defer cancel()
	for index := range v.Transition.Materials {
		step := v.Steps[index*(1+iptablesRestoreAttempts)]
		if _, err = runIPTablesRestore(call, f.dataDir, iptablesRestoreRequest{ID: step.ID, OperationID: id, Target: "candidate"}); err != nil {
			return v, err
		}
	}
	err = withIPTablesCandidateProof(call, f.dataDir, v, func() error {
		v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "waiting_confirmation", "awaiting_new_connection", time.Now().Unix()
		return saveIPTablesChange(f.dataDir, v)
	})
	if err != nil {
		return v, err
	}
	f.remote.stopListening()
	if err = f.remote.reconcile(); err != nil {
		return v, err
	}
	if f.remote.listener == nil || f.remote.web == nil {
		return v, errors.New("iptables 候选生效后管理监听或控制通道不可用")
	}
	f.proofListener = f.remote.listener
	for socketID, socket := range f.remote.connections {
		if socketID != connection {
			shutdownListenerConn(socket.conn)
			delete(f.remote.connections, socketID)
		}
	}
	return v, nil
}

func (f *hostFirewall) confirmIPTablesLocked(ctx context.Context, id, connection string) (*iptablesChangeCheckpoint, error) {
	v := f.iptablesState
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return v, err
	}
	defer unlock()
	if err = f.refreshIPTablesStateLocked(); err != nil {
		return v, err
	}
	v = f.iptablesState
	if v == nil || v.Operation.ID != id {
		return v, fault.Conflict("iptables 原操作已变化")
	}
	if v.Rollback || v.Operation.State != "waiting_confirmation" || f.problem != "" || f.policyUncertain {
		return v, fault.Conflict("iptables 当前操作仅允许继续恢复")
	}
	socket, ok := f.remote.connections[connection]
	if !ok || f.proofListener == nil || socket.listener != f.proofListener || f.remote.listener != f.proofListener || socket.version != f.remote.state.Version || f.remote.web == nil || !validUFWConfirmationSource(socket.source) {
		return v, fault.Conflict("须从非回环地址通过规则生效后新建的 TCP/TLS 连接确认")
	}
	deadline := time.Unix(v.Operation.Deadline, 0)
	if !f.deadline.IsZero() && f.deadline.Before(deadline) {
		deadline = f.deadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	proofRecord := v.Policy
	proofRecord.Action, proofRecord.Policy = "apply", iptablesProtectionPolicy(v.Policy)
	observed := f.observeProtectionsLocked(ctx, &proofRecord)
	if observed.State == "changed" {
		return v, errIPTablesProtectionChanged
	}
	if f.expiredLocked() {
		return v, fault.Conflict("iptables 确认期限已到，请恢复原操作")
	}
	if observed.State != "current" {
		return v, fault.Unavailable(observed.Reason)
	}
	err = withIPTablesCandidateProof(ctx, f.dataDir, v, func() error {
		// The root checkpoint is the persistent direct-mode policy. No global
		// distribution restore file or historical foreign snapshot is installed.
		v.Operation.State, v.Operation.Stage, v.Operation.ConfirmedSource, v.Operation.UpdatedAt = "succeeded", "confirmed", socket.source, time.Now().Unix()
		v.Confirmed = &v.Policy
		if v.Policy.Action == "remove" {
			v.Operation.Stage = "rules_removed"
		}
		return saveIPTablesChange(f.dataDir, v)
	})
	if err == nil {
		f.protectionObservation, f.protectionObservedAt = observed, time.Now()
	}
	return v, err
}

func (f *hostFirewall) rollbackIPTablesLocked() error {
	call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f.proofListener, f.protectionObservedAt = nil, time.Time{}
	return errors.Join(f.recoverIPTablesLocked(call), f.remote.reconcile())
}

func (f *hostFirewall) decideIPTablesLocked(ctx context.Context, id, action, connection string) (firewall.Operation, error) {
	if f.iptablesState == nil || f.iptablesState.Operation.ID != id || iptablesChangeTerminal(f.iptablesState) {
		return f.operationLocked(id)
	}
	if action == "rollback" || f.expiredLocked() {
		err := f.rollbackIPTablesLocked()
		return f.iptablesState.Operation, err
	}
	v, err := f.confirmIPTablesLocked(ctx, id, connection)
	if err != nil {
		if refreshErr := f.refreshIPTablesStateLocked(); refreshErr != nil {
			if v != nil {
				return v.Operation, errors.Join(err, refreshErr)
			}
			return firewall.Operation{}, errors.Join(err, refreshErr)
		}
		if current := f.iptablesState; current != nil && current.Operation.ID == id {
			if current.Operation.State == "succeeded" {
				f.problem = "iptables 确认回执尚未发布完成"
			} else if f.expiredLocked() || errors.Is(err, errIPTablesProtectionChanged) {
				err = errors.Join(err, f.rollbackIPTablesLocked())
			}
			return f.iptablesState.Operation, err
		}
		return firewall.Operation{}, err
	}
	f.proofListener, f.problem, f.policyUncertain = nil, "", false
	return v.Operation, nil
}
