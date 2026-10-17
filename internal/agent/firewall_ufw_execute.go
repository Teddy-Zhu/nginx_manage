package agent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

var errUFWProtectionChanged = fault.Conflict("UFW 保护依据已变化，请恢复原操作")

func (f *hostFirewall) checkUFWEnvironment(ctx context.Context, ipv6 bool, backend string) (firewall.Observation, error) {
	return checkUFWEnvironment(ctx, f.dataDir, ipv6, backend)
}

func checkUFWEnvironment(ctx context.Context, dataDir string, ipv6 bool, backend string) (firewall.Observation, error) {
	observed := (&firewallObserver{ctx: ctx, scope: "host", dataDir: dataDir}).collect(ctx)
	if !observed.Available || observed.Scope != "host" || observed.Manager != "ufw" || observed.Backend != backend || observed.UFW.Active == nil || !*observed.UFW.Active || observed.UFW.Enabled == nil || !*observed.UFW.Enabled || observed.UFW.IPv6 == nil || *observed.UFW.IPv6 != ipv6 || !observed.UFW.RuleInventory.Available || len(observed.Rulesets) != 5 {
		return observed, fault.Unavailable("UFW 管理器、启用状态、地址族或内核后端已变化，保持只读")
	}
	for _, rules := range observed.Rulesets {
		if !rules.Available {
			return observed, fault.Unavailable("UFW 内核后端视图无法完整核对")
		}
	}
	return observed, nil
}

// All three locks remain held through publication. A process exit alone never
// advances the business operation; every family and persistent inode is read.
func withUFWCandidateProof(ctx context.Context, dataDir string, v *ufwChangeCheckpoint, fileTarget string, publish func() error) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer unlock()
	manager, err := lockUFWManager()
	if err != nil {
		return err
	}
	defer manager.Close()
	parent, err := loadUFWReceipt(dataDir, v.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(parent, v) || ufwRestoreProcessPending(dataDir) {
		return errors.New("UFW 原业务回执或子进程尚未完成核对")
	}
	if err = checkUFWChangeSources(ctx, dataDir, v); err != nil {
		return err
	}
	if err = checkUFWPersistentFiles(ctx, v, fileTarget); err != nil {
		return err
	}
	for _, material := range v.Transition.Materials {
		image, err := readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
		if err != nil || !sameUFWReloadImage(image, material.AfterKernel) {
			return errors.New("UFW 完整地址族的业务内核状态未核对")
		}
	}
	if err = verifyUFWManagerLock(manager); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if time.Now().Unix() >= v.Operation.Deadline {
		return errors.New("UFW 原确认期限已到，禁止推进候选状态")
	}
	if publish != nil {
		return publish()
	}
	return nil
}

func (f *hostFirewall) applyUFWLocked(ctx context.Context, id, planID string, version int64, hash, action, connection string) (firewall.Operation, error) {
	var out firewall.Operation
	if err := forbidIPTablesRegistration(f.dataDir); err != nil {
		return out, fault.Conflict(err.Error())
	}
	if !f.ufwPlanning || f.problem != "" || f.policyUncertain || !f.recovering {
		return out, fault.Unavailable("UFW 本机授权或独立恢复尚未就绪")
	}
	if f.ufwPreparingLocked() || f.activeLocked() || ufwRestorePending(f.dataDir) || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	plan, ok := f.plans[planID]
	if !ok || time.Now().Unix() >= plan.view.ExpiresAt {
		return out, fault.Conflict("UFW 计划不存在或已过期，请重新生成")
	}
	if !plan.view.CanApply || plan.ufw == nil || plan.record == nil || plan.view.Backend != "ufw" || plan.view.Version != version || plan.view.PolicyHash != hash || plan.view.Action != action {
		return out, fault.Unavailable("UFW 计划尚不具备完整应用条件")
	}
	if f.remote.state.Version != plan.view.ListenerVersion || f.remote.state.Confirmed.Listen != plan.view.Listener || f.sshMode != plan.view.SSHProfile {
		return out, fault.Conflict("管理监听或 SSH 保护方式变化，请重新计划")
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
	observed, err := f.checkUFWEnvironment(ctx, plan.ufw.IPv6, plan.ufw.Reload.Backend)
	if err != nil {
		return out, err
	}
	for _, rule := range effect.Rules {
		if rule.Enabled && rule.Interface != "" && !slices.Contains(observed.Interfaces, rule.Interface) {
			return out, fault.Conflict("目标网络接口已变化，请重新计划")
		}
	}
	v, err := f.submitUFWPlanLocked(ctx, id, plan, connection)
	if err == nil {
		return v.Operation, nil
	}
	if v == nil {
		return out, err
	}
	if readErr := f.refreshUFWStateLocked(); readErr != nil {
		return v.Operation, errors.Join(err, readErr)
	}
	if f.ufwState != nil && f.ufwState.Operation.ID == id {
		err = errors.Join(err, f.rollbackUFWLocked())
		return f.ufwState.Operation, err
	}
	return out, err
}

func (f *hostFirewall) submitUFWPlanLocked(ctx context.Context, id string, plan firewallPrivatePlan, connection string) (*ufwChangeCheckpoint, error) {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	v, err := acceptUFWChangeLocked(ctx, f.dataDir, id, plan)
	if err != nil {
		return v, err
	}
	f.ufwState, f.protectionObservedAt = v, time.Time{}
	if f.ufwLastRescue != "" && v.LastRescue != f.ufwLastRescue {
		v.LastRescue = f.ufwLastRescue
		if err = saveUFWChange(f.dataDir, v); err != nil {
			return v, err
		}
	}
	f.deadline = time.Now().Add(time.Until(time.Unix(v.Operation.Deadline, 0)))
	delete(f.plans, plan.view.ID)
	// Admission survives caller cancellation. The original root deadline still
	// bounds submission, and the independent loop handles control-channel loss.
	call, cancel := context.WithDeadline(context.Background(), f.deadline)
	defer cancel()
	for index, material := range v.Transition.Materials {
		if sameUFWReloadImage(material.BeforeKernel, material.AfterKernel) {
			continue
		}
		if _, err = runUFWRestore(call, f.dataDir, ufwRestoreRequest{ID: v.Steps[index*2].ID, OperationID: id, Target: "candidate"}); err != nil {
			return v, err
		}
	}
	err = withUFWCandidateProof(call, f.dataDir, v, "previous", func() error {
		v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "waiting_confirmation", "awaiting_new_connection", time.Now().Unix()
		return saveUFWChange(f.dataDir, v)
	})
	if err != nil {
		return v, err
	}
	f.remote.stopListening()
	if err = f.remote.reconcile(); err != nil {
		return v, err
	}
	if f.remote.listener == nil || f.remote.web == nil {
		return v, errors.New("UFW 候选生效后管理监听或控制通道不可用")
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

func (f *hostFirewall) decideUFWLocked(ctx context.Context, id, action, connection string) (firewall.Operation, error) {
	v := f.ufwState
	if v == nil || v.Operation.ID != id || ufwChangeTerminal(v) {
		return f.operationLocked(id)
	}
	if action == "rollback" || f.expiredLocked() {
		err := f.rollbackUFWLocked()
		return f.ufwState.Operation, err
	}
	v, err := f.confirmUFWLocked(ctx, id, connection)
	if err != nil {
		if refreshErr := f.refreshUFWStateLocked(); refreshErr != nil {
			return v.Operation, errors.Join(err, refreshErr)
		}
		if current := f.ufwState; current != nil && current.Operation.ID == id {
			if current.Operation.Stage == "persisting_confirmed" || v.Operation.Stage == "persisting_confirmed" || f.expiredLocked() || errors.Is(err, errUFWProtectionChanged) {
				err = errors.Join(err, f.rollbackUFWLocked())
			} else if current.Operation.State == "succeeded" {
				f.problem = ufwProcessProblem + "确认回执尚未发布完成"
			}
			return f.ufwState.Operation, err
		}
		return v.Operation, err
	}
	f.proofListener, f.problem, f.policyUncertain = nil, "", false
	return v.Operation, nil
}

func (f *hostFirewall) confirmUFWLocked(ctx context.Context, id, connection string) (*ufwChangeCheckpoint, error) {
	v := f.ufwState
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return v, err
	}
	defer unlock()
	if err = f.refreshUFWStateLocked(); err != nil {
		return v, err
	}
	current := f.ufwState
	if current == nil || current.Operation.ID != id {
		return v, fault.Conflict("UFW 原业务操作已变化")
	}
	v = current
	if v.Rollback || v.Operation.State != "waiting_confirmation" || f.problem != "" || f.policyUncertain {
		return v, fault.Conflict("UFW 当前操作仅允许继续恢复")
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
	observed := f.observeProtectionsLocked(ctx, &v.Policy)
	if observed.State == "changed" {
		return v, errUFWProtectionChanged
	}
	if f.expiredLocked() {
		return v, fault.Conflict("UFW 确认期限已到，请恢复原操作")
	}
	if observed.State == "unavailable" {
		return v, fault.Unavailable(observed.Reason)
	}
	if _, err = f.checkUFWEnvironment(ctx, v.Transition.IPv6, v.Transition.Reload.Backend); err != nil {
		return v, err
	}
	err = withUFWCandidateProof(ctx, f.dataDir, v, "previous", func() error {
		v.Operation.State, v.Operation.Stage, v.Operation.ConfirmedSource, v.Operation.UpdatedAt = "running", "persisting_confirmed", socket.source, time.Now().Unix()
		return saveUFWChange(f.dataDir, v)
	})
	if err != nil {
		return v, err
	}
	if err = persistUFWFilesLocked(ctx, f.dataDir, v, "candidate"); err != nil {
		return v, err
	}
	err = withUFWCandidateProof(ctx, f.dataDir, v, "candidate", func() error {
		v.Operation.State, v.Operation.Stage, v.Operation.Error, v.Operation.UpdatedAt = "succeeded", "confirmed", "", time.Now().Unix()
		if v.Policy.Action == "remove" {
			v.Operation.Stage = "rules_removed"
		}
		v.Confirmed = &v.Policy
		return saveUFWChange(f.dataDir, v)
	})
	if err != nil {
		// Re-read the durable checkpoint before choosing compensation. A saved
		// confirmation with a missing journal reply must never be reopened.
		return v, err
	}
	f.protectionObservation, f.protectionObservedAt = observed, time.Now()
	return v, nil
}
