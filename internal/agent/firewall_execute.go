package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

func firewallRequestHash(planID, action string) string {
	return secure.Hash([]byte("firewall.change:v2:" + action + ":" + planID))
}
func (f *hostFirewall) checkManagers(ctx context.Context) error {
	observer := firewallObserver{scope: "host", ctx: ctx, dataDir: f.dataDir}
	return checkFirewallManagers(observer.collect(ctx))
}
func checkFirewallManagers(observed firewall.Observation) error {
	if !observed.Available || observed.Manager != "direct-candidate" || observed.Backend == "legacy" || observed.Backend == "mixed" {
		return fault.Unavailable("无法排除既有管理器或混合后端，保持只读")
	}
	nft := false
	for _, r := range observed.Rulesets {
		if r.ID == "nftables" && r.Available {
			nft = true
		}
		if r.ID != "nftables" && !r.Available {
			return fault.Unavailable("后端规则读取不完整，不能执行")
		}
	}
	if !nft {
		return fault.Unavailable("nftables 结构视图无法完整读取")
	}
	return nil
}
func (f *hostFirewall) Apply(ctx context.Context, id, planID string, version int64, policyHash, action, connection string) (firewall.Operation, error) {
	f.dns.mu.Lock()
	defer f.dns.mu.Unlock()
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out firewall.Operation
	if !validID(id) || !validID(planID) || (action != "apply" && action != "remove") {
		return out, fault.Invalid("防火墙操作或计划 ID 无效")
	}
	if f.owner == "ufw" && f.state.Schema == 0 {
		if err := f.refreshUFWStateLocked(); err != nil {
			return out, fault.Unavailable("UFW 独立业务记录无法读取")
		}
	}
	hash := firewallRequestHash(planID, action)
	if old := f.currentOperation(); old != nil && old.ID == id {
		if firewallRequestHash(old.PlanID, old.Action) != hash || old.Version != version || old.PolicyHash != policyHash || old.Action != action {
			return out, fault.Conflict("幂等键已用于其他请求")
		}
		return f.operationLocked(id)
	}
	if old, err := f.journal.Get(id); err == nil {
		if old.Kind != firewallOperationKind || old.RequestHash != hash || old.Firewall == nil || old.Firewall.Version != version || old.Firewall.PolicyHash != policyHash || old.Firewall.Action != action {
			return out, fault.Conflict("幂等键已用于其他请求")
		}
		return *old.Firewall, nil
	} else if !os.IsNotExist(err) {
		return out, err
	}
	if f.owner == "firewalld" {
		return f.applyFirewalldLocked(ctx, id, planID, version, policyHash, action, connection)
	}
	if f.owner == "ufw" && f.state.Schema == 0 {
		return f.applyUFWLocked(ctx, id, planID, version, policyHash, action, connection)
	}
	if f.iptablesPlannerLocked() {
		return out, fault.Unavailable("iptables 计划尚未完成官方预演、子进程回执与业务恢复，不能应用")
	}
	if !f.available || f.problem != "" || f.state.Schema != firewallRuntimeSchema {
		return out, fault.Unavailable("防火墙执行未就绪")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成可达性变更")
	}
	plan, ok := f.plans[planID]
	if !ok || time.Now().Unix() >= plan.view.ExpiresAt {
		return out, fault.Conflict("计划不存在或已过期，请重新生成")
	}
	if plan.view.Version != version || plan.view.PolicyHash != policyHash || plan.view.Action != action {
		return out, fault.Conflict("已保存策略与计划不一致，请重新生成")
	}
	if !plan.view.CanApply || plan.record == nil {
		return out, fault.Unavailable("该计划仅供核对，尚不能应用")
	}
	if action == "remove" && (f.state.Confirmed == nil || f.state.Confirmed.Action != "apply" || f.state.Confirmed.Version != version || f.state.Confirmed.PolicyHash != policyHash) {
		return out, fault.Conflict("待移除的已确认策略已变化，请重新生成计划")
	}
	if f.remote.state.Version != plan.view.ListenerVersion || f.remote.state.Confirmed.Listen != plan.view.Listener {
		return out, fault.Conflict("管理监听已变化，请重新生成计划")
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
	if !bytes.Equal(actual, expected) {
		return out, fault.Conflict("SSH、控制来源或保护配置变化，请重新生成计划")
	}
	for _, rule := range effect.Rules {
		if rule.Enabled && rule.Interface != "" {
			if _, err := net.InterfaceByName(rule.Interface); err != nil {
				return out, fault.Conflict("目标网络接口已变化")
			}
		}
	}
	if err = f.checkManagers(ctx); err != nil {
		return out, err
	}
	current, err := f.snapshot(f.state.Confirmed)
	if err != nil {
		return out, fault.Unavailable("无法证明原受管对象")
	}
	if !current.TableExists || current.NamespaceID != plan.view.Baseline.NamespaceID || current.Fingerprint != plan.view.Baseline.Fingerprint || current.Generation != plan.view.Baseline.Generation {
		return out, fault.Conflict("内核基线已变化，请重新生成计划")
	}
	program, marker, err := f.program(plan.record)
	if err != nil {
		return out, err
	}
	batch, err := firewall.PrepareNFTManaged(program, current, marker)
	if err != nil {
		return out, err
	}
	if batch.Hash != plan.view.TransactionHash {
		return out, fault.Conflict("事务摘要变化，请重新生成计划")
	}
	op := &firewall.Operation{Action: action, ID: id, PlanID: planID, Version: plan.record.Version, PolicyHash: plan.record.PolicyHash, ProgramHash: plan.record.ProgramHash, State: "running", Stage: "submitting", Deadline: time.Now().Unix() + firewall.ConfirmationSeconds, VerificationScope: "controlled-listener"}
	candidate := *plan.record
	candidate.OperationID = id
	f.state.Operation, f.state.RequestHash, f.state.Candidate = op, hash, &candidate
	f.protectionObservedAt = time.Time{}
	f.state.BeforeKernel, f.state.CandidateKernel, f.state.Rollback = current, firewall.KernelView{}, false
	f.deadline = time.Now().Add(firewall.ConfirmationSeconds * time.Second)
	if err = f.save(); err != nil {
		f.state.Rollback = true
		return *op, err
	}
	delete(f.plans, planID)
	call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	namespace, err := nftNamespace()
	if err == nil && namespace != current.NamespaceID {
		err = errors.New("提交前命名空间变化")
	}
	if err == nil {
		err = submitNFTBatch(call, batch.Wire)
	}
	cancel()
	post, postErr := f.snapshot(f.state.Candidate)
	generation := current.Generation + 1
	if generation == 0 {
		generation = 1
	}
	if err != nil || postErr != nil || !post.TableExists || post.NamespaceID != current.NamespaceID || post.Generation != generation {
		rollbackErr := f.rollbackLocked("候选提交结果未能完整证明，恢复最后确认策略")
		return *f.state.Operation, rollbackErr
	}
	f.state.CandidateKernel, f.state.CurrentKernel = post, post
	op.State, op.Stage, op.UpdatedAt = "waiting_confirmation", "awaiting_new_connection", time.Now().Unix()
	if err = f.save(); err != nil {
		_ = f.rollbackLocked("候选回执无法保存，恢复最后确认策略")
		return *f.state.Operation, err
	}
	// Closing the old listening descriptor discards both accepted-old and queued
	// pre-change handshakes. A fresh listener is opened only after kernel proof.
	f.remote.stopListening()
	if err = f.remote.reconcile(); err != nil {
		rollbackErr := f.rollbackLocked("无法建立新的确认监听，恢复最后确认策略")
		_ = f.remote.reconcile()
		return *f.state.Operation, errors.Join(err, rollbackErr)
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

func (f *hostFirewall) Decide(ctx context.Context, id, action, connection string) (firewall.Operation, error) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	out, err := f.operationLocked(id)
	if err != nil {
		return out, err
	}
	if action != "confirm" && action != "rollback" {
		return out, fault.Invalid("防火墙决定无效")
	}
	if f.firewalldState != nil {
		return f.decideFirewalldLocked(ctx, id, action, connection)
	}
	if f.owner == "ufw" && f.state.Schema == 0 {
		return f.decideUFWLocked(ctx, id, action, connection)
	}
	if !f.activeLocked() || f.state.Operation.ID != id {
		return out, nil
	}
	if action == "rollback" || f.expiredLocked() {
		err = f.rollbackLocked("已请求恢复或确认期限已到")
		return *f.state.Operation, err
	}
	if f.state.Rollback || out.State != "waiting_confirmation" || f.problem != "" {
		return out, fault.Conflict("当前操作仅允许继续恢复")
	}
	socket, ok := f.remote.connections[connection]
	if !ok || f.proofListener == nil || socket.listener != f.proofListener || f.remote.listener != f.proofListener || socket.version != f.remote.state.Version || f.remote.web == nil {
		return out, fault.Conflict("须通过规则生效后新建的 TCP/TLS 连接确认")
	}
	peer := net.ParseIP(socket.source)
	if peer == nil || peer.IsLoopback() || peer.IsUnspecified() {
		return out, fault.Conflict("须从非回环的目标管理连接确认")
	}
	deadline := time.Unix(f.state.Operation.Deadline, 0)
	if !f.deadline.IsZero() && f.deadline.Before(deadline) {
		deadline = f.deadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	observed := f.observeProtectionsLocked(ctx, f.state.Candidate)
	if f.expiredLocked() {
		err = f.rollbackLocked("确认核对期间期限已到，恢复最后确认策略")
		return *f.state.Operation, err
	}
	if observed.State == "changed" {
		err = f.rollbackLocked("保护依据已变化，恢复最后确认策略；请重新计划")
		return *f.state.Operation, err
	}
	if observed.State == "unavailable" {
		return out, fault.Unavailable(observed.Reason)
	}
	current, err := f.snapshotContext(ctx, f.state.Candidate)
	if err != nil || !current.TableExists || current.NamespaceID != f.state.CandidateKernel.NamespaceID || current.Fingerprint != f.state.CandidateKernel.Fingerprint {
		return out, fault.Conflict("候选内核对象变化，禁止确认")
	}
	if f.expiredLocked() {
		err = f.rollbackLocked("确认期限已到，恢复最后确认策略")
		return *f.state.Operation, err
	}
	before := f.state
	confirmed := out
	confirmed.UpdatedAt = time.Now().Unix()
	confirmed.State, confirmed.Stage, confirmed.ConfirmedSource, confirmed.Error = "succeeded", "confirmed", socket.source, ""
	if confirmed.Action == "remove" {
		confirmed.Stage = "rules_removed"
	}
	f.state.Confirmed, f.state.Candidate, f.state.Operation, f.state.CurrentKernel = f.state.Candidate, nil, &confirmed, current
	f.state.BeforeKernel, f.state.CandidateKernel, f.state.Rollback = firewall.KernelView{}, firewall.KernelView{}, false
	written, err := f.persist()
	if err != nil {
		if !written {
			f.state = before
		}
		return *f.state.Operation, err
	}
	f.proofListener = nil
	f.problem = ""
	f.protectionObservation, f.protectionObservedAt = observed, time.Now()
	return confirmed, nil
}
func (f *hostFirewall) expiredLocked() bool {
	op := f.currentOperation()
	return f.activeLocked() && op != nil && (time.Now().Unix() >= op.Deadline || !f.deadline.IsZero() && !time.Now().Before(f.deadline))
}

func (f *hostFirewall) rollbackLocked(reason string) error {
	if !f.activeLocked() {
		return nil
	}
	op := *f.state.Operation
	op.UpdatedAt = time.Now().Unix()
	op.State, op.Stage, op.Error = "compensating", "restoring_confirmed", reason
	f.state.Operation, f.state.Rollback = &op, true
	if err := f.save(); err != nil {
		return err
	}
	// Prefer the last confirmed object. A missing candidate or a lost ACK never
	// causes blind resubmission, and unrelated tables are never restored/flushed.
	current, oldErr := f.snapshot(f.state.Confirmed)
	if oldErr == nil && current.TableExists {
		// The durable rollback direction authorizes reconciliation of the complete
		// original program, including a prior restore whose final receipt was lost.
		return f.finishRollbackLocked(current, reason)
	}
	candidate, candidateErr := f.snapshot(f.state.Candidate)
	if candidateErr != nil {
		return f.recoveryFailedLocked("候选与原受管对象均无法完整核对，保留恢复材料")
	}
	if candidate.TableExists && f.state.CandidateKernel.Available && candidate.NamespaceID == f.state.CandidateKernel.NamespaceID && candidate.Fingerprint != f.state.CandidateKernel.Fingerprint {
		return f.recoveryFailedLocked("候选受管对象身份变化，禁止覆盖")
	}
	target, marker, err := f.program(f.state.Confirmed)
	if err != nil {
		return f.recoveryFailedLocked("已确认策略无法重新编译")
	}
	// Store the checked submission baseline before each compensating transaction.
	// A retry first proves the complete current candidate/absence and generation.
	f.state.CurrentKernel = candidate
	if err = f.save(); err != nil {
		return err
	}
	batch, err := firewall.PrepareNFTManaged(target, candidate, marker)
	if err != nil {
		return f.recoveryFailedLocked("恢复事务无法生成")
	}
	call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	namespace, submitErr := nftNamespace()
	if submitErr == nil && namespace != candidate.NamespaceID {
		submitErr = errors.New("恢复前命名空间变化")
	}
	if submitErr == nil {
		submitErr = submitNFTBatch(call, batch.Wire)
	}
	cancel()
	restored, err := f.snapshot(f.state.Confirmed)
	if err != nil || !restored.TableExists || restored.NamespaceID != candidate.NamespaceID {
		return f.recoveryFailedLocked("恢复提交尚未核对完成")
	}
	// Full semantic proof with the original durable intent reconciles a lost
	// rollback ACK. An unrelated generation change alone is not ownership drift.
	_ = submitErr
	return f.finishRollbackLocked(restored, reason)
}
func (f *hostFirewall) finishRollbackLocked(kernel firewall.KernelView, reason string) error {
	op := *f.state.Operation
	op.UpdatedAt = time.Now().Unix()
	op.State, op.Stage, op.Error = "rolled_back", "confirmed_restored", reason
	f.state.Candidate, f.state.Operation, f.state.CurrentKernel, f.state.Rollback = nil, &op, kernel, false
	f.state.CandidateKernel = firewall.KernelView{}
	f.proofListener = nil
	if err := f.save(); err != nil {
		return err
	}
	f.problem = ""
	return nil
}
func (f *hostFirewall) recoveryFailedLocked(reason string) error {
	op := *f.state.Operation
	op.UpdatedAt = time.Now().Unix()
	op.State, op.Stage, op.Error = "recovery_required", "restore_unproven", reason
	f.state.Operation = &op
	f.problem = reason
	f.retryAt = time.Now().Add(10 * time.Second)
	if err := f.save(); err != nil {
		return err
	}
	return fault.Unavailable(reason)
}

func (f *hostFirewall) reconcileConfirmedLocked() error {
	if f.state.Schema != firewallRuntimeSchema {
		return nil
	}
	current, err := f.snapshot(f.state.Confirmed)
	if err != nil {
		return err
	}
	if current.TableExists {
		if f.state.Operation == nil && (current.NamespaceID != f.state.CurrentKernel.NamespaceID || current.Fingerprint != f.state.CurrentKernel.Fingerprint) {
			return errors.New("初始空表登记身份变化，须本机核对")
		}
		if f.state.RestoreIntent == nil && current.NamespaceID == f.state.CurrentKernel.NamespaceID && current.Fingerprint != f.state.CurrentKernel.Fingerprint {
			return errors.New("受管对象身份变化")
		}
		changed := current.NamespaceID != f.state.CurrentKernel.NamespaceID || current.Fingerprint != f.state.CurrentKernel.Fingerprint || f.state.RestoreIntent != nil || f.problem != ""
		f.state.CurrentKernel = current
		f.state.RestoreIntent = nil
		if changed && f.state.Operation != nil {
			if err = f.save(); err != nil {
				return err
			}
		}
		f.problem = ""
		return nil
	}
	// Only the durable confirmed policy is restored after disappearance/reboot.
	// An empty initial registration is not automatically recreated without a
	// previously accepted runtime operation.
	if f.state.Operation == nil {
		return errors.New("空表登记缺失，须停止 Agent 后由 root 重新登记")
	}
	target, marker, err := f.program(f.state.Confirmed)
	if err != nil {
		return err
	}
	batch, err := firewall.PrepareNFTManaged(target, current, marker)
	if err != nil {
		return err
	}
	baseline := current
	f.state.RestoreIntent = &baseline
	if err = f.save(); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	namespace, submitErr := nftNamespace()
	if submitErr == nil && namespace != current.NamespaceID {
		submitErr = errors.New("恢复前命名空间变化")
	}
	if submitErr == nil {
		submitErr = submitNFTBatch(call, batch.Wire)
	}
	cancel()
	restored, err := f.snapshot(f.state.Confirmed)
	if err != nil || !restored.TableExists || restored.NamespaceID != current.NamespaceID {
		return errors.Join(errors.New("已确认策略恢复未核对"), err, submitErr)
	}
	f.state.CurrentKernel = restored
	f.state.RestoreIntent = nil
	if err = f.save(); err != nil {
		return err
	}
	f.problem = ""
	return nil
}

func RequestFirewallRollback(dataDir string) error {
	if os.Geteuid() != 0 {
		return errors.New("防火墙救援需要本机 root")
	}
	dir := filepath.Dir(firewallStatePath(dataDir))
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	return rootJSONWrite(filepath.Join(dir, "rescue.json"), struct {
		ID string `json:"id"`
	}{secure.ID()}, 1024)
}
func (f *hostFirewall) rescueLocked() error {
	raw, err := listenerRead(filepath.Join(filepath.Dir(firewallStatePath(f.dataDir)), "rescue.json"), 1024)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var request struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &request) != nil || !validID(request.ID) {
		return errors.New("防火墙救援请求无效")
	}
	if request.ID == f.state.LastRescue {
		return nil
	}
	if err = f.rollbackLocked("本机 root 已请求恢复最后确认策略"); err != nil {
		return err
	}
	f.state.LastRescue = request.ID
	if f.state.Operation == nil {
		return nil
	}
	return f.save()
}
func (f *hostFirewall) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextInspect := time.Now().Add(30 * time.Second)
	nextProtectionInspect := time.Now()
	for {
		stopping := false
		select {
		case <-ctx.Done():
			stopping = true
		case <-ticker.C:
		}
		f.remote.mu.Lock()
		f.mu.Lock()
		if f.owner == "ufw" && f.firewalldState == nil && f.state.Schema == 0 {
			f.runUFWLocked(ctx, stopping, &nextInspect, &nextProtectionInspect)
		}
		if f.firewalldState != nil {
			f.runFirewalldLocked(ctx, stopping, &nextInspect, &nextProtectionInspect)
		}
		if f.state.Schema == firewallRuntimeSchema {
			if err := f.rescueLocked(); err != nil {
				f.problem = "本机防火墙救援请求未处理完成"
			}
			if f.activeLocked() && (stopping || f.expiredLocked() || f.state.Rollback || f.problem != "" || f.remote.web == nil || f.remote.problem != "" || f.remote.listener == nil) {
				if stopping || !time.Now().Before(f.retryAt) {
					if err := f.rollbackLocked("未确认、控制通道中断或 Agent 停止，恢复最后确认策略"); err != nil {
						f.retryAt = time.Now().Add(10 * time.Second)
					}
				}
			} else if !f.activeLocked() && f.recovering && !time.Now().Before(nextInspect) {
				nextInspect = time.Now().Add(30 * time.Second)
				if err := f.reconcileConfirmedLocked(); err != nil {
					f.problem = "已确认防火墙对象无法核对或恢复"
				}
			}
			if !stopping && !f.activeLocked() && f.problem == "" && !time.Now().Before(nextProtectionInspect) {
				f.protectionObservation = f.observeProtectionsLocked(ctx, f.state.Confirmed)
				f.protectionObservedAt = time.Now()
				nextProtectionInspect = time.Now().Add(30 * time.Second)
			}
		}
		f.mu.Unlock()
		f.remote.mu.Unlock()
		if stopping {
			return
		}
	}
}
