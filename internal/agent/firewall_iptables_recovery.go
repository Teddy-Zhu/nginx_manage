package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
)

// A restart never resumes an unconfirmed candidate. Only the original parent's
// inverse batches may run, after its original child is proven to have ended.
func recoverIPTablesChange(ctx context.Context, dataDir string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return errors.New("iptables 业务恢复须在真实宿主机 root 范围执行")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	v, err := loadIPTablesChange(dataDir)
	if err != nil {
		return err
	}
	if v == nil {
		if iptablesRestorePending(dataDir) {
			return errors.New("iptables 子进程缺少原业务快照，请本机核对")
		}
		return nil
	}
	if iptablesChangeTerminal(v) {
		if iptablesRestorePending(dataDir) {
			child, err := loadIPTablesRestore(dataDir)
			matched := err == nil && child != nil && child.Phase == "ended" && iptablesRestoreMatchesChange(child, v)
			if err == nil && child != nil && child.Target == "repair" {
				repair, repairErr := loadIPTablesRepair(dataDir)
				matched = repairErr == nil && repair != nil && iptablesPolicySourceMatches(repair, v) && iptablesRestoreMatchesRepair(child, repair)
			}
			if !matched {
				return errors.New("iptables 终态仍有未核对原子进程")
			}
			if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
				return err
			}
		}
		if receipt, err := loadIPTablesReceipt(dataDir, v.Operation.ID); err == nil && iptablesChangeReceiptMatches(receipt, v) {
			return nil
		}
		return saveIPTablesChange(dataDir, v)
	}
	fail := func(reason string) error {
		v.Rollback = true
		v.Operation.State, v.Operation.Stage, v.Operation.Error = "recovery_required", "restore_unproven", reason
		v.Operation.UpdatedAt = time.Now().Unix()
		return errors.Join(errors.New(reason), saveIPTablesChange(dataDir, v))
	}
	// Repair a checkpoint-first publication gap before any write. Contradictory
	// terminal audit records are rejected by save, never reopened for recovery.
	if err = saveIPTablesChange(dataDir, v); err != nil {
		return err
	}
	if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
		return fail("iptables 原执行进程尚未完整结束或回执冲突")
	}
	if iptablesRepairPending(dataDir) {
		repair, err := loadIPTablesRepair(dataDir)
		if err != nil || repair == nil || !iptablesPolicySourceMatches(repair, v) {
			return fail("iptables 原确认规则修复与当前业务冲突，请本机核对")
		}
	}
	if err = iptablesChangeAuthority(dataDir, v); err != nil {
		return fail("iptables 原本机授权或机器身份无法核对")
	}
	v.Rollback = true
	v.Operation.State, v.Operation.Stage, v.Operation.Error = "compensating", "restoring_previous", "未确认操作恢复原确认受管范围"
	v.Operation.UpdatedAt = time.Now().Unix()
	if err = saveIPTablesChange(dataDir, v); err != nil {
		return err
	}
	for _, material := range v.Transition.Materials {
		current, err := inspectIPTablesChangeScope(ctx, dataDir, v, true)
		if err != nil {
			return fail("iptables 当前工具、管理器或完整规则无法核对：" + boundedIPTablesError(err))
		}
		state := current.States[material.Family]
		if state == "previous" || state == "previous_missing" {
			continue
		}
		// Missing old rules after a removal/reboot are restored from the
		// independent original confirmation, not attributed to an unproven call.
		if state == "candidate" && iptablesGeneration(v.Transition.Program, material.Family) == nil && dockerIPTablesGeneration(v.Transition.Docker, material.Family) == nil {
			continue
		}
		if current.States[material.Family] != "candidate" || iptablesCandidateReceipt(dataDir, v, material.Family) != nil {
			return fail("iptables 当前代际规则无法关联原候选调用")
		}
		var next *iptablesChangeStep
		for index := range v.Steps {
			step := &v.Steps[index]
			if step.Family != material.Family || step.Target != "previous" {
				continue
			}
			old, err := loadIPTablesReceipt(dataDir, step.ID)
			if os.IsNotExist(err) {
				next = step
				break
			}
			if err != nil || !iptablesRestoreRecordMatches(old, old.IPTablesRestore) || !iptablesRestoreMatchesChange(old.IPTablesRestore, v) || old.IPTablesRestore.Phase != "ended" {
				return fail("iptables 原补偿调用回执无法核对")
			}
			if iptablesRestoreResult(old.IPTablesRestore) == nil {
				return fail("iptables 成功补偿后原代际规则再次出现，禁止自动覆盖")
			}
		}
		if next == nil {
			return fail("iptables 原操作补偿许可已耗尽，请本机核对")
		}
		_, submitErr := runIPTablesRestore(ctx, dataDir, iptablesRestoreRequest{ID: next.ID, OperationID: v.Operation.ID, Target: "previous"})
		// A lost/failed native ACK is not a rollback proof. Inspect only after
		// ending the original process; a later retry uses another frozen ID.
		if err = recoverIPTablesRestore(ctx, dataDir); err != nil {
			return fail("iptables 补偿原进程尚未结束或回执未核对")
		}
		after, err := inspectIPTablesChangeScope(ctx, dataDir, v, true)
		if err != nil || after.States[material.Family] != "previous" {
			if submitErr != nil {
				return fail("iptables 原补偿调用未完成，保留原操作待核对")
			}
			return fail("iptables 补偿后原确认受管范围无法核对")
		}
	}
	if err = reconcileIPTablesConfirmedLocked(ctx, dataDir, v); err != nil {
		return fail("iptables 原确认策略尚未完整恢复：" + boundedIPTablesError(err))
	}
	// Hold both registry and execution guard through the final observation and
	// terminal publication. No delayed restore may run after rolled_back.
	registrationUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return fail("iptables 最终授权锁暂不可用")
	}
	defer registrationUnlock()
	guard, err := openIPTablesExecutionLock()
	if err != nil {
		return fail("iptables 原执行锁尚未释放")
	}
	defer guard.Close()
	final, err := inspectIPTablesChange(ctx, dataDir, v)
	if err != nil || iptablesRestorePending(dataDir) {
		return fail("iptables 最终环境或执行回执无法核对")
	}
	for _, material := range v.Transition.Materials {
		if final.States[material.Family] != "previous" {
			return fail("iptables 最终原确认范围无法核对")
		}
	}
	v.Operation.State, v.Operation.Stage, v.Operation.Error = "rolled_back", "confirmed_restored", "原确认受管范围已恢复；保留当前第三方规则"
	v.Operation.UpdatedAt = time.Now().Unix()
	return saveIPTablesChange(dataDir, v)
}

func boundedIPTablesError(err error) string {
	text := err.Error()
	if len(text) > 256 {
		return "原工具、环境或规则核对失败"
	}
	return text
}

func (f *hostFirewall) refreshIPTablesStateLocked() error {
	v, err := loadIPTablesChange(f.dataDir)
	if err != nil || v == nil && f.iptablesState != nil {
		if err == nil {
			retirement, retireErr := loadIPTablesRetirement(f.dataDir, f.iptablesState.Operation.ID)
			if retireErr == nil && retirement != nil && iptablesChangeIntentHash(&retirement.Business) == iptablesChangeIntentHash(f.iptablesState) {
				record, _, recordErr := retirement.record(f.dataDir)
				if recordErr == nil && record.State == "succeeded" {
					f.iptablesState, f.proofListener, f.deadline = nil, nil, time.Time{}
					return nil
				}
			}
		}
		if err == nil {
			err = errors.New("iptables 原业务快照丢失，请本机核对")
		}
		return err
	}
	f.iptablesState = v
	if v != nil {
		f.iptablesLastRescue = v.LastRescue
	}
	return nil
}

func (f *hostFirewall) recoverIPTablesLocked(ctx context.Context) error {
	err := recoverIPTablesChange(ctx, f.dataDir)
	if err == nil {
		err = reconcileIPTablesConfirmed(ctx, f.dataDir)
	}
	refreshErr := f.refreshIPTablesStateLocked()
	if err != nil || refreshErr != nil {
		f.problem = "iptables 原业务或子进程尚未完成恢复核对"
		f.retryAt = time.Now().Add(10 * time.Second)
		return errors.Join(err, refreshErr)
	}
	f.problem, f.policyUncertain = "", false
	return nil
}

func (f *hostFirewall) runIPTablesLocked(ctx context.Context, stopping bool, nextInspect, nextProtectionInspect *time.Time) {
	if !f.recovering {
		return
	}
	if err := f.rescueIPTablesLocked(ctx); err != nil {
		f.problem = "iptables 本机救援请求尚未完成核对"
	}
	if f.activeLocked() {
		if stopping || f.expiredLocked() || f.iptablesState.Rollback || f.problem != "" || f.remote.web == nil || f.remote.problem != "" || f.remote.listener == nil {
			if stopping || !time.Now().Before(f.retryAt) {
				_ = f.rollbackIPTablesWithTimeoutLocked(firewall.RecoveryOperationTimeout)
			}
		}
		return
	}
	if stopping || !time.Now().Before(*nextInspect) {
		*nextInspect = time.Now().Add(30 * time.Second)
		call, cancel := context.WithTimeout(context.Background(), firewall.RecoveryOperationTimeout)
		_ = f.recoverIPTablesLocked(call)
		cancel()
	}
	if !stopping && f.problem == "" && !time.Now().Before(*nextProtectionInspect) {
		f.protectionObservation = f.observeProtectionsLocked(ctx, f.confirmedRecord())
		f.protectionObservedAt = time.Now()
		*nextProtectionInspect = time.Now().Add(30 * time.Second)
	}
}

func (f *hostFirewall) rescueIPTablesLocked(ctx context.Context) error {
	raw, err := listenerRead(filepath.Join(filepath.Dir(iptablesChangePath(f.dataDir)), "rescue.json"), 1024)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var request struct {
		ID string `json:"id"`
	}
	if ufwToolJSON(raw, &request) != nil || !validID(request.ID) {
		return errors.New("iptables 本机救援请求无效")
	}
	if request.ID == f.iptablesLastRescue {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, firewall.RecoveryOperationTimeout)
	defer cancel()
	if f.activeLocked() {
		if err = f.rollbackIPTablesWithTimeoutLocked(firewall.RecoveryOperationTimeout); err != nil {
			return err
		}
	} else if err = f.recoverIPTablesLocked(call); err != nil {
		return err
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = f.refreshIPTablesStateLocked(); err != nil {
		return err
	}
	if v := f.iptablesState; v != nil {
		if !iptablesChangeTerminal(v) {
			return errors.New("iptables 救援期间原操作变化")
		}
		v.LastRescue = request.ID
		if err = saveIPTablesChange(f.dataDir, v); err != nil {
			return err
		}
	}
	f.iptablesLastRescue = request.ID
	return nil
}
