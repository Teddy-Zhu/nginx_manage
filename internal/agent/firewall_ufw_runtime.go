package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/secure"
)

const ufwRuntimeProblem = "UFW 已确认状态待核对："

func (f *hostFirewall) refreshUFWStateLocked() error {
	v, err := loadUFWChange(f.dataDir)
	if err != nil || v == nil && f.ufwState != nil {
		f.problem, f.policyUncertain = ufwProcessProblem+"原业务快照无法读取或丢失", true
		return errors.Join(err, errors.New("UFW 原业务快照无法完整读取"))
	}
	f.ufwState = v
	if v != nil {
		f.ufwLastRescue = v.LastRescue
	}
	return nil
}

func (f *hostFirewall) openUFWExecutor(v *ufwChangeCheckpoint) error {
	f.owner, f.available, f.ufwState = "ufw", false, v
	if os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		f.problem, f.policyUncertain = "UFW 恢复须在真实宿主机 root 范围执行", true
		return nil
	}
	if v == nil && !f.ufwPlanning && !ufwRestorePending(f.dataDir) {
		return nil
	}
	// An alternate IPC socket must not start a second controller that mistakes
	// this Agent's live confirmation window for a crashed original operation.
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-agent.lock")
	if err != nil {
		return errors.Join(errors.New("其他 UFW Agent 正在维护原操作"), err)
	}
	f.unlock = unlock
	if err := secure.RootDirectory(filepath.Dir(ufwChangePath(f.dataDir)), 0700); err != nil {
		return err
	}
	f.recovering, f.policyUncertain = true, false
	call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A restarted Agent cannot retain proof of the post-change listener. Never
	// resume its unconfirmed candidate, even when the wall deadline is future.
	if err := f.recoverUFWProcess(call); err != nil {
		return nil
	}
	if err := f.rescueUFWLocked(call); err != nil {
		f.problem = ufwProcessProblem + "本机救援请求尚未处理完成"
		return nil
	}
	if err := f.reconcileUFWConfirmedLocked(call); err != nil {
		f.problem = ufwRuntimeProblem + err.Error()
	}
	return nil
}

func (f *hostFirewall) rollbackUFWLocked() error {
	call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f.proofListener, f.protectionObservedAt = nil, time.Time{}
	err := f.recoverUFWProcess(call)
	// A failed listener replacement must not leave the original confirmed
	// management endpoint closed after the firewall has been restored.
	return errors.Join(err, f.remote.reconcile())
}

// Confirmed ownership is recompiled against fresh native files. Legitimate
// foreign changes are checked against their current file/kernel pair; an old
// complete foreign snapshot is never replayed after confirmation.
func (f *hostFirewall) reconcileUFWConfirmedLocked(ctx context.Context) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = f.refreshUFWStateLocked(); err != nil {
		return err
	}
	v := f.ufwState
	if v == nil {
		return nil
	}
	parent, err := loadUFWReceipt(f.dataDir, v.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(parent, v) || !ufwChangeTerminal(v) || ufwRestoreProcessPending(f.dataDir) {
		return errors.New("原业务或子进程尚未完成核对")
	}
	if v.Confirmed == nil || v.Confirmed.Action == "remove" {
		f.policyUncertain = false
		if strings.HasPrefix(f.problem, ufwRuntimeProblem) {
			f.problem = ""
		}
		return nil
	}
	registrationUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer registrationUnlock()
	authority, err := ufwRegistrationAuthority(f.dataDir)
	if err != nil || authority.NextClaim.Owner != v.Transition.Owner || authority.NextClaim.MachineHash != v.Transition.MachineHash || authority.NextClaim.OperationID != v.Transition.RegistrationOperationID {
		return errors.New("原确认策略不属于当前本机授权")
	}
	// Official status/report reads take the POSIX UFW lock themselves. Collect
	// them before our conflicting OFD lock, then re-read flags and native state.
	if _, err = f.checkUFWEnvironment(ctx, v.Transition.IPv6, v.Transition.Reload.Backend); err != nil {
		return err
	}
	manager, err := lockUFWManager()
	if err != nil {
		return err
	}
	defer manager.Close()
	enabled, enabledErr := ufwConfigured()
	ipv6, ipv6Err := ufwConfigurationFlag("/etc/default/ufw", "IPV6")
	if enabledErr != nil || ipv6Err != nil || enabled == nil || !*enabled || ipv6 == nil || *ipv6 != v.Transition.IPv6 {
		return errors.New("UFW 持久启用状态或地址族在核对期间变化")
	}
	if err = v.Transition.Tools.verify(ctx); err != nil {
		return err
	}
	binary, err := ufwTool()
	if err != nil || binary != v.Transition.Tools.Files[0].File.Path {
		return errors.New("已确认 UFW 的 CLI 选择发生变化")
	}
	configuration, err := readUFWConfiguration(ctx, binary, v.Transition.IPv6)
	if err != nil {
		return err
	}
	program, err := ufwPolicyProgram(v.Confirmed, v.Transition.Owner)
	if err != nil {
		return err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return err
	}
	if err = verifyUFWOwnedConfiguration(configuration, v.Transition.IPv6, owned); err != nil {
		return err
	}
	baseline, err := readUFWReloadBaseline(ctx, configuration, v.Transition.IPv6, &v.Transition.Tools, filepath.Dir(ufwChangePath(f.dataDir)))
	if err != nil || baseline.Backend != v.Transition.Reload.Backend {
		return errors.Join(err, errors.New("当前持久文件与内核运行状态不一致，须恢复确认规则"))
	}
	after, err := readUFWConfiguration(ctx, binary, v.Transition.IPv6)
	if err != nil || after.Hash != configuration.Hash {
		return errors.New("已确认规则核对期间固定配置变化")
	}
	if err = v.Transition.Tools.verify(ctx); err != nil {
		return err
	}
	current, err := ufwTool()
	if err != nil || current != binary {
		return errors.New("UFW CLI 选择在确认规则核对期间变化")
	}
	if err = verifyUFWManagerLock(manager); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	f.policyUncertain = false
	if strings.HasPrefix(f.problem, ufwRuntimeProblem) {
		f.problem = ""
	}
	return nil
}

func (f *hostFirewall) rescueUFWLocked(ctx context.Context) error {
	raw, err := listenerRead(filepath.Join(filepath.Dir(ufwChangePath(f.dataDir)), "rescue.json"), 1024)
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
		return errors.New("UFW 本机救援请求无效")
	}
	if request.ID == f.ufwLastRescue {
		return nil
	}
	if f.activeLocked() {
		if err = f.rollbackUFWLocked(); err != nil {
			return err
		}
	} else if err = f.reconcileUFWConfirmedLocked(ctx); err != nil {
		return err
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = f.refreshUFWStateLocked(); err != nil {
		return err
	}
	if v := f.ufwState; v != nil {
		if !ufwChangeTerminal(v) {
			return errors.New("UFW 救援期间原业务状态变化")
		}
		v.LastRescue = request.ID
		if err = saveUFWChange(f.dataDir, v); err != nil {
			return err
		}
	}
	f.ufwLastRescue = request.ID
	return nil
}

func (f *hostFirewall) runUFWLocked(ctx context.Context, stopping bool, nextInspect, nextProtectionInspect *time.Time) {
	if !f.recovering {
		return
	}
	if err := f.rescueUFWLocked(ctx); err != nil {
		f.problem = ufwProcessProblem + "本机救援请求尚未处理完成"
	}
	if f.activeLocked() {
		if stopping || f.expiredLocked() || f.ufwState.Rollback || f.problem != "" || f.remote.web == nil || f.remote.problem != "" || f.remote.listener == nil {
			if stopping || !time.Now().Before(f.retryAt) {
				if err := f.rollbackUFWLocked(); err != nil {
					f.retryAt = time.Now().Add(10 * time.Second)
				}
			}
		}
		return
	}
	if stopping || !time.Now().Before(*nextInspect) {
		*nextInspect = time.Now().Add(30 * time.Second)
		call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if ufwRestorePending(f.dataDir) || strings.HasPrefix(f.problem, ufwProcessProblem) {
			if err := f.recoverUFWProcess(call); err != nil {
				cancel()
				return
			}
		}
		if !stopping {
			if err := f.reconcileUFWConfirmedLocked(call); err != nil {
				f.problem = ufwRuntimeProblem + err.Error()
			}
		}
		cancel()
	}
	if !stopping && !f.activeLocked() && f.problem == "" && !time.Now().Before(*nextProtectionInspect) {
		f.protectionObservation = f.observeProtectionsLocked(ctx, f.confirmedRecord())
		f.protectionObservedAt = time.Now()
		*nextProtectionInspect = time.Now().Add(30 * time.Second)
	}
}
