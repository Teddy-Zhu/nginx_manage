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

// Confirmed ownership is recompiled against fresh native files; repair uses
// its own intent, never the original operation's foreign-rule snapshot.
func (f *hostFirewall) reconcileUFWConfirmedLocked(ctx context.Context) error {
	if err := reconcileUFWConfirmed(ctx, f.dataDir); err != nil {
		return err
	}
	if err := f.refreshUFWStateLocked(); err != nil {
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
