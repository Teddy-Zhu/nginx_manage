package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type fail2banHostSyncExecutor struct {
	server    *Server
	gate      *maintenanceGate
	wake      chan struct{}
	mu        sync.Mutex
	value     fail2ban.HostInputSyncView
	selection string
}

func (f *fail2banHostSyncExecutor) enqueue() {
	f.mu.Lock()
	f.value.Queued = true
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fail2banHostSyncExecutor) status() fail2ban.HostInputSyncView {
	event, err := loadFail2banHostSync(f.server.DataDir)
	if err != nil {
		return fail2ban.EmptyHostInputSync("持续同步批准无法完整读取")
	}
	out := fail2banHostBootRecoveryView(f.server.DataDir, fail2banHostRetirementSyncView(f.server.DataDir, fail2banHostSyncMetadata(event)))
	if !out.Enabled || out.State == "recovery_required" || out.State == "recovering" || out.RecoveryID != "" && out.State == "paused" {
		return out
	}
	if err = fail2banHostBootSyncAuthority(f.server.DataDir, event); err != nil {
		out.State, out.Reason = "paused", err.Error()
		return out
	}
	if stopping, e := loadFail2banHostSyncStop(f.server.DataDir, event); e != nil {
		out.State, out.Reason = "recovery_required", "持续同步停用意图无法完整核对"
		return out
	} else if stopping != nil {
		out.State, out.Reason, out.Queued = "stopping", "停用已记录，等待核对并清除动作规则", true
		return out
	}
	protection, protectionErr := loadFail2banHostProtection(f.server.DataDir)
	sources, sourcesErr := loadFail2banHostSources(f.server.DataDir)
	if protectionErr != nil || sourcesErr != nil || protection == nil || protection.Action != "approve" || protection.ID != event.ProtectionID || sources == nil || sources.Action != "approve" || sources.ID != event.SourcesID || sources.EngineKey != event.EngineKey {
		out.State, out.Reason = "paused", "保护或官方来源批准已变化，须停用后重新批准"
		return out
	}
	f.mu.Lock()
	value := f.value
	selection := f.selection
	f.mu.Unlock()
	if value.ID == event.ID {
		out = value
		out.At = time.Now().Unix()
		if out.State == "current" && (out.CollectedAt > out.At || out.At-out.CollectedAt > 60) {
			out.State, out.Reason = "waiting", "完整同步样本已过期，等待重新核对"
		}
		if out.State == "current" && sources.Policy.Managed {
			r, e := loadFail2banManaged(f.server.DataDir)
			if e != nil || r == nil || r.State != "installed" || fail2banNginxEngineKey(r.binding()) != event.EngineKey {
				out.State, out.Reason = "paused", "受管实例身份无法核对"
			} else if r.JailSelection != selection {
				out.State, out.Reason = "waiting", "受管 jail 配置变化，等待完整新采样"
			}
		}
	}
	return out
}

func (s *Server) fail2banHostSyncStatus() fail2ban.HostInputSyncView {
	if s.fail2banHostSync == nil {
		return fail2ban.EmptyHostInputSync("宿主机持续同步执行器未连接")
	}
	return s.fail2banHostSync.status()
}

func (f *fail2banHostSyncExecutor) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	dirty := true
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.wake:
			dirty = true
		case <-ticker.C:
		}
		if time.Since(last) < 5*time.Second || !dirty && time.Since(last) < 30*time.Second {
			continue
		}
		dirty = false
		f.mu.Lock()
		f.value.State, f.value.Queued = "collecting", false
		f.mu.Unlock()
		call, cancel := context.WithTimeout(ctx, 30*time.Second)
		value, err := f.reconcile(call)
		cancel()
		last = time.Now()
		if err != nil {
			if value.RecoveryID != "" {
				value.State, value.Queued = "recovery_required", false
			} else if value.State != "recovery_required" {
				value.State = "failed"
			}
			value.Reason = err.Error()
			if value.RecoveryID == "" && (errors.Is(err, ErrBusy) || errors.Is(err, unix.EWOULDBLOCK)) {
				value.State, value.Reason, value.Queued, dirty = "paused", "维护或实例变更期间暂停同步，保留已核对规则", true, true
			}
		}
		if err == nil && (value.State == "recovering" || value.RecoveryID != "" && value.State == "waiting") {
			dirty = true
		}
		f.mu.Lock()
		if value.State != "recovering" && value.State != "recovery_required" {
			value.Queued = value.Queued || f.value.Queued
		}
		f.value = value
		f.mu.Unlock()
	}
}

func (f *fail2banHostSyncExecutor) reconcile(ctx context.Context) (fail2ban.HostInputSyncView, error) {
	dataDir := f.server.DataDir
	event, err := loadFail2banHostSync(dataDir)
	out := fail2banHostSyncMetadata(event)
	if err != nil {
		return fail2ban.EmptyHostInputSync("持续同步批准无法读取"), err
	}
	leaveGate, ok := f.gate.enter(true)
	if !ok {
		return out, ErrBusy
	}
	defer leaveGate()
	leave, err := fail2banHostSyncLocks(dataDir)
	if err != nil {
		return out, err
	}
	defer leave()
	if err = fail2banUpgradeSwitchIdle(dataDir, ""); err != nil {
		return out, err
	}
	if err = fail2banUpgradeRestoreIdle(dataDir, ""); err != nil {
		return out, err
	}
	if err = fail2banUpgradeQuiesceIdle(dataDir, ""); err != nil {
		return out, err
	}
	if err = fail2banUpgradeActivationActions(ctx, dataDir); err != nil {
		return out, err
	}
	if changed, e := advanceFail2banHostRetirement(ctx, dataDir); e != nil || changed {
		latest, readErr := loadFail2banHostSync(dataDir)
		out = fail2banHostBootRecoveryView(dataDir, fail2banHostRetirementSyncView(dataDir, fail2banHostSyncMetadata(latest)))
		return out, errors.Join(e, readErr)
	}
	latest, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return out, err
	}
	if handled, e := f.bootRecovery(ctx, latest); handled || e != nil {
		latest, readErr := loadFail2banHostSync(dataDir)
		out = fail2banHostBootRecoveryView(dataDir, fail2banHostRetirementSyncView(dataDir, fail2banHostSyncMetadata(latest)))
		if e != nil && out.State != "recovering" && out.State != "recovery_required" {
			out.State, out.Reason = "paused", e.Error()
		}
		return out, errors.Join(e, readErr)
	}
	if event == nil || event.Action != "enable" {
		return out, nil
	}
	latest, err = loadFail2banHostSync(dataDir)
	if err != nil || latest == nil || latest.ID != event.ID {
		return out, errors.Join(errors.New("持续同步批准已变化，等待新观察"), err)
	}
	stopping, err := loadFail2banHostSyncStop(dataDir, event)
	if err != nil {
		return out, err
	}
	if stopping != nil {
		out.State, out.Reason = "stopping", "正在核对并清除当前会话规则"
		if err = finishFail2banHostSyncStop(ctx, dataDir, event, stopping); err != nil {
			return out, err
		}
		return fail2banHostSyncMetadata(stopping), nil
	}
	parent, err := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(event.ID)
	if err != nil || !fail2banHostSyncParentMatches(parent, event) || parent.State != "running" {
		return out, errors.Join(errors.New("持续同步父操作未核对，禁止重启旧会话"), err)
	}
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if root == nil || root.State != "registered" || root.OperationID != event.RegistrationID || root.Owner != event.Owner || root.Confirmed.NamespaceID != event.NamespaceID || !fail2banHostRegistrationReceipt(dataDir, root) {
		return out, errors.New("持续同步所属登记、所有者或命名空间变化，须本机重新授权")
	}
	current, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return out, err
	}
	if current != nil && current.Intent.ControllerID != event.ID && current.Intent.OperationID != event.RuntimeBaseID {
		return out, errors.New("当前运行对象不属于批准的持续会话或初始基础")
	}
	if current != nil && (current.State == "running" || current.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, current)) {
		out.State, out.Reason = "recovery_required", "正在核对原子事务，不重发旧样本"
		status, e := recoverFail2banHostRuntime(ctx, dataDir, root, current)
		if e != nil && !status.Runtime.Verified {
			return out, e
		}
		current, err = loadFail2banHostRuntime(dataDir)
		if err != nil {
			return out, err
		}
	}
	if f.gate.closing() {
		activation, _, e := pendingFail2banUpgradeActivation(dataDir)
		if e != nil {
			return out, e
		}
		if activation == nil {
			return out, ErrBusy
		}
		if e = fail2banUpgradeActivationActions(ctx, dataDir); e != nil {
			return out, e
		}
	}
	admit, err := fail2banHostSyncAdmissionFor(ctx, dataDir, true, true)
	if err != nil {
		return out, err
	}
	defer admit()
	protection, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return out, err
	}
	sources, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return out, err
	}
	if protection == nil || protection.Action != "approve" || protection.ID != event.ProtectionID || sources == nil || sources.Action != "approve" || sources.ID != event.SourcesID || sources.EngineKey != event.EngineKey {
		return out, errors.New("持续同步绑定的保护或官方来源批准变化，须停用后重新批准")
	}
	status, err := executeFail2banHostRuntime(ctx, dataDir, root, current, "apply", secure.ID(), event.ID)
	if err != nil {
		checkpoint, e := loadFail2banHostRuntime(dataDir)
		if e != nil || checkpoint != nil && checkpoint.Intent.ControllerID == event.ID && (checkpoint.State == "running" || checkpoint.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, checkpoint)) {
			out.State = "recovery_required"
		}
		return out, err
	}
	if !status.Runtime.Verified || status.Sources == nil || status.Sources.State != "ready" {
		return out, errors.New("持续同步结果未完整核对")
	}
	out.State, out.Reason = "current", ""
	out.CollectedAt, out.ConfirmedAt = status.Sources.CollectedAt, time.Now().Unix()
	out.SourceHash, out.KernelOperationID = status.Sources.SourceHash, status.Runtime.OperationID
	selection := ""
	if sources.Policy.Managed {
		r, e := loadFail2banManaged(dataDir)
		if e != nil || r == nil || r.State != "installed" {
			return out, errors.Join(errors.New("已同步样本的受管来源选择无法核对"), e)
		}
		selection = r.JailSelection
	}
	f.mu.Lock()
	f.selection = selection
	f.mu.Unlock()
	return out, nil
}
