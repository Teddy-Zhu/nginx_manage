package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/secure"
)

// Jail execution belongs to the host engine. Nginx is an optional log/action
// dependency, never a substitute host runtime when no Nginx is installed.
type fail2banJailsExecutor struct {
	server *Server
	gate   *maintenanceGate
	wake   chan struct{}
}

type fail2banJailBasis struct {
	NginxDir   string `json:"nginx_dir"`
	NginxHash  string `json:"nginx_hash"`
	RegistryID string `json:"registry_id"`
	HostHash   string `json:"host_hash"`
}

func (b fail2banJailBasis) valid() bool {
	return (b.NginxDir == "" && b.NginxHash == "" && b.RegistryID == "" || (validID(b.NginxDir) || b.NginxDir == "bootstrap") && fail2banDigest.MatchString(b.NginxHash) && (b.RegistryID == "" || validID(b.RegistryID))) && (b.HostHash == "" || fail2banDigest.MatchString(b.HostHash))
}

type fail2banJailHostScope struct {
	hash         string
	protectionID string
	protected    []string
	ready        bool
	reason       string
}

func (f *fail2banJailsExecutor) journal() *Journal      { return f.server.Journal }
func (f *fail2banJailsExecutor) persist(r Record) error { return f.journal().Put(r) }
func (f *fail2banJailsExecutor) enqueue() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Keep the Nginx -> host -> binding ordering used by the two action workers.
func (f *fail2banJailsExecutor) lock(progress bool) (func(), error) {
	leave, ok := f.gate.enter(progress)
	if !ok {
		return nil, ErrBusy
	}
	n := f.server.Nginx
	if n != nil {
		if !n.mu.TryLock() {
			leave()
			return nil, ErrBusy
		}
		if n.closed || n.unlock == nil {
			n.mu.Unlock()
			leave()
			return nil, ErrRuntimeUnavailable
		}
	}
	unhost, err := fail2banHostSyncLocks(f.server.DataDir)
	if err != nil {
		if n != nil {
			n.mu.Unlock()
		}
		leave()
		return nil, err
	}
	if err = fail2banHostRetirementIdle(f.server.DataDir); err != nil {
		unhost()
		if n != nil {
			n.mu.Unlock()
		}
		leave()
		return nil, err
	}
	return func() {
		unhost()
		if n != nil {
			n.mu.Unlock()
		}
		leave()
	}, nil
}

func (f *fail2banJailsExecutor) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	dirty := true
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-f.wake:
			dirty = true
		}
		if time.Since(last) < 5*time.Second || !dirty && time.Since(last) < 30*time.Second {
			continue
		}
		dirty = false
		addressCall, stopAddress := context.WithTimeout(ctx, 40*time.Second)
		addressErr := f.advanceAddress(addressCall)
		stopAddress()
		call, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := errors.Join(addressErr, f.advanceJails(call))
		cancel()
		last = time.Now()
		if errors.Is(err, ErrBusy) || errors.Is(err, unix.EWOULDBLOCK) {
			dirty = true
		} else if err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("advance managed Fail2ban jails", "error", err)
		}
	}
}

func (f *fail2banJailsExecutor) hostScope(ctx context.Context, r *fail2banManagedRecord) fail2banJailHostScope {
	out := fail2banJailHostScope{protected: []string{}, reason: "须本机批准受管宿主机来源并开启持续同步"}
	root, e1 := loadFail2banHostRegistration(f.server.DataDir)
	protection, e2 := loadFail2banHostProtection(f.server.DataDir)
	sources, e3 := loadFail2banHostSources(f.server.DataDir)
	sync, e4 := loadFail2banHostSync(f.server.DataDir)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		out.reason = "宿主机动作批准无法完整读取"
		return out
	}
	var stopping *fail2banHostSyncEvent
	if sync != nil && sync.Action == "enable" {
		var err error
		stopping, err = loadFail2banHostSyncStop(f.server.DataDir, sync)
		if err != nil {
			out.reason = "宿主机停用意图无法核对"
			return out
		}
	}
	// Hash the complete immutable approvals, including revocation/stop identity.
	raw, _ := json.Marshal([]any{root, protection, sources, sync, stopping})
	out.hash = secure.Hash(append([]byte("nginxpanel:fail2ban-jail-host-scope:v1:"), raw...))
	if root == nil || protection == nil || sources == nil || sync == nil || root.State != "registered" || protection.Action != "approve" || sources.Action != "approve" || !sources.Policy.Managed || sync.Action != "enable" || stopping != nil {
		return out
	}
	if err := fail2banHostBootSyncAuthority(f.server.DataDir, sync); err != nil {
		out.reason = err.Error()
		return out
	}
	if sources.EngineKey != fail2banNginxEngineKey(r.binding()) || sync.EngineKey != sources.EngineKey || sync.SourcesID != sources.ID || sync.ProtectionID != protection.ID || sync.RegistrationID != root.OperationID || sync.Owner != root.Owner || sync.NamespaceID != root.Confirmed.NamespaceID {
		out.reason = "宿主机会话所属实例或批准变化，须本机重新批准"
		return out
	}
	observer := firewallObserver{scope: "host", ctx: ctx, dataDir: f.server.DataDir}
	call, stop := context.WithTimeout(ctx, 6*time.Second)
	err := checkFirewallManagers(observer.collect(call))
	stop()
	if err != nil {
		out.reason = err.Error()
		return out
	}
	basis, err := loadFail2banHostSourcesBasis(ctx, f.server.DataDir)
	if err != nil {
		out.reason = err.Error()
		return out
	}
	if basis.root.OperationID != sync.RegistrationID {
		out.reason = "宿主机登记在核对期间变化"
		return out
	}
	out.protected, out.protectionID, out.ready, out.reason = basis.protected, protection.ID, true, ""
	return out
}

func (f *fail2banJailsExecutor) basis(ctx context.Context, r *fail2banManagedRecord) (fail2banJailBasis, manifest, fail2banJailHostScope, string) {
	host := f.hostScope(ctx, r)
	out := fail2banJailBasis{HostHash: host.hash}
	var m manifest
	n := f.server.Nginx
	if n == nil {
		return out, m, host, "未接入 Nginx 运行实例"
	}
	if n.disasterBusy != "" || n.http01 != nil && n.http01.busy() {
		return out, m, host, "Nginx 正在恢复或处理证书挑战"
	}
	dir, value, err := n.active()
	if err != nil {
		return out, m, host, "Nginx 当前修订无法读取：" + err.Error()
	}
	if err = n.observe(ctx, value); err != nil {
		return out, m, host, "Nginx 运行修订未确认：" + err.Error()
	}
	registry, err := loadFail2banNginxRegistry(f.server.DataDir)
	if err != nil {
		return out, m, host, "Nginx 动作登记无法读取：" + err.Error()
	}
	out.NginxDir, out.NginxHash, out.RegistryID = dir, manifestHash(value), registry.ID
	return out, value, host, ""
}

func (f *fail2banJailsExecutor) verifyNginx(ctx context.Context, b *fail2banJailBundle) error {
	if b.NginxDir == "" {
		return nil
	}
	n := f.server.Nginx
	if n == nil {
		return errors.New("原 jail 依赖的 Nginx 运行实例不可读取")
	}
	dir, m, err := n.active()
	if err != nil || dir != b.NginxDir || manifestHash(m) != b.NginxHash {
		return ErrExternalChange
	}
	return n.observe(ctx, m)
}

func (f *fail2banJailsExecutor) verifyHost(ctx context.Context, r *fail2banManagedRecord, b *fail2banJailBundle, basis fail2banJailBasis) error {
	if !fail2banJailNeedsHost(b) {
		return nil
	}
	host := f.hostScope(ctx, r)
	a, _ := json.Marshal(host.protected)
	expected, _ := json.Marshal(b.HostProtected)
	if !host.ready || host.hash != basis.HostHash || host.protectionID != b.HostProtectionID || string(a) != string(expected) {
		return errors.New("宿主机来源、会话或保护依据变化，须重新预览")
	}
	return nil
}

func fail2banJailsSocket(data string) string {
	return filepath.Join(data, "agent", "fail2ban", "jails", "action.sock")
}
