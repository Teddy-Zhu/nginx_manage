package components

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

type Manager struct {
	Dir, TrustPath, TokenPath, Scope string
	Dev                              bool
	mu                               sync.Mutex
	ctx                              context.Context
	cancel                           context.CancelFunc
	workers                          sync.WaitGroup
	lock                             *os.File
	active, closed, poisoned         bool
}

func (m *Manager) Overview() Overview {
	out := Overview{Scope: m.Scope, KeyIDs: []string{}}
	if m.Dev || m.Scope != "host" {
		out.Reason = "须由本机 root 确认宿主机组件范围"
		return out
	}
	trust, err := releases.InspectTrust(m.TrustPath)
	if err != nil {
		out.Reason = "本机发行信任不可用：" + bounded(err.Error())
		return out
	}
	out.Available, out.Repository, out.TrustSHA256, out.KeyIDs = true, trust.Repository, trust.SHA256, trust.KeyIDs
	return out
}
func (m *Manager) Open(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	if m.Dev || m.Scope != "host" {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("组件管理需要本机 root Agent")
	}
	if err := secure.RootDirectory(m.Dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.Dir, ".manager.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 {
			err = errors.New("组件管理锁无效")
		}
	}
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return err
	}
	m.lock = f
	entries, _, err := m.entries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		out, err := m.read(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		if out.State != "queued" && out.State != "running" {
			continue
		}
		recoverCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		m.interrupted(recoverCtx, &out)
		stop()
		if err := m.write(&out); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	m.workers.Wait()
	if m.lock != nil {
		m.lock.Close()
	}
}
func (m *Manager) Status(id string) (Operation, error) {
	if !ValidID(id) {
		return Operation{}, fault.Invalid("组件操作标识无效")
	}
	if m.Dev || m.Scope != "host" {
		return Operation{}, fault.Unavailable("宿主机组件范围尚未确认")
	}
	out, err := m.read(id)
	if os.IsNotExist(err) {
		return Operation{}, fault.NotFound("组件操作记录不存在")
	}
	return out, err
}
func (m *Manager) Submit(in Request) (Operation, error) {
	if in.Protocol != protocol.Agent || !ValidID(in.OperationID) {
		return Operation{}, fault.Invalid("组件请求协议或标识无效")
	}
	if err := in.Input.Validate(); err != nil {
		return Operation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.poisoned || m.ctx == nil || m.ctx.Err() != nil {
		return Operation{}, fault.Unavailable("组件执行器已停止或记录待本机恢复")
	}
	if overview := m.Overview(); !overview.Available {
		return Operation{}, fault.Unavailable(overview.Reason)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return Operation{}, err
	}
	prior, err := m.read(in.OperationID)
	if err == nil {
		if prior.RequestHash != secure.Hash(raw) {
			return Operation{}, fault.Conflict("组件操作标识已用于不同请求")
		}
		return prior, nil
	}
	if !os.IsNotExist(err) {
		return Operation{}, err
	}
	if m.active {
		return Operation{}, fault.Conflict("已有组件检查或准备操作正在执行")
	}
	_, count, err := m.entries()
	if err != nil {
		return Operation{}, err
	}
	if count >= 64 {
		return Operation{}, fault.Conflict("组件记录已达 64 项，须本机维护")
	}
	now := time.Now().Unix()
	out := Operation{Protocol: protocol.Agent, ID: in.OperationID, RequestHash: secure.Hash(raw), Input: in.Input, State: "queued", Stage: "queued", CreatedAt: now, UpdatedAt: now, Deadline: now + 600}
	if err := m.write(&out); err != nil {
		m.poisoned = true
		return Operation{}, err
	}
	m.active = true
	m.workers.Add(1)
	go m.run(out)
	return out, nil
}
func (m *Manager) host() releases.Host {
	h := platform.Detect()
	return releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: h.OS, Version: h.Version}
}
func receiver() releases.Receiver {
	return releases.Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: releases.LauncherVersion}
}
func bounded(message string) string {
	chars := []rune(message)
	if len(chars) > 1000 {
		chars = chars[:1000]
	}
	return string(chars)
}
func (m *Manager) interrupted(ctx context.Context, out *Operation) {
	out.State, out.Stage, out.ErrorCode, out.Error = "failed", "interrupted", "COMPONENT_INTERRUPTED", "组件操作在确认完成前中断，未启用或切换运行版本"
	if out.Input.Action != "prepare" {
		return
	}
	result, err := releases.Prepared(ctx, releases.Input{TrustPath: m.TrustPath, Assets: out.Input.Assets, AllowedComponents: []string{"nginx", "fail2ban"}, AllowPrerelease: out.Input.Prerelease, Host: m.host(), Receiver: receiver()}, out.Input.PlanID)
	if err == nil {
		if result.Plan.ManifestSHA256 != out.Input.ManifestSHA256 || result.Plan.TrustSHA256 != out.Input.TrustSHA256 {
			err = releases.ErrReleaseChanged
		} else {
			info := release(result.Plan)
			out.Release, out.State, out.Stage, out.ErrorCode, out.Error, out.RuntimeReady = &info, "succeeded", "prepared", "", "", true
			return
		}
	}
	if _, statErr := os.Lstat(filepath.Join(releases.Store, out.Input.PlanID)); os.IsNotExist(statErr) {
		return
	}
	out.State, out.Stage, out.ErrorCode, out.Error = "recovery_required", "receipt_unconfirmed", "COMPONENT_PREPARATION_UNCONFIRMED", "准备目录存在但未确认有效："+bounded(err.Error())
}
func (m *Manager) run(out Operation) {
	defer m.workers.Done()
	defer func() { m.mu.Lock(); m.active = false; m.mu.Unlock() }()
	ctx, cancel := context.WithDeadline(m.ctx, time.Unix(out.Deadline, 0))
	defer cancel()
	out.State, out.Stage = "running", "checking"
	err := m.write(&out)
	if err == nil {
		in := out.Input.online()
		in.TrustPath, in.TokenPath, in.Host, in.Receiver = m.TrustPath, m.TokenPath, m.host(), receiver()
		var result releases.OnlineResult
		result, err = releases.Online(ctx, in)
		if err == nil {
			info := release(result.Plan)
			out.Release, out.State, out.Stage = &info, "succeeded", "checked"
			if out.Input.Action == "prepare" {
				out.Stage, out.RuntimeReady = "prepared", true
			} else if e := releases.RuntimeReadiness(ctx, result.Plan.Assets); e == nil {
				out.RuntimeReady = true
			} else {
				out.RuntimeReason = bounded(e.Error())
			}
			if ctx.Err() != nil && out.Input.Action == "check" {
				err = ctx.Err()
			}
		}
	}
	if err != nil {
		out.State, out.Stage, out.ErrorCode, out.Error = "failed", "failed", "COMPONENT_OPERATION_FAILED", bounded(err.Error())
		if errors.Is(err, releases.ErrReleaseChanged) {
			out.ErrorCode = "COMPONENT_SOURCE_CHANGED"
		}
		if out.Input.Action == "prepare" {
			// A failed response is not evidence that the atomic publication failed.
			recoverCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
			prior := out
			m.interrupted(recoverCtx, &out)
			stop()
			if out.State == "failed" {
				out = prior
			}
		}
	}
	if err := m.write(&out); err != nil {
		slog.Error("组件任务结果持久化失败", "operation_id", out.ID, "error", err)
		m.mu.Lock()
		m.poisoned = true
		m.mu.Unlock()
	}
}
