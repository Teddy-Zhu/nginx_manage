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
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
)

type Manager struct {
	InstallNginx                              func(context.Context, string, software.Progress) (software.Result, error)
	BundledNginxVersion                       func() (*componentversions.Version, error)
	NginxInstalled                            func()
	BuiltinVersions                           func(context.Context, componentversions.Query) (componentversions.Catalog, error)
	BuiltinAction                             func(context.Context, software.Request, software.Progress) (software.Result, error)
	ContainerAction                           func(context.Context, software.Request, software.Progress) (software.Result, error)
	FrpsAction                                func(context.Context, software.Request, software.Progress) (software.Result, error)
	Fail2banAction                            func(context.Context, software.Request, software.Progress) (software.Result, error)
	UpdatePanel                               func(context.Context, string, software.Request, software.Progress) (software.Result, error)
	Dir, DataDir, TrustPath, TokenPath, Scope string
	Dev                                       bool
	mu                                        sync.Mutex
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	workers                                   sync.WaitGroup
	lock                                      *os.File
	active, closed, poisoned                  bool
}

func (m *Manager) Overview() Overview {
	out := Overview{Scope: m.Scope, KeyIDs: []string{}, Versions: map[string]componentversions.Version{}}
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
	var resume *Operation
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		out, err := m.read(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		// Preparation can remain unconfirmed until a local repair restores its
		// immutable cache or staging directories. Reconcile the same receipt on
		// restart; interrupted only uses already authenticated, retained assets.
		if out.State != "queued" && out.State != "running" && !(out.State == "recovery_required" && out.Input.Action == "prepare") {
			continue
		}
		if out.Input.Action == "software" && out.Input.Software != nil && out.Input.Software.Action == "update-panel" {
			if resume != nil {
				return errors.New("发现多项未完成的系统更新，请检查服务日志")
			}
			copy := out
			resume = &copy
			continue
		}
		recoverCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		m.interrupted(recoverCtx, &out)
		stop()
		if err := m.write(&out); err != nil {
			return err
		}
	}
	if resume != nil {
		m.active = true
		m.workers.Add(1)
		go m.run(*resume, time.Now().Add(10*time.Minute))
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
	if m.Dev || m.Scope != "host" {
		return Operation{}, fault.Unavailable("当前环境不允许修改宿主机软件")
	}
	if in.Protocol != protocol.Agent || !ValidID(in.OperationID) {
		return Operation{}, fault.Invalid("组件请求协议或标识无效")
	}
	if err := in.Input.validateSubmission(); err != nil {
		return Operation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if m.closed || m.poisoned || m.ctx == nil || m.ctx.Err() != nil {
		return Operation{}, fault.New(503, "COMPONENT_NOT_SUBMITTED", "组件执行器暂不可用")
	}
	if in.Input.Action != "software" || in.Input.Software.Action == "update-panel" {
		if overview := m.Overview(); !overview.Available {
			return Operation{}, fault.New(503, "COMPONENT_NOT_SUBMITTED", overview.Reason)
		}
	}
	if m.active {
		return Operation{}, fault.Conflict("已有组件检查或准备操作正在执行")
	}
	if _, _, err := m.entries(); err != nil {
		return Operation{}, err
	}
	now := time.Now().Unix()
	out := Operation{Protocol: protocol.Agent, ID: in.OperationID, RequestHash: secure.Hash(raw), Input: in.Input, State: "queued", Stage: "queued", CreatedAt: now, UpdatedAt: now, Deadline: now + 600}
	if err := m.write(&out); err != nil {
		m.poisoned = true
		return Operation{}, err
	}
	m.active = true
	m.workers.Add(1)
	go m.run(out, time.Unix(out.Deadline, 0))
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
	out.Announcement = nil
	out.State, out.Stage, out.ErrorCode, out.Error = "failed", "interrupted", "COMPONENT_INTERRUPTED", "组件操作在确认完成前中断，未启用或切换运行版本"
	if out.Input.Action == "software" {
		out.Error = "软件操作在确认完成前中断，请检查当前状态与日志后重试"
		return
	}
	if out.Input.Action == "pull" {
		if out.Image != nil {
			if err := m.reconcileImage(ctx, out); err != nil {
				out.State, out.Stage, out.ErrorCode, out.Error = "failed", "image_unconfirmed", "COMPONENT_IMAGE_UNCONFIRMED", "镜像下载结果未确认："+bounded(err.Error())
			}
		}
		return
	}
	if out.Input.Action != "prepare" {
		return
	}
	result, err := releases.Prepared(ctx, releases.Input{PanelStaging: true, TrustPath: m.TrustPath, Assets: out.Input.Assets, AllowedComponents: []string{"nginx", "fail2ban", "panel"}, AllowPrerelease: out.Input.Prerelease, Host: m.host(), Receiver: receiver()}, out.Input.PlanID)
	if err == nil {
		if result.Plan.ManifestSHA256 != out.Input.ManifestSHA256 || result.Plan.TrustSHA256 != out.Input.TrustSHA256 {
			err = releases.ErrReleaseChanged
		} else if err = m.prepareRuntime(ctx, out, result.Plan); err == nil {
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
func (m *Manager) run(out Operation, until time.Time) {
	defer m.workers.Done()
	defer func() { m.mu.Lock(); m.active = false; m.mu.Unlock() }()
	ctx, cancel := context.WithDeadline(m.ctx, until)
	defer cancel()
	out.State, out.Stage = "running", "checking"
	err := m.write(&out)
	if err == nil && out.Input.Action == "software" {
		progress := func(text string) {
			out.Stage = "software_running"
			out.RuntimeReason = bounded(text)
			if e := m.write(&out); e != nil {
				slog.Error("软件进度保存失败", "error", e)
				cancel()
			}
		}
		var result software.Result
		if out.Input.Software.Action == "install-nginx" {
			if m.InstallNginx == nil {
				err = errors.New("Nginx 安装不可用")
			} else {
				result, err = m.InstallNginx(ctx, out.Input.Software.Version, progress)
			}
		} else if out.Input.Software.AppID != "" {
			if m.BuiltinAction == nil {
				err = errors.New("内置组件管理不可用")
			} else {
				result, err = m.BuiltinAction(ctx, *out.Input.Software, progress)
			}
		} else if out.Input.Software.Action == "container" {
			if m.ContainerAction == nil {
				err = errors.New("Docker 容器管理不可用")
			} else {
				result, err = m.ContainerAction(ctx, *out.Input.Software, progress)
			}
		} else if out.Input.Software.Action == "frps" {
			if m.FrpsAction == nil {
				err = errors.New("FRP 服务端管理不可用")
			} else {
				result, err = m.FrpsAction(ctx, *out.Input.Software, progress)
			}
		} else if out.Input.Software.Action == "fail2ban" {
			if m.Fail2banAction == nil {
				err = errors.New("登录防护安装不可用")
			} else {
				result, err = m.Fail2banAction(ctx, *out.Input.Software, progress)
			}
		} else if out.Input.Software.Action == "update-panel" {
			if m.UpdatePanel == nil {
				err = errors.New("此安装未提供面板更新能力")
			} else {
				if out.Input.Tag != "" {
					err = PrepareCoreUpgrade(ctx, m.DataDir, m.TrustPath, m.TokenPath, out.Input, progress)
				}
				if err == nil {
					result, err = m.UpdatePanel(ctx, out.ID, *out.Input.Software, progress)
				}
				if errors.Is(err, context.Canceled) && m.ctx.Err() != nil {
					err = ErrRestartPending
				}
			}
		} else {
			err = errors.New("软件操作无效")
		}
		if !errors.Is(err, ErrRestartPending) {
			out.Software = &result
		}
		if err == nil {
			out.State, out.Stage = "succeeded", "software_done"
			out.RuntimeReason = bounded(result.Message)
		}
	} else if err == nil && out.Input.Action == "pull" {
		err = m.pullImage(ctx, &out)
	} else if err == nil {
		in := out.Input.online()
		in.TrustPath, in.TokenPath, in.Host, in.Receiver = m.TrustPath, m.TokenPath, m.host(), receiver()
		var result releases.OnlineResult
		if out.Input.OfflineID != "" {
			result, err = m.offline(ctx, out.Input)
		} else {
			result, err = releases.Online(ctx, in)
		}
		out.Announcement = result.Announcement
		if err == nil {
			_, err = panelSelection(result.Plan)
		}
		if err == nil && out.Input.Action == "prepare" {
			err = m.prepareRuntime(ctx, &out, result.Plan)
		}
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
	if errors.Is(err, ErrRestartPending) {
		out.State, out.Stage, out.ErrorCode, out.Error = "running", "core_updating", "", ""
		if writeErr := m.write(&out); writeErr != nil {
			slog.Error("核心更新中断状态持久化失败", "operation_id", out.ID, "error", writeErr)
			m.mu.Lock()
			m.poisoned = true
			m.mu.Unlock()
		}
		return
	}
	if err != nil {
		out.State, out.Stage, out.ErrorCode, out.Error = "failed", "failed", "COMPONENT_OPERATION_FAILED", bounded(err.Error())
		if errors.Is(err, releases.ErrReceiverIncompatible) {
			out.ErrorCode = "COMPONENT_RECEIVER_INCOMPATIBLE"
		}
		if errors.Is(err, releases.ErrReleaseChanged) {
			out.ErrorCode = "COMPONENT_SOURCE_CHANGED"
		}
		if out.Input.Action == "prepare" || out.Input.Action == "pull" {
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
	} else if out.State == "succeeded" && out.Input.Software != nil && out.Input.Software.Action == "install-nginx" && m.NginxInstalled != nil {
		m.NginxInstalled()
	}
}

// Pending inspects independent root receipts; an unreadable receipt blocks drain.
func (m *Manager) Pending() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Dev || m.Scope != "host" {
		return 0, nil
	}
	if m.poisoned {
		return 0, errors.New("组件执行记录待本机恢复")
	}
	entries, _, err := m.entries()
	if err != nil {
		return 0, err
	}
	pending := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		op, err := m.read(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return 0, err
		}
		if op.State == "queued" || op.State == "running" || op.State == "recovery_required" {
			pending++
		}
	}
	return pending, nil
}
