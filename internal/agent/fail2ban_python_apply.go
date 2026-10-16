package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

func fail2banPythonPackageIdle(manager string) error {
	paths := []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}
	if manager == "dnf" {
		paths = []string{"/var/lib/rpm/.rpm.lock", "/usr/lib/sysimage/rpm/.rpm.lock"}
		for _, path := range []string{"/var/lib/dnf/rpmdb_lock.pid", "/var/cache/dnf/metadata_lock.pid", "/var/cache/dnf/download_lock.pid"} {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			}
			raw, err := nginxmodules.ReadTrusted(path, 32)
			if err != nil {
				return err
			}
			pidText := strings.TrimSpace(string(raw))
			if pidText == "" {
				continue
			}
			pid, err := strconv.Atoi(pidText)
			if err != nil || pid <= 1 {
				return errors.New("DNF 原生锁记录无法核对")
			}
			err = syscall.Kill(pid, 0)
			if err == nil || errors.Is(err, syscall.EPERM) {
				return errFail2banPythonBusy
			}
			if !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		resolved, err := trustedFile(path, false)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(resolved, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		probe := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &probe)
		if err == nil && probe.Type != syscall.F_UNLCK {
			f.Close()
			return errFail2banPythonBusy
		}
		if err == nil {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				f.Close()
				return errFail2banPythonBusy
			}
			if err == nil {
				err = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			}
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	return nil
}
func fail2banPythonSpace(path string, needed int64) error {
	var info syscall.Statfs_t
	if err := syscall.Statfs(path, &info); err != nil {
		return err
	}
	if info.Bsize <= 0 || uint64(needed+(64<<20)) > info.Bavail*uint64(info.Bsize) {
		return errors.New("系统包计划所需磁盘空间不足")
	}
	return nil
}
func fail2banPythonDiskPlan(data string, p fail2banPythonPlan) error {
	downloadPath := fail2banPythonDir(data)
	if p.Plan.Manager == "dnf" {
		downloadPath = "/var/cache/dnf"
		if _, err := os.Stat(downloadPath); os.IsNotExist(err) {
			downloadPath = "/var/cache"
		} else if err != nil {
			return err
		}
		if err := fail2banToolDirectory(downloadPath); err != nil {
			return err
		}
	}
	downloadInfo, err := os.Stat(downloadPath)
	if err != nil {
		return err
	}
	installInfo, err := os.Stat("/usr")
	if err != nil {
		return err
	}
	downloadStat, ok := downloadInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("下载目录文件系统无法核对")
	}
	installStat, ok := installInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("安装目录文件系统无法核对")
	}
	needed := p.Plan.DownloadBytes
	if downloadStat.Dev == installStat.Dev {
		needed += p.Plan.InstalledBytes
	}
	if err = fail2banPythonSpace(downloadPath, needed); err != nil {
		return err
	}
	return fail2banPythonSpace("/usr", p.Plan.InstalledBytes)
}
func fail2banPythonView(r Record) fail2ban.PythonOperation {
	i := r.Fail2banPython
	return fail2ban.PythonOperation{ID: r.OperationID, PlanID: i.Plan.Plan.ID, State: r.State, Stage: r.Stage, Submission: i.Submission, At: r.UpdatedAt, Python: i.Python, Error: r.Error}
}
func fail2banPythonPersist(data string, r *Record) error {
	r.UpdatedAt = time.Now().Unix()
	return fail2banPythonJournal(data).Put(*r)
}
func readFail2banPythonOperation(data, id string) (Record, error) {
	var r Record
	if !validID(id) {
		return r, errors.New("Python 系统包操作 UUID 无效")
	}
	raw, err := listenerRead(filepath.Join(fail2banPythonJournal(data).Dir, id+".json"), 256<<10)
	if err != nil {
		return r, err
	}
	if err = fail2banPythonDecode(raw, &r); err != nil {
		return r, err
	}
	if r.Kind != fail2banPythonKind || r.OperationID != id || r.Fail2banPython == nil || validFail2banPythonPlan(r.Fail2banPython.Plan) != nil || (!r.Fail2banPython.Request.Valid() || r.Fail2banPython.Request.OperationID != id || r.Fail2banPython.Request.Input.Action != "install" || r.Fail2banPython.Request.Input.PlanID != r.Fail2banPython.Plan.Plan.ID || r.RequestHash != r.Fail2banPython.Request.Hash()) || r.UpdatedAt <= 0 {
		return r, errors.New("Python 系统包操作持久合同无效")
	}
	if r.State != "running" && r.State != "recovery_required" && r.State != "succeeded" && r.State != "failed" {
		return r, errors.New("Python 系统包操作状态未知")
	}
	if r.Fail2banPython.Submission != "not_sent" && r.Fail2banPython.Submission != "unknown" && r.Fail2banPython.Submission != "acknowledged" {
		return r, errors.New("Python 系统包派发状态未知")
	}
	if r.Fail2banPython.Sent && r.Fail2banPython.Submission == "not_sent" || !r.Fail2banPython.Sent && r.Fail2banPython.Submission != "not_sent" || len(r.Fail2banPython.ExecutionError) > 1024 {
		return r, errors.New("Python 系统包派发材料不一致")
	}
	return r, nil
}

// The caller holds the installation lock. Admission freezes the stored plan;
// expensive native resolution and installation belong to the durable executor.
func admitFail2banPythonInstall(data string, request fail2ban.PythonTaskRequest) (Record, error) {
	var out Record
	if !request.Valid() || request.Input.Action != "install" {
		return out, errors.New("Python 安装请求合同无效")
	}
	if err := fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	p, err := loadFail2banPythonPlan(data, request.Input.PlanID)
	if err != nil {
		return out, err
	}
	if p.Plan.ExpiresAt <= time.Now().Unix() || p.Plan.At > time.Now().Unix()+300 {
		return out, errors.New("Python 系统包计划已过期，请重新规划")
	}
	if err = secure.RootDirectory(fail2banPythonJournal(data).Dir, 0700); err != nil {
		return out, err
	}
	out = Record{OperationID: request.OperationID, RequestHash: request.Hash(), Kind: fail2banPythonKind, State: "running", Stage: "queued", Deadline: time.Now().Add(5 * time.Minute).Unix(), Fail2banPython: &fail2banPythonIntent{Request: request, Plan: p, Submission: "not_sent", Python: fail2ban.Empty("host", "尚未派发依赖安装").Python}}
	if err = fail2banPythonPersist(data, &out); err != nil {
		return Record{}, err
	}
	return out, nil
}
func loadFail2banPythonPlan(data, id string) (fail2banPythonPlan, error) {
	var p fail2banPythonPlan
	if !fail2banDigest.MatchString(id) {
		return p, errors.New("Python 系统包计划摘要无效")
	}
	raw, err := listenerRead(filepath.Join(fail2banPythonDir(data), "plans", id+".json"), 128<<10)
	if err != nil {
		return p, err
	}
	if err = fail2banPythonDecode(raw, &p); err != nil {
		return p, err
	}
	if err = validFail2banPythonPlan(p); err != nil {
		return p, err
	}
	if p.Plan.ID != id {
		return p, errors.New("Python 系统包计划身份不一致")
	}
	return p, nil
}
func InstallFail2banPython(ctx context.Context, in Fail2banPythonOptions) (fail2ban.PythonOperation, error) {
	var out fail2ban.PythonOperation
	if err := fail2banManagedRoot(in.DataDir, in.Scope); err != nil {
		return out, err
	}
	if !validID(in.OperationID) || !fail2banDigest.MatchString(in.PlanID) || !in.Confirm || in.Refresh {
		return out, errors.New("安装须明确确认原 Python 系统包计划与操作 UUID；不能在安装中刷新或更换来源")
	}
	request := fail2ban.PythonTaskRequest{Protocol: protocol.Agent, OperationID: in.OperationID, Input: fail2ban.PythonTaskInput{Action: "install", PlanID: in.PlanID}}
	unlock, err := (&Journal{Dir: fail2banBindingDir(in.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	r, err := readFail2banPythonOperation(in.DataDir, in.OperationID)
	if err == nil {
		if r.RequestHash != request.Hash() {
			return out, errors.New("Python 系统包操作 ID 已用于其他请求")
		}
	} else if os.IsNotExist(err) {
		r, err = admitFail2banPythonInstall(in.DataDir, request)
	}
	if err != nil {
		return out, err
	}
	return fail2banPythonInstallOutcome(runFail2banPython(ctx, in.DataDir, &r))
}

// The sent marker precedes every native effect. An accepted, unsent request
// may continue once; after dispatch only its package state is observed.
func runFail2banPython(ctx context.Context, data string, r *Record) (fail2ban.PythonOperation, error) {
	if r.State == "succeeded" || r.State == "failed" || r.Fail2banPython.Sent {
		return observeFail2banPython(ctx, data, r)
	}
	fail := func(stage string, err error) (fail2ban.PythonOperation, error) {
		r.State, r.Stage, r.Error = "failed", stage, err.Error()
		if writeErr := fail2banPythonPersist(data, r); writeErr != nil {
			return fail2banPythonView(*r), writeErr
		}
		return fail2banPythonView(*r), nil
	}
	if r.Deadline <= time.Now().Unix() || r.Fail2banPython.Plan.Plan.ExpiresAt <= time.Now().Unix() {
		return fail("authorization_expired", errors.New("Python 依赖操作或计划已过期，请重新生成计划"))
	}
	if err := fail2banManagedIdle(data, r.OperationID); err != nil {
		return fail2banPythonView(*r), err
	}
	p := r.Fail2banPython.Plan
	current, err := planFail2banPython(ctx, data, false)
	if ctx.Err() != nil {
		return fail2banPythonView(*r), ctx.Err()
	}
	if err != nil {
		return fail("preflight_failed", err)
	}
	current.Plan.At, current.Plan.ExpiresAt, current.Plan.ID = p.Plan.At, p.Plan.ExpiresAt, ""
	actualRaw, _ := json.Marshal(current)
	expected := p
	expected.Plan.ID = ""
	expectedRaw, _ := json.Marshal(expected)
	if string(actualRaw) != string(expectedRaw) {
		return fail("target_changed", errors.New("软件包、来源、主机或工具已变化，请重新生成计划"))
	}
	if err = fail2banPythonDiskPlan(data, p); err != nil {
		return fail("resources_unavailable", err)
	}
	if p.Plan.ExpiresAt <= time.Now().Unix() {
		return fail("authorization_expired", errors.New("Python 依赖计划已过期，请重新生成计划"))
	}
	if err = ctx.Err(); err != nil {
		return fail2banPythonView(*r), err
	}
	r.Fail2banPython.Sent, r.Fail2banPython.Submission, r.Stage = true, "unknown", "installing_packages"
	if err = fail2banPythonPersist(data, r); err != nil {
		return fail2banPythonView(*r), err
	}
	if p.Plan.Manager == "apt" {
		err = installFail2banAPT(ctx, data, r.OperationID, p)
	} else {
		err = installFail2banDNF(ctx, p)
	}
	if err == nil {
		r.Fail2banPython.Submission = "acknowledged"
	} else {
		r.Error = err.Error()
		r.Fail2banPython.ExecutionError = r.Error
	}
	r.Stage = "observing_packages"
	if writeErr := fail2banPythonPersist(data, r); writeErr != nil {
		return fail2banPythonView(*r), errors.Join(err, writeErr)
	}
	if ctx.Err() != nil {
		return fail2banPythonView(*r), ctx.Err()
	}
	return observeFail2banPython(ctx, data, r)
}
func fail2banPythonInstallOutcome(out fail2ban.PythonOperation, err error) (fail2ban.PythonOperation, error) {
	if err == nil && out.State != "succeeded" {
		if out.Error != "" {
			err = errors.New(out.Error)
		} else {
			err = errors.New("Python 系统包安装尚未确认完成")
		}
	}
	return out, err
}
func Fail2banPythonStatus(ctx context.Context, data, scope, id string) (fail2ban.PythonOperation, error) {
	var out fail2ban.PythonOperation
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(data)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	r, err := readFail2banPythonOperation(data, id)
	if err != nil {
		return out, err
	}
	return observeFail2banPython(ctx, data, &r)
}
func observeFail2banPython(ctx context.Context, data string, r *Record) (fail2ban.PythonOperation, error) {
	if r.State == "succeeded" || r.State == "failed" {
		return fail2banPythonView(*r), nil
	}
	i := r.Fail2banPython
	if !i.Sent {
		return fail2banPythonView(*r), nil
	} else if err := fail2banPythonPackageIdle(i.Plan.Plan.Manager); err != nil {
		r.State, r.Stage, r.Error = "recovery_required", "package_manager_unconfirmed", err.Error()
	} else {
		var err error
		if i.Plan.Plan.Manager == "apt" {
			err = proveFail2banAPT(ctx, i.Plan)
		} else {
			err = proveFail2banDNF(ctx, i.Plan)
		}
		i.Python = readFail2banPython(ctx)
		if ctx.Err() != nil {
			return fail2banPythonView(*r), ctx.Err()
		}
		if err == nil && (i.Python.StandardLibrary == nil || !*i.Python.StandardLibrary || !i.Python.Package.Available || !i.Python.Executable.Trusted) {
			err = errors.New("系统 Python、包归属、必要标准库或 SQLite 读写尚未完整确认")
		}
		if idleErr := fail2banPythonPackageIdle(i.Plan.Plan.Manager); idleErr != nil {
			r.State, r.Stage, r.Error = "recovery_required", "package_manager_unconfirmed", idleErr.Error()
		} else if err != nil {
			if i.ExecutionError != "" {
				err = errors.Join(errors.New(i.ExecutionError), err)
			}
			r.State, r.Stage, r.Error = "failed", "packages_unconfirmed", err.Error()
		} else {
			r.State, r.Stage, r.Error = "succeeded", "python_confirmed", ""
			if i.Submission == "unknown" {
				r.Stage = "python_confirmed_receipt_unknown"
			}
		}
	}
	if err := fail2banPythonPersist(data, r); err != nil {
		return fail2banPythonView(*r), err
	}
	return fail2banPythonView(*r), nil
}
