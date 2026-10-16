package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

func readFail2banManaged(data string) fail2ban.Managed {
	r, err := loadFail2banManaged(data)
	if err != nil {
		out := fail2ban.UnknownManaged()
		out.Reason = "受管引擎安装登记不可核对，须在本机检查"
		return out
	}
	if r == nil {
		return fail2ban.Managed{Available: true, State: "absent", Reason: "未登记受管引擎；已有实例须单独诊断与接入"}
	}
	return r.view()
}
func fail2banManagedNoOther(ctx context.Context, data string, fresh bool) error {
	b, err := loadFail2banBinding(data)
	if err != nil {
		return err
	}
	if b != nil && b.State == "bound" {
		return errors.New("已有实例已接入，不允许另建受管引擎")
	}
	for _, state := range readFail2banServices(ctx) {
		if !fresh && state.ID == fail2banManagedService {
			continue
		}
		if !state.Available || state.Load != "not-found" || state.MainPID == nil || *state.MainPID != 0 || state.Active != "inactive" {
			return errors.New("发现已有 Fail2ban 服务或无法排除已有实例，请使用已有实例接入")
		}
	}
	if fresh {
		for _, name := range []string{"fail2ban-server", "fail2ban-client", "fail2ban-regex"} {
			tool := fail2banTool(name)
			if tool.Present == nil || *tool.Present {
				return errors.New("已有 Fail2ban 工具或安装状态未知，不创建第二套引擎")
			}
		}
	}
	socket := readFail2banSocket()
	if socket.Present == nil || *socket.Present {
		return errors.New("已有默认 Socket 或无法排除已有实例")
	}
	return nil
}
func fail2banManagedEffective(ctx context.Context) error {
	raw, err := fail2banManagedExec(ctx, fail2banTool("systemctl"), []string{"show", "--no-pager", "--property=FragmentPath,DropInPaths,NeedDaemonReload", fail2banManagedService}, 5*time.Second, 4096)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("受管服务实际入口无法核对")
		}
		if key != "FragmentPath" && key != "DropInPaths" && key != "NeedDaemonReload" {
			return errors.New("受管服务出现未知属性")
		}
		if _, ok = values[key]; ok {
			return errors.New("受管服务属性重复")
		}
		values[key] = value
	}
	if len(values) != 3 || values["FragmentPath"] != fail2banManagedUnit || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" {
		return errors.New("受管服务的实际文件、覆盖项或加载版本发生变化")
	}
	return nil
}

func fail2banManagedStopped(ctx context.Context) error {
	for _, service := range readFail2banServices(ctx) {
		if service.ID != fail2banManagedService {
			continue
		}
		if service.Available && service.MainPID != nil && *service.MainPID == 0 && (service.Active == "inactive" || service.Active == "failed") {
			return nil
		}
		return errors.New("独立服务未能确认停止，保留安装现场")
	}
	return errors.New("独立服务停止状态缺失")
}
func InstallFail2ban(ctx context.Context, in Fail2banInstallOptions) (fail2ban.Managed, error) {
	return installFail2ban(ctx, in, "")
}
func installFail2ban(ctx context.Context, in Fail2banInstallOptions, allowed string) (out fail2ban.Managed, resultErr error) {
	out = fail2ban.UnknownManaged()
	if err := fail2banManagedRoot(in.DataDir, in.Scope); err != nil {
		return out, err
	}
	if !validID(in.OperationID) || !fail2banDigest.MatchString(in.PlanID) || in.AssetID == "" || len(in.AssetID) > 128 || !filepath.IsAbs(in.TrustPath) || filepath.Clean(in.TrustPath) != in.TrustPath || len(in.TrustPath) > 512 {
		return out, errors.New("受管引擎安装须提供操作 UUID、固定准备计划、资产与信任文件")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	unlock, err := (&Journal{Dir: fail2banBindingDir(in.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(in.DataDir, allowed); err != nil {
		return out, err
	}
	r, err := loadFail2banManaged(in.DataDir)
	if err != nil {
		return out, err
	}
	if r != nil && r.State != "rolled-back" {
		out = r.view()
		if r.OperationID != in.OperationID || r.PlanID != in.PlanID || r.AssetID != in.AssetID || r.TrustPath != in.TrustPath || r.Prerelease != in.Prerelease || r.Start != in.Start || r.Enable != in.Enable {
			return out, errors.New("已有受管安装意图不同，不替换现有记录")
		}
		if r.State == "installed" {
			return out, verifyFail2banManaged(call, r, true)
		}
		if r.State == "rolling-back" || !in.Resume {
			return out, errors.New("原安装尚未结束，须以相同意图明确续办或撤回")
		}
		if err = verifyFail2banManaged(call, r, false); err != nil {
			return out, err
		}
	} else {
		if r != nil {
			registry, e := loadFail2banNginxRegistry(in.DataDir)
			if e != nil {
				return out, e
			}
			key := fail2banNginxEngineKey(r.binding())
			for _, grant := range registry.Grants {
				if grant.EngineKey == key {
					return out, errors.New("原安装仍有动作授权，须先完成撤回授权清理")
				}
			}
		}
		if in.Resume || r != nil && r.OperationID == in.OperationID {
			return out, errors.New("原安装不存在或已经撤回，不能重建同一操作")
		}
		if err = fail2banManagedNoOther(call, in.DataDir, true); err != nil {
			return out, err
		}
		if err = fail2banManagedOverrides(); err != nil {
			return out, err
		}
		for _, path := range []string{fail2banManagedUnit, "/run/nginxpanel-fail2ban", filepath.Join(fail2banManagedDir(in.DataDir), in.OperationID)} {
			if _, err = os.Lstat(path); err == nil {
				return out, errors.New("受管安装目标已有未登记材料，不覆盖")
			} else if !os.IsNotExist(err) {
				return out, err
			}
		}
		previousEvent := ""
		if r != nil {
			previousEvent = r.EventID
		}
		r, err = admitFail2banManaged(call, in)
		if err != nil {
			return out, err
		}
		r.EventID = previousEvent
		if err = saveFail2banManaged(r, "reserved", ""); err != nil {
			return out, err
		}
	}
	defer func() {
		if resultErr != nil {
			r.ActionState = "unknown"
			reason := "安装未完成，实际文件及服务状态须在续办或撤回前重新核对"
			if err := saveFail2banManaged(r, "interrupted", reason); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
		out = r.view()
	}()
	if r.State != "reserved" || r.ActionState != "pending" {
		r.Action, r.ActionState = "install", "pending"
		if err = saveFail2banManaged(r, "reserved", ""); err != nil {
			return out, err
		}
	}
	for _, dir := range []string{r.work(), filepath.Join(r.work(), "state"), filepath.Join(r.work(), "config"), filepath.Join(r.work(), "config", "jail.d"), filepath.Join(r.work(), "config", "filter.d"), filepath.Join(r.work(), "config", "action.d")} {
		if err = secure.RootDirectory(dir, 0700); err != nil {
			return out, err
		}
	}
	// The durable reservation precedes every file creation. Resuming never
	// replaces a changed file; partial writes only exist under private temp names.
	for name, content := range r.files() {
		if err = writeFail2banManagedFile(name, content); err != nil {
			return out, err
		}
	}
	if err = checkFail2banManaged(call, r); err != nil {
		return out, err
	}
	if err = saveFail2banManaged(r, "ready", ""); err != nil {
		return out, err
	}
	if err = fail2banManagedSystemctl(call, "daemon-reload"); err != nil {
		return out, err
	}
	if err = fail2banManagedEffective(call); err != nil {
		return out, err
	}
	if r.Enable {
		if err = fail2banManagedSystemctl(call, "enable", "--no-reload", fail2banManagedService); err != nil {
			return out, err
		}
	}
	if r.Start {
		if err = fail2banManagedNoOther(call, in.DataDir, false); err != nil {
			return out, err
		}
		if err = fail2banManagedSystemctl(call, "start", fail2banManagedService); err != nil {
			return out, err
		}
		if err = waitFail2banManagedLive(call, r); err != nil {
			return out, err
		}
	}
	r.Action, r.ActionState = "install", "completed"
	if err = saveFail2banManaged(r, "installed", ""); err != nil {
		return out, err
	}
	return out, nil
}

// CheckFail2banManaged is also the systemd ExecStartPre entry. It never writes a
// lock or receipt, so a parent installer may safely wait for the service start.
func CheckFail2banManaged(ctx context.Context, data, scope string) (fail2ban.Managed, error) {
	if err := fail2banManagedRoot(data, scope); err != nil {
		return fail2ban.UnknownManaged(), err
	}
	r, err := loadFail2banManaged(data)
	if err != nil {
		return fail2ban.UnknownManaged(), err
	}
	if r == nil {
		return readFail2banManaged(data), errors.New("没有受管引擎安装登记")
	}
	if r.State != "ready" && r.State != "installed" {
		return r.view(), errors.New("受管引擎安装尚未就绪或正在撤回")
	}
	call, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err = fail2banManagedNoOther(call, data, false); err != nil {
		return r.view(), err
	}
	if err = fail2banManagedEffective(call); err != nil {
		return r.view(), err
	}
	return r.view(), checkFail2banManaged(call, r)
}

// ManageFail2banManaged only controls the dedicated unit admitted above. It
// cannot stop, enable, adopt or replace a system Fail2ban service.
func ManageFail2banManaged(ctx context.Context, data, scope, action string) (fail2ban.Managed, error) {
	return manageFail2banManaged(ctx, data, scope, action, "")
}
func manageFail2banManaged(ctx context.Context, data, scope, action, allowed string) (out fail2ban.Managed, resultErr error) {
	out = fail2ban.UnknownManaged()
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if action == "status" {
		return readFail2banManaged(data), nil
	}
	if action != "start" && action != "stop" && action != "enable" && action != "disable" && action != "rollback" {
		return out, errors.New("未知受管引擎操作")
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(data)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(data, allowed); err != nil {
		return out, err
	}
	r, err := loadFail2banManaged(data)
	if err != nil {
		return out, err
	}
	if r == nil {
		return readFail2banManaged(data), errors.New("没有受管引擎安装登记")
	}
	out = r.view()
	if r.State == "rolled-back" {
		if action == "rollback" {
			return out, nil
		}
		return out, errors.New("受管引擎已经撤回")
	}
	call, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if action == "rollback" {
		// Retain the private configuration, SQLite database, release and audit
		// history. Only the exact owned service unit is removed.
		content := r.unit()
		fileErr := fail2banManagedFile(fail2banManagedUnit, content)
		if fileErr != nil && !os.IsNotExist(fileErr) {
			return out, fileErr
		}
		if err = fail2banManagedOverrides(); err != nil {
			return out, err
		}
		r.Action, r.ActionState = "rollback", "pending"
		if err = saveFail2banManaged(r, "rolling-back", ""); err != nil {
			return out, err
		}
		out = r.view()
		if fileErr == nil {
			if err = fail2banManagedSystemctl(call, "daemon-reload"); err != nil {
				return out, err
			}
			if err = fail2banManagedEffective(call); err != nil {
				return out, err
			}
			if err = fail2banManagedSystemctl(call, "stop", fail2banManagedService); err != nil {
				return out, err
			}
			if err = fail2banManagedStopped(call); err != nil {
				return out, err
			}
			if err = fail2banManagedSystemctl(call, "disable", "--no-reload", fail2banManagedService); err != nil {
				return out, err
			}
			if err = fail2banManagedFile(fail2banManagedUnit, content); err != nil {
				return out, err
			}
			if err = os.Remove(fail2banManagedUnit); err != nil {
				return out, err
			}
		} else {
			if err = fail2banManagedSystemctl(call, "daemon-reload"); err != nil {
				return out, err
			}
			for _, service := range readFail2banServices(call) {
				if service.ID == fail2banManagedService && (!service.Available || service.Load != "not-found" || service.Active != "inactive" || service.MainPID == nil || *service.MainPID != 0) {
					return out, errors.New("服务文件缺失但实际服务仍存在，不能视为撤回")
				}
			}
		}
		dir, openErr := os.Open(filepath.Dir(fail2banManagedUnit))
		if openErr != nil {
			return out, openErr
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil || closeErr != nil {
			return out, errors.Join(syncErr, closeErr)
		}
		if err = fail2banManagedSystemctl(call, "daemon-reload"); err != nil {
			return out, err
		}
		r.ActionState = "completed"
		if err = saveFail2banManaged(r, "rolled-back", "独立服务已撤回；配置、状态库及安装审计予以保留"); err != nil {
			return out, err
		}
		return r.view(), nil
	}
	if r.State != "installed" {
		return out, errors.New("安装尚未完成，请先续办或撤回")
	}
	if err = verifyFail2banManaged(call, r, true); err != nil {
		return out, err
	}
	if err = fail2banManagedEffective(call); err != nil {
		return out, err
	}
	if action == "start" || action == "enable" {
		if err = fail2banManagedNoOther(call, data, false); err != nil {
			return out, err
		}
		if err = checkFail2banManaged(call, r); err != nil {
			return out, err
		}
	}
	args := []string{action}
	if action == "enable" || action == "disable" {
		args = append(args, "--no-reload")
	}
	args = append(args, fail2banManagedService)
	r.Action, r.ActionState = action, "pending"
	if err = saveFail2banManaged(r, "installed", "独立服务操作待核对："+action); err != nil {
		return out, err
	}
	err = fail2banManagedSystemctl(call, args...)
	if err == nil && action == "start" {
		err = waitFail2banManagedLive(call, r)
	}
	if err == nil && action == "stop" {
		err = fail2banManagedStopped(call)
	}
	r.ActionState = "completed"
	message := "最近完成独立服务操作：" + action
	if err != nil {
		r.ActionState = "unknown"
		message = "独立服务操作未确认完成：" + action + "；须核对实际状态"
	}
	if saveErr := saveFail2banManaged(r, "installed", message); saveErr != nil {
		err = errors.Join(err, saveErr)
	}
	if err != nil {
		return r.view(), fmt.Errorf("%s：%w", message, err)
	}
	return r.view(), nil
}
