package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/nginxmodules"
)

const fail2banPythonWorkerTemplate = "nginxpanel-fail2ban-python@.service"

func fail2banPythonWorkerName(id string) string {
	return "nginxpanel-fail2ban-python@" + id + ".service"
}

// Package managers need the host filesystem, whereas the long-lived Agent
// deliberately has a read-only system view. Only an admitted journal UUID can
// enter this fixed, separately registered executor; no command is supplied by
// the API or inherited from the Agent's namespace.
func fail2banPythonWorkerUnit(ctx context.Context, data, id string) error {
	if !validID(id) {
		return errors.New("Python 依赖执行操作 UUID 无效")
	}
	if _, err := installationExecutable(); err != nil {
		return err
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v14\n" || !strings.HasPrefix(string(intent), "native-install-v14\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") {
		return errors.New("Python 依赖执行器缺少当前数据目录的安装登记")
	}
	name := "/etc/systemd/system/" + fail2banPythonWorkerTemplate
	raw, err := nginxmodules.ReadTrusted(name, 64<<10)
	if err != nil {
		return err
	}
	expected := "ExecStart=/opt/nginxpanel/current/nginxpanel fail2ban-python-worker --data-dir " + data + " --fail2ban-operation %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != expected {
				return errors.New("Python 依赖执行器不是固定操作入口")
			}
		}
	}
	if count != 1 {
		return errors.New("Python 依赖执行器须只有一个固定入口")
	}
	unit := fail2banPythonWorkerName(id)
	values, err := agentUpgradeProperties(ctx, unit, "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ProtectSystem,NoNewPrivileges")
	if err != nil {
		return err
	}
	if values["LoadState"] != "loaded" || values["FragmentPath"] != name || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["User"] != "root" || values["Group"] != "root" || values["Type"] != "exec" || values["Restart"] != "no" || values["KillMode"] != "mixed" || values["ProtectSystem"] != "no" || values["NoNewPrivileges"] != "yes" {
		return errors.New("Python 依赖执行服务的实际入口、权限或挂载策略变化")
	}
	// systemctl omits empty execution arrays, even with --all. Validate them
	// separately from scalar properties, and reject every additional command.
	commands := "ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost"
	extra, err := installationSystemctl(ctx, "show", "--property="+commands, unit)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(extra), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.Contains(","+commands+",", ","+key+",") || value != "" {
			return errors.New("Python 依赖执行服务包含额外命令")
		}
	}
	return nil
}

func startFail2banPythonWorker(ctx context.Context, data, id string) error {
	if err := fail2banPythonWorkerUnit(ctx, data, id); err != nil {
		return err
	}
	unit := fail2banPythonWorkerName(id)
	values, err := agentUpgradeProperties(ctx, unit, "ActiveState,Job")
	if err != nil {
		return err
	}
	if job := values["Job"]; job != "" {
		n, err := strconv.ParseUint(job, 10, 32)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != job {
			return errors.New("Python 依赖执行服务作业状态无法核对")
		}
		return nil
	}
	if values["ActiveState"] == "active" || values["ActiveState"] == "activating" || values["ActiveState"] == "deactivating" {
		return nil
	}
	if values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" {
		return errors.New("Python 依赖执行服务状态无法核对")
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", unit)
	return err
}

func RunFail2banPythonWorker(ctx context.Context, data, id string) error {
	if err := fail2banManagedRoot(data, "host"); err != nil {
		return err
	}
	if err := fail2banPythonWorkerUnit(ctx, data, id); err != nil {
		return err
	}
	if err := verifySystemdWorker(ctx, fail2banPythonWorkerName(id)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	// Follow the same host -> binding lock order as all Fail2ban writers.
	// The durable pending request also blocks Nginx/maintenance admission.
	unlock, err := fail2banHostSyncLocks(data)
	if err != nil {
		return err
	}
	defer unlock()
	p := &fail2banPythonTasks{server: &Server{DataDir: data, Journal: &Journal{Dir: filepath.Join(data, "agent", "operations")}}}
	r, err := p.record(id)
	if err != nil {
		return err
	}
	if r.State == "succeeded" || r.State == "failed" {
		return nil
	}
	if r.Kind == fail2banPythonKind {
		_, err = runFail2banPython(ctx, data, &r)
		return err
	}
	return p.runPlan(ctx, &r)
}
