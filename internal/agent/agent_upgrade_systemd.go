package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func agentUpgradeUnit(id string) string { return "nginxpanel-agent-upgrade@" + id + ".service" }

func agentUpgradeProperties(ctx context.Context, unit, properties string) (map[string]string, error) {
	raw, err := installationSystemctl(ctx, "show", "--property="+properties, unit)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("Agent 服务属性格式无效或重复")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("Agent 服务属性重复")
		}
		values[key] = value
	}
	if len(values) != len(strings.Split(properties, ",")) {
		return nil, errors.New("Agent 服务属性不完整")
	}
	return values, nil
}

func agentUpgradeUnits(ctx context.Context, data, id string) (string, string, []string, error) {
	var agentHash, workerHash string
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return "", "", nil, err
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return "", "", nil, err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v12\n" || !strings.HasPrefix(string(intent), "native-install-v12\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") {
		return "", "", nil, errors.New("Agent 升级缺少已完成的本机安装登记")
	}
	args := []string{"/opt/nginxpanel/current/nginxpanel", "agent", "--data-dir", data, "--allowed-uid", strconv.Itoa(d.UID), "--nginx-binding", "--nginx-user", "nginxpanel-nginx", "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--metrics-scope", "host", "--component-scope", "host", "--maintenance-scope", "host"}
	for _, spec := range []struct{ template, unit, command, restart, kill, group string }{
		{"nginxpanel-agent.service", "nginxpanel-agent.service", "", "on-failure", "control-group", "nginxpanel-ipc"},
		{agentUpgradeTemplate, agentUpgradeUnit(id), "/opt/nginxpanel/current/nginxpanel agent-upgrade-worker --data-dir " + data + " --agent-upgrade %i", "no", "mixed", "root"},
	} {
		name := "/etc/systemd/system/" + spec.template
		raw, err := nginxmodules.ReadTrusted(name, 64<<10)
		if err != nil {
			return "", "", nil, err
		}
		count := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "ExecStart=") {
				continue
			}
			count++
			actual := strings.TrimPrefix(line, "ExecStart=")
			if spec.template == agentUpgradeTemplate {
				if actual != spec.command {
					return "", "", nil, errors.New("Agent 独立升级服务入口不匹配")
				}
			} else {
				if actual != strings.Join(args, " ") {
					args[6] = "--nginx-container"
					if actual != strings.Join(args, " ") {
						return "", "", nil, errors.New("Agent 服务参数不是已登记的固定入口")
					}
				}
			}
		}
		if count != 1 {
			return "", "", nil, errors.New("Agent 服务必须只有一个固定执行入口")
		}
		v, err := agentUpgradeProperties(ctx, spec.unit, "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode")
		if err != nil {
			return "", "", nil, err
		}
		if v["LoadState"] != "loaded" || v["FragmentPath"] != name || v["DropInPaths"] != "" || v["NeedDaemonReload"] != "no" || v["User"] != "root" || v["Group"] != spec.group || v["Type"] != "exec" || v["Restart"] != spec.restart || v["KillMode"] != spec.kill {
			return "", "", nil, errors.New("Agent 或独立升级服务的实际 systemd 属性不匹配")
		}
		if spec.template == agentUpgradeTemplate {
			workerHash = secure.Hash(raw)
		} else {
			agentHash = secure.Hash(raw)
		}
	}
	return agentHash, workerHash, args, nil
}

func agentUpgradeObserve(ctx context.Context, data, id string, expected AgentProgram) (AgentProcess, error) {
	var out AgentProcess
	_, _, args, err := agentUpgradeUnits(ctx, data, id)
	if err != nil {
		return out, err
	}
	v, err := agentUpgradeProperties(ctx, "nginxpanel-agent.service", "ActiveState,SubState,MainPID,ControlPID,InvocationID")
	if err != nil {
		return out, err
	}
	pid, err := strconv.Atoi(v["MainPID"])
	if err != nil || pid < 0 || pid == 1 || v["ControlPID"] != "0" {
		return out, errors.New("Agent 服务主进程或控制进程不确定")
	}
	if (v["ActiveState"] == "inactive" && v["SubState"] == "dead" || v["ActiveState"] == "failed" && v["SubState"] == "failed") && pid == 0 {
		out.State = "stopped"
		return out, nil
	}
	if v["ActiveState"] != "active" || v["SubState"] != "running" || pid == 0 {
		return out, errors.New("Agent 服务仍在转换或状态未知")
	}
	if err := checkAgentProgram(expected); err != nil {
		return out, err
	}
	base := "/proc/" + strconv.Itoa(pid)
	live, err := os.Stat(base + "/exe")
	if err != nil {
		return out, err
	}
	binary, err := os.Stat(expected.binary())
	if err != nil {
		return out, err
	}
	if !os.SameFile(live, binary) {
		return out, errors.New("Agent 进程并非本次确认的程序")
	}
	argv, err := panelProcFile(base+"/cmdline", 8192)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(argv, []byte(strings.Join(args, "\x00")+"\x00")) {
		return out, errors.New("Agent 实际进程参数不匹配")
	}
	cgroup, err := panelProcFile(base+"/cgroup", 8192)
	if err != nil {
		return out, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(cgroup)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		owned = owned || len(parts) == 3 && parts[2] == "/system.slice/nginxpanel-agent.service"
	}
	if !owned {
		return out, errors.New("Agent 主进程不属于已登记的服务")
	}
	boot, err := panelProcFile("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return out, err
	}
	stat, err := panelProcFile(base+"/stat", 8192)
	if err != nil {
		return out, err
	}
	end := strings.LastIndex(string(stat), ") ")
	if end < 0 {
		return out, errors.New("Agent 启动时钟缺失")
	}
	fields := strings.Fields(string(stat)[end+2:])
	if len(fields) < 20 {
		return out, errors.New("Agent 启动时钟无效")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return out, err
	}
	out = AgentProcess{State: "running", BootID: strings.TrimSpace(string(boot)), Invocation: v["InvocationID"], PID: pid, StartTicks: ticks}
	if !agentProcessValid(out) {
		return out, errors.New("Agent 进程身份无效")
	}
	check, err := agentUpgradeProperties(ctx, "nginxpanel-agent.service", "MainPID,InvocationID")
	if err != nil {
		return out, err
	}
	if check["MainPID"] != v["MainPID"] || check["InvocationID"] != out.Invocation {
		return out, errors.New("Agent 进程在观测期间变化")
	}
	return out, nil
}

// This fixed helper runs as the installed API account; root is not added to
// the Agent's Unix peer allowlist merely for an upgrade health check.
func AgentUpgradeProbe(ctx context.Context, data, maintenanceID string) (maintenance.RootStatus, error) {
	if os.Geteuid() == 0 || !validID(maintenanceID) {
		return maintenance.RootStatus{}, errors.New("Agent 就绪辅助入口仅供专用非 root 身份使用")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return maintenance.RootStatus{}, err
	}
	return NewClient(filepath.Join(data, "run", "agent", "agent.sock")).AcquireMaintenance(ctx, maintenance.RootRequest{Protocol: Protocol, OperationID: maintenanceID})
}
func probeAgentUpgrade(ctx context.Context, data, maintenanceID string, helper AgentProgram) (maintenance.RootStatus, error) {
	var out maintenance.RootStatus
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return out, err
	}
	if err = checkAgentProgram(helper); err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, helper.binary(), "agent-upgrade-probe", "--data-dir", data, "--maintenance-id", maintenanceID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(d.UID), Gid: uint32(d.GID), Groups: []uint32{uint32(d.IPCGID)}}}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var output serviceOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err = cmd.Run(); err != nil {
		return out, errors.New("Agent 未能以登记协议响应独立维护核对")
	}
	if len(output.String()) > 8192 || json.Unmarshal([]byte(output.String()), &out) != nil || !out.Available || out.ID != maintenanceID || out.Phase != "held" || out.Busy != 0 || !validID(out.Epoch) {
		return out, errors.New("Agent 就绪回执不属于原维护会话或仍有未排空任务")
	}
	return out, nil
}
