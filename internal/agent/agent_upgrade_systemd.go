package agent

import (
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

func verifySystemdWorker(ctx context.Context, unit string) error {
	actual, err := agentUpgradeProperties(ctx, unit, "MainPID,ControlGroup")
	if err != nil {
		return err
	}
	group := actual["ControlGroup"]
	// Instantiated services normally live in a systemd-created template slice.
	// Bind to the registered unit's actual cgroup and main process instead of
	// assuming that every service is a direct child of system.slice.
	if actual["MainPID"] != strconv.Itoa(os.Getpid()) || !strings.HasPrefix(group, "/system.slice/") || filepath.Clean(group) != group || filepath.Base(group) != unit {
		return errors.New("独立 worker 不是已登记 systemd 服务的主进程")
	}
	raw, err := panelProcFile("/proc/self/cgroup", 8192)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 && fields[2] == group {
			return nil
		}
	}
	return errors.New("独立 worker 不在已登记 systemd 服务的控制组中")
}

func agentUpgradeUnits(ctx context.Context, data, id string) (string, string, []string, error) {
	var agentHash, workerHash string
	var args []string
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return "", "", nil, err
	}
	if d.Mode != "native" || d.UID != 0 || d.GID != 0 || d.IPCGID != 0 {
		return "", "", nil, errors.New("核心服务未登记为宿主机 root 单服务")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return "", "", nil, err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != nativeInstallationStamp || !strings.HasPrefix(string(intent), nativeInstallationStamp) || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\npanel_mode=native\n") {
		return "", "", nil, errors.New("核心服务缺少已完成的本机安装登记")
	}
	name := "/etc/systemd/system/nginxpanel.service"
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
		actual := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		args, err = nativeCoreArguments(actual, data, d.UID, "/opt/nginxpanel/current/nginxpanel")
		if err != nil {
			return "", "", nil, err
		}
	}
	if count != 1 {
		return "", "", nil, errors.New("核心服务必须只有一个固定执行入口")
	}
	v, err := agentUpgradeProperties(ctx, "nginxpanel.service", "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode")
	if err != nil {
		return "", "", nil, err
	}
	if v["LoadState"] != "loaded" || v["FragmentPath"] != name || v["DropInPaths"] != "" || v["NeedDaemonReload"] != "no" || v["User"] != "root" || v["Group"] != "root" || v["Type"] != "exec" || v["Restart"] != "on-failure" || v["KillMode"] != "control-group" {
		return "", "", nil, errors.New("核心服务的实际 systemd 属性不匹配")
	}
	agentHash = secure.Hash(raw)
	return agentHash, workerHash, args, nil
}

func agentUpgradeObserve(ctx context.Context, data, id string, expected AgentProgram) (AgentProcess, error) {
	var out AgentProcess
	_, _, configured, err := agentUpgradeUnits(ctx, data, id)
	if err != nil {
		return out, err
	}
	if expected.DataDir != data {
		return out, errors.New("核心进程恢复身份不属于当前数据目录")
	}
	v, err := agentUpgradeProperties(ctx, "nginxpanel.service", "ActiveState,SubState,MainPID,ControlPID,InvocationID")
	if err != nil {
		return out, err
	}
	pid, err := strconv.Atoi(v["MainPID"])
	if err != nil || pid < 0 || pid == 1 || v["ControlPID"] != "0" {
		return out, errors.New("核心服务主进程或控制进程不确定")
	}
	if (v["ActiveState"] == "inactive" && v["SubState"] == "dead" || v["ActiveState"] == "failed" && v["SubState"] == "failed") && pid == 0 {
		out.State = "stopped"
		return out, nil
	}
	if v["ActiveState"] != "active" || v["SubState"] != "running" || pid == 0 {
		return out, errors.New("核心服务仍在转换或状态未知")
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
		return out, errors.New("核心进程并非本次确认的程序")
	}
	argv, err := panelProcFile(base+"/cmdline", 8192)
	if err != nil {
		return out, err
	}
	actual := strings.TrimSuffix(strings.ReplaceAll(string(argv), "\x00", " "), " ")
	args, err := nativeCoreArguments(actual, data, 0, expected.binary())
	if err != nil || len(configured) != len(args) {
		return out, errors.New("核心实际进程参数不匹配")
	}
	for index := 1; index < len(args); index++ {
		if args[index] != configured[index] {
			return out, errors.New("核心实际参数偏离固定服务登记")
		}
	}
	cgroup, err := panelProcFile(base+"/cgroup", 8192)
	if err != nil {
		return out, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(cgroup)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		owned = owned || len(parts) == 3 && parts[2] == "/system.slice/nginxpanel.service"
	}
	if !owned {
		return out, errors.New("核心主进程不属于已登记的服务")
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
		return out, errors.New("核心启动时钟缺失")
	}
	fields := strings.Fields(string(stat)[end+2:])
	if len(fields) < 20 {
		return out, errors.New("核心启动时钟无效")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return out, err
	}
	out = AgentProcess{State: "running", BootID: strings.TrimSpace(string(boot)), Invocation: v["InvocationID"], PID: pid, StartTicks: ticks}
	if !agentProcessValid(out) {
		return out, errors.New("核心进程身份无效")
	}
	check, err := agentUpgradeProperties(ctx, "nginxpanel.service", "MainPID,InvocationID")
	if err != nil {
		return out, err
	}
	if check["MainPID"] != v["MainPID"] || check["InvocationID"] != out.Invocation {
		return out, errors.New("核心进程在观测期间变化")
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
	if helper.DataDir != "" {
		if os.Geteuid() != 0 || helper.DataDir != data || !validID(maintenanceID) {
			return out, errors.New("核心维护核对需要 root 与匹配的发布身份")
		}
		if err := checkAgentProgram(helper); err != nil {
			return out, err
		}
		return NewClient(filepath.Join(data, "run", "agent", "agent.sock")).AcquireMaintenance(ctx, maintenance.RootRequest{Protocol: Protocol, OperationID: maintenanceID})
	}
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
