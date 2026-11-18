package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nginxpanel/internal/launcher"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/panelruntime"
)

type PanelServiceObservation struct {
	Mode       string `json:"mode"`
	State      string `json:"state"`
	BootID     string `json:"boot_id"`
	InstanceID string `json:"instance_id"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	ReleaseID  string `json:"release_id"`
}

func panelProcFile(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(raw)) > limit {
		err = errors.New("面板进程信息超过读取上限")
	}
	return raw, err
}

func panelNativeUnit(data string) error {
	deployment, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return err
	}
	if deployment.Mode != "native" || deployment.UID != 0 || deployment.GID != 0 || deployment.IPCGID != 0 {
		return errors.New("原生核心未登记为宿主机 root 单服务")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil {
		return err
	}
	if string(ready) != nativeInstallationStamp || !strings.HasPrefix(string(intent), nativeInstallationStamp) || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\npanel_mode=native\n") {
		return errors.New("原生面板服务不属于已完成的本机安装")
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/nginxpanel.service", 64<<10)
	if err != nil {
		return err
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			actual := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
			if _, err = nativeCoreArguments(actual, data, deployment.UID, "/opt/nginxpanel/current/nginxpanel"); err != nil {
				return errors.New("原生核心固定启动入口已变化")
			}
		}
	}
	if count != 1 {
		return errors.New("原生核心服务启动入口无效")
	}
	return nil
}

func panelNativeObservation(ctx context.Context, s panelruntime.Snapshot) (PanelServiceObservation, error) {
	o := PanelServiceObservation{Mode: "native", ReleaseID: s.Release.ID}
	if err := panelNativeUnit(s.Deployment.DataDir); err != nil {
		return o, err
	}
	raw, err := installationSystemctl(ctx, "show", "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,ActiveState,MainPID,InvocationID", "nginxpanel.service")
	if err != nil {
		return o, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return o, errors.New("原生面板服务观测格式无效")
		}
		if _, exists := values[key]; exists {
			return o, errors.New("原生面板服务观测包含重复字段")
		}
		values[key] = value
	}
	if len(values) != 9 || values["LoadState"] != "loaded" || values["FragmentPath"] != "/etc/systemd/system/nginxpanel.service" || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["User"] != "root" || values["Group"] != "root" {
		return o, errors.New("systemd 实际加载的核心服务与固定安装不一致")
	}
	boot, err := panelProcFile("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return o, err
	}
	o.BootID = strings.TrimSpace(string(boot))
	if !validID(o.BootID) {
		return o, errors.New("宿主机启动身份无效")
	}
	o.PID, err = strconv.Atoi(values["MainPID"])
	if err != nil || o.PID < 0 || o.PID == 1 {
		return o, errors.New("systemd 核心主进程标识无效")
	}
	switch values["ActiveState"] {
	case "inactive", "failed":
		if o.PID != 0 {
			return o, errors.New("已停止服务仍有核心主进程")
		}
		o.State = "stopped"
		return o, nil
	case "active":
		o.State = "running"
	case "activating", "deactivating":
		o.State = values["ActiveState"]
	default:
		return o, errors.New("原生核心服务处于未知状态")
	}
	if o.PID == 0 {
		return o, nil
	}
	invocation := values["InvocationID"]
	if len(invocation) != 32 {
		return o, errors.New("systemd 核心实例身份缺失")
	}
	o.InstanceID = invocation[:8] + "-" + invocation[8:12] + "-" + invocation[12:16] + "-" + invocation[16:20] + "-" + invocation[20:]
	if !validID(o.InstanceID) {
		return o, errors.New("systemd 核心实例身份无效")
	}
	base := "/proc/" + strconv.Itoa(o.PID)
	process, err := panelProcFile(base+"/status", 16384)
	if err != nil {
		return o, err
	}
	identities := 0
	for _, line := range strings.Split(string(process), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "Uid:" && fields[0] != "Gid:") {
			continue
		}
		if len(fields) != 5 {
			return o, errors.New("核心主进程账户格式无效")
		}
		for _, field := range fields[1:] {
			value, e := strconv.Atoi(field)
			if e != nil || value != 0 {
				return o, errors.New("核心主进程账户不是 root")
			}
		}
		identities++
	}
	if identities != 2 {
		return o, errors.New("核心主进程账户身份缺失")
	}
	live, err := os.Stat(base + "/exe")
	if err != nil {
		return o, err
	}
	cgroup, err := panelProcFile(base+"/cgroup", 8192)
	if err != nil {
		return o, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(cgroup)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] == "/system.slice/nginxpanel.service" {
			owned = true
		}
	}
	if !owned {
		return o, errors.New("面板主进程不属于固定 systemd 服务")
	}
	cmdline, err := panelProcFile(base+"/cmdline", 8192)
	if err != nil {
		return o, err
	}
	if err := validateNativeCoreProcess(s, live, cmdline); err != nil {
		return o, err
	}
	stat, err := panelProcFile(base+"/stat", 8192)
	if err != nil {
		return o, err
	}
	end := strings.LastIndex(string(stat), ") ")
	if end < 0 {
		return o, errors.New("核心进程启动标识无效")
	}
	fields := strings.Fields(string(stat)[end+2:])
	if len(fields) < 20 {
		return o, errors.New("核心进程启动标识缺失")
	}
	o.StartTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil || o.StartTicks == 0 {
		return o, errors.New("核心进程启动标识无效")
	}
	after, err := installationSystemctl(ctx, "show", "--property=MainPID,InvocationID", "nginxpanel.service")
	if err != nil {
		return o, err
	}
	check := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(after), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return o, errors.New("核心进程复核格式无效")
		}
		check[key] = value
	}
	if len(check) != 2 || check["MainPID"] != strconv.Itoa(o.PID) || check["InvocationID"] != invocation {
		return o, errors.New("核心服务实例在观测期间变化")
	}
	return o, nil
}

func validateNativeCoreProcess(s panelruntime.Snapshot, live os.FileInfo, cmdline []byte) error {
	releasePath := filepath.Join(s.Directory, "nginxpanel")
	expected, err := os.Stat(releasePath)
	if err != nil {
		return err
	}
	// systemd can retain the installed entry as argv[0] while /proc/<pid>/exe
	// resolves to the selected release. Check the arguments and inode independently.
	const bootstrapPath = "/opt/nginxpanel/current/nginxpanel"
	executable := releasePath
	argv0, _, _ := strings.Cut(string(cmdline), "\x00")
	if argv0 == bootstrapPath {
		executable = bootstrapPath
	}
	if !os.SameFile(live, expected) {
		if executable != bootstrapPath {
			return errors.New("systemd 主进程不是当前批准的核心程序")
		}
		bootstrap, err := trustedFile(bootstrapPath, true)
		if err != nil {
			return err
		}
		info, err := os.Stat(bootstrap)
		if err != nil {
			return err
		}
		if !os.SameFile(live, info) {
			return errors.New("systemd 主进程不是当前批准的核心程序")
		}
	}
	args, err := nativeCoreArguments(strings.TrimSuffix(strings.ReplaceAll(string(cmdline), "\x00", " "), " "), s.Deployment.DataDir, 0, executable)
	if err != nil || !bytes.Equal(cmdline, []byte(strings.Join(args, "\x00")+"\x00")) {
		return errors.New("核心主进程参数不是固定 core 入口")
	}
	return nil
}

func observePanelService(ctx context.Context, s panelruntime.Snapshot) (PanelServiceObservation, error) {
	if s.Deployment.Mode == "native" {
		return panelNativeObservation(ctx, s)
	}
	status, err := (launcher.Client{DataDir: s.Deployment.DataDir}).Status(ctx)
	o := PanelServiceObservation{Mode: "docker", State: status.State, BootID: status.BootID, InstanceID: status.InstanceID, PID: status.PID, ReleaseID: status.ReleaseID}
	if err != nil {
		return o, err
	}
	if status.State != "running" && status.State != "stopped" && status.State != "starting" && status.State != "stopping" && status.State != "failed" {
		return o, errors.New("launcher 面板进程状态无效")
	}
	if status.PID > 0 && (status.ReleaseID != s.Release.ID || status.Version != s.Release.Version) {
		return o, errors.New("launcher 正在运行其他面板版本")
	}
	return o, nil
}

func PanelServiceStatus(ctx context.Context, data string) (PanelServiceObservation, error) {
	if os.Geteuid() != 0 {
		return PanelServiceObservation{}, errors.New("面板进程查询需要本机 root")
	}
	s, err := panelruntime.Read(data)
	if err != nil {
		return PanelServiceObservation{}, err
	}
	return observePanelService(ctx, s)
}
