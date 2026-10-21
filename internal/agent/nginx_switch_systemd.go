package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"

	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

type nginxSwitchService struct {
	Running bool
	PID     int
}

func switchUnitDigest(ctx context.Context, data, unit string) (string, error) {
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v14\n" {
		return "", errors.New("原生安装尚未完成")
	}
	if err = nativeNginxUnit(ctx, unit, data, "nginxpanel-nginx", false); err != nil {
		return "", err
	}
	return secure.HashRootFile("/etc/systemd/system/"+unit, 64<<10)
}

func switchService(ctx context.Context, r Record, unit string) (nginxSwitchService, error) {
	var out nginxSwitchService
	i := r.NginxSwitch
	data := i.Input.Source.DataDir
	digest, err := switchUnitDigest(ctx, data, unit)
	if err != nil {
		return out, err
	}
	if digest != i.Units[unit] {
		return out, errors.New("原生服务文件已偏离切换快照")
	}
	raw, err := installationSystemctl(ctx, "show", "--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,ActiveState,SubState,MainPID,ControlPID", unit)
	if err != nil {
		return out, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return out, errors.New("原生服务观测格式无效")
		}
		if _, exists := values[key]; exists {
			return out, errors.New("原生服务观测包含重复字段")
		}
		values[key] = value
	}
	group := "root"
	if unit == "nginxpanel-agent.service" {
		group = "nginxpanel-ipc"
	}
	if len(values) != 11 || values["LoadState"] != "loaded" || values["FragmentPath"] != "/etc/systemd/system/"+unit || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" || values["User"] != "root" || values["Group"] != group || values["Type"] != "exec" || values["ControlPID"] != "0" {
		return out, errors.New("systemd 实际加载的服务与切换登记不一致")
	}
	out.PID, err = strconv.Atoi(values["MainPID"])
	if err != nil || out.PID < 0 || out.PID == 1 {
		return out, errors.New("原生服务主进程标识无效")
	}
	if (values["ActiveState"] == "inactive" && values["SubState"] == "dead" || values["ActiveState"] == "failed" && values["SubState"] == "failed") && out.PID == 0 {
		return out, nil
	}
	if values["ActiveState"] != "active" || values["SubState"] != "running" || out.PID == 0 {
		return out, errors.New("原生服务正在转换或状态不明，保留原操作")
	}
	base := "/proc/" + strconv.Itoa(out.PID)
	cgroup, err := panelProcFile(base+"/cgroup", 8192)
	if err != nil {
		return out, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(cgroup)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] == "/system.slice/"+unit {
			owned = true
		}
	}
	if !owned {
		return out, errors.New("主进程不属于已登记的原生服务")
	}
	if unit == "nginxpanel-nginx.service" {
		matched := false
		for _, b := range []string{i.Before.Binary, i.Candidate.Binary} {
			n := &Nginx{DataDir: data, Binary: b}
			if pid, e := n.masterPID(); e == nil && pid == out.PID {
				matched = true
			}
		}
		if !matched {
			return out, errors.New("服务进程不是原 Nginx 或本次候选程序")
		}
	} else {
		executable, e := installationExecutable()
		if e != nil {
			return out, e
		}
		expected, e := os.Stat(executable)
		if e != nil {
			return out, e
		}
		actual, e := os.Stat(base + "/exe")
		if e != nil || !os.SameFile(actual, expected) {
			return out, errors.New("Agent 主进程不是本机固定程序")
		}
		identity, e := user.Lookup("nginxpanel")
		if e != nil {
			return out, e
		}
		uid, e := strconv.Atoi(identity.Uid)
		if e != nil {
			return out, e
		}
		cmdline, e := panelProcFile(base+"/cmdline", 8192)
		if e != nil {
			return out, e
		}
		configured := strings.TrimSuffix(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")
		args, e := agentUpgradeArguments(configured, data, uid)
		if e != nil || args[6] != "--nginx-binding" || !bytes.Equal(cmdline, []byte(strings.Join(args, "\x00")+"\x00")) {
			return out, errors.New("Agent 主进程参数已偏离原生安装")
		}
	}
	out.Running = true
	return out, nil
}

func switchControl(ctx context.Context, j *Journal, r *Record, unit, action, stage string) error {
	state, err := switchService(ctx, *r, unit)
	if err != nil {
		return err
	}
	if err = nginxSwitchStage(ctx, j, r, stage); err != nil {
		return err
	}
	if state.Running == (action == "start") {
		return nil
	}
	if _, err = installationSystemctl(ctx, action, unit); err != nil {
		return err
	}
	state, err = switchService(ctx, *r, unit)
	if err != nil {
		return err
	}
	if state.Running != (action == "start") {
		return errors.New("原生服务控制后未确认目标状态")
	}
	return nil
}
