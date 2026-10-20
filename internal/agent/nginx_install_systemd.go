package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
)

type NginxInstallationProbe struct {
	Components components.Overview `json:"components"`
	Runtime    NginxState          `json:"runtime"`
}

func InstallationProbe(ctx context.Context, data string) (NginxInstallationProbe, error) {
	var out NginxInstallationProbe
	c := NewClient(filepath.Join(data, "run", "agent", "agent.sock"))
	var err error
	out.Components, err = c.ReadComponents(ctx)
	if err != nil {
		return out, err
	}
	out.Runtime, err = c.NginxState(ctx)
	return out, err
}
func installationExecutable() (string, error) {
	name, err := os.Executable()
	if err != nil {
		return "", err
	}
	actual, err := trustedFile(name, true)
	if err != nil {
		return "", err
	}
	installed, err := trustedFile("/opt/nginxpanel/current/nginxpanel", true)
	if err != nil {
		return "", err
	}
	if actual != installed {
		return "", errors.New("安装执行器必须使用本机已登记的面板程序")
	}
	return actual, nil
}
func installationUnit(ctx context.Context, unit, data, worker string) error {
	return nativeNginxUnit(ctx, unit, data, worker, true)
}

func nativeNginxUnit(ctx context.Context, unit, data, worker string, firstInstall bool) error {
	if worker != "nginxpanel-nginx" {
		return errors.New("在线原生安装须使用已登记的专用 Nginx 账户")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(intent), "native-install-v14\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || firstInstall && !strings.Contains(string(intent), "\nwithout_nginx=yes\n") {
		return errors.New("本机原生安装意图与目标不一致")
	}
	raw, err := nginxmodules.ReadTrusted("/etc/systemd/system/"+unit, 64<<10)
	if err != nil {
		return err
	}
	expected := "ExecStart=/opt/nginxpanel/current/nginxpanel nginx-runtime --data-dir " + data
	if unit == "nginxpanel-agent.service" {
		identity, e := user.Lookup("nginxpanel")
		if e != nil {
			return e
		}
		expected = "ExecStart=/opt/nginxpanel/current/nginxpanel agent --data-dir " + data + " --allowed-uid " + identity.Uid + " --nginx-binding --nginx-user " + worker + " --nginx-modules /etc/nginxpanel/nginx-modules.json --metrics-scope host --component-scope host --maintenance-scope host"
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != expected {
				return errors.New("本机原生服务执行入口与安装意图不一致")
			}
		}
	}
	if count != 1 {
		return errors.New("本机原生服务执行入口无效")
	}
	fragment, err := installationSystemctl(ctx, "show", "--property=FragmentPath", "--value", unit)
	if err != nil {
		return err
	}
	if strings.TrimSpace(fragment) != "/etc/systemd/system/"+unit {
		return errors.New("systemd 未加载已登记的原生服务")
	}
	return nil
}
func installationSystemctl(ctx context.Context, args ...string) (string, error) {
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	binary, err := trustedFile("/usr/bin/systemctl", true)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(call, binary, append([]string{"--no-ask-password", "--no-pager"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	var out serviceOutput
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err = cmd.Run(); err != nil {
		return "", errors.New("原生专用服务控制未成功，请核对 systemd 日志")
	}
	return out.String(), nil
}
func waitInstallationProbe(ctx context.Context, data string, b nginxruntime.Binding, running bool) (NginxInstallationProbe, error) {
	if b.Owner != "managed" || b.Signed == nil {
		return NginxInstallationProbe{}, errors.New("安装确认缺少签名来源绑定")
	}
	return waitNativeNginxProbe(ctx, data, b, running, "", "")
}

func waitNativeNginxProbe(ctx context.Context, data string, b nginxruntime.Binding, running bool, revision, deployment string) (NginxInstallationProbe, error) {
	return waitNginxInstallationProbe(ctx, data, running, revision, deployment, func(info *nginxruntime.Installation) bool {
		matches := info != nil && info.Owner == b.Owner && info.SHA256 == b.SHA256 && info.Version == b.Version
		if matches && b.Signed != nil {
			matches = info.PlanID == b.Signed.PlanID && info.AssetID == b.Signed.AssetID
		}
		return matches
	})
}
func waitNginxInstallationProbe(ctx context.Context, data string, running bool, revision, deployment string, sourceMatches func(*nginxruntime.Installation) bool) (NginxInstallationProbe, error) {
	var result NginxInstallationProbe
	executable, err := installationExecutable()
	if err != nil {
		return result, err
	}
	identity, err := user.Lookup("nginxpanel")
	if err != nil {
		return result, err
	}
	ipc, err := user.LookupGroup("nginxpanel-ipc")
	if err != nil {
		return result, err
	}
	uid, err := strconv.ParseUint(identity.Uid, 10, 32)
	if err != nil || uid == 0 {
		return result, errors.New("Web 身份无效")
	}
	gid, err := strconv.ParseUint(identity.Gid, 10, 32)
	if err != nil || gid == 0 {
		return result, errors.New("Web 组身份无效")
	}
	ipcGID, err := strconv.ParseUint(ipc.Gid, 10, 32)
	if err != nil || ipcGID == 0 {
		return result, errors.New("IPC 组身份无效")
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		attempt, stop := context.WithTimeout(call, 8*time.Second)
		cmd := exec.CommandContext(attempt, executable, "nginx-install-probe", "--data-dir", data)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(ipcGID)}}}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		cmd.WaitDelay = time.Second
		var output serviceOutput
		cmd.Stdout, cmd.Stderr = &output, io.Discard
		err = cmd.Run()
		stop()
		if err == nil && json.Unmarshal([]byte(output.String()), &result) == nil {
			if sourceMatches(result.Components.Installation) && result.Runtime.Available && result.Runtime.Integrity && !result.Runtime.ExternalChange && result.Runtime.RevisionID == revision && result.Runtime.DeploymentID == deployment && (!running || result.Runtime.Running) {
				return result, nil
			}
		}
		select {
		case <-call.Done():
			return result, errors.New("Agent 组件来源或专用 Nginx 实际发布未确认，保留原操作记录")
		case <-ticker.C:
		}
	}
}
