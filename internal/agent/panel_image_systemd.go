package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

func panelImageUnit(id string) string { return "nginxpanel-image@" + id + ".service" }

// Reconfirm the original maintenance lease through the registered application
// identity even while the panel container is stopped. It cannot release it.
func PanelImageProbe(ctx context.Context, data, id string) (maintenance.RootStatus, error) {
	if os.Geteuid() != 0 || !validID(id) {
		return maintenance.RootStatus{}, errors.New("镜像维护核对需要宿主机 root 和原维护 UUID")
	}
	helper, err := readAgentProgram()
	if err != nil {
		return maintenance.RootStatus{}, err
	}
	return probeAgentUpgrade(ctx, data, id, helper)
}
func panelImageHost(ctx context.Context, data, id string) (string, bool, error) {
	if !validID(id) {
		return "", false, errors.New("镜像替换服务实例标识无效")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return "", false, err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v12\n" || !strings.HasPrefix(string(intent), "native-install-v12\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\npanel_mode=docker\n") {
		return "", false, errors.New("镜像替换缺少已完成的容器面板安装登记")
	}
	name := "/etc/systemd/system/" + panelImageTemplate
	raw, err := nginxmodules.ReadTrusted(name, 64<<10)
	if err != nil {
		return "", false, err
	}
	command := "ExecStart=/opt/nginxpanel/current/nginxpanel panel-image-worker --data-dir " + data + " --panel-image %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != command {
				return "", false, errors.New("镜像替换服务入口与固定登记不一致")
			}
		}
	}
	if count != 1 {
		return "", false, errors.New("镜像替换服务入口无效")
	}
	v, err := agentUpgradeProperties(ctx, panelImageUnit(id), "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ActiveState")
	if err != nil {
		return "", false, err
	}
	if v["LoadState"] != "loaded" || v["FragmentPath"] != name || v["DropInPaths"] != "" || v["NeedDaemonReload"] != "no" || v["User"] != "root" || v["Group"] != "root" || v["Type"] != "exec" || v["Restart"] != "no" || v["KillMode"] != "mixed" {
		return "", false, errors.New("实际加载的独立镜像服务偏离固定策略")
	}
	switch v["ActiveState"] {
	case "active", "activating", "deactivating", "reloading":
		return secure.Hash(raw), true, nil
	case "inactive", "failed":
		return secure.Hash(raw), false, nil
	default:
		return "", false, errors.New("独立镜像服务状态不明")
	}
}

func RunPanelImage(ctx context.Context, data, id string) (Record, error) {
	j, unlock, err := panelImageLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := PanelImageStatus(data, id)
	if err != nil || panelImageTerminal(r) {
		return r, err
	}
	if _, err = installationExecutable(); err != nil {
		return r, err
	}
	raw, err := panelProcFile("/proc/self/cgroup", 8192)
	if err != nil {
		return r, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		owned = owned || len(parts) == 3 && parts[2] == "/system.slice/"+panelImageUnit(id)
	}
	if !owned {
		return r, errors.New("镜像替换 worker 必须由独立 systemd 实例运行")
	}
	actual, err := agentUpgradeProperties(ctx, panelImageUnit(id), "MainPID")
	if err != nil {
		return r, err
	}
	if actual["MainPID"] != fmt.Sprint(os.Getpid()) {
		return r, errors.New("镜像替换 worker 不是独立服务主进程")
	}
	service, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return r, err
	}
	defer service()
	w := &panelImageWorker{j: j, r: r}
	if !w.r.PanelImage.Rollback {
		forward, cancel := context.WithDeadline(ctx, time.Unix(r.PanelImage.Intent.Deadline, 0))
		err = w.forward(forward)
		cancel()
		if err == nil {
			return w.r, nil
		}
		if panelImageTerminal(w.r) {
			retained, readErr := PanelImageStatus(data, id)
			return retained, errors.Join(err, readErr)
		}
		w.r.PanelImage.Rollback, w.r.PanelImage.Failure = true, panelRestoreError(err)
		if err = w.stage("rollback_stopping"); err != nil {
			return w.r, err
		}
	}
	// Restore the original image even after SIGTERM or the forward deadline. A
	// failed compensation remains nonterminal and keeps maintenance unavailable.
	recovery, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err = w.compensate(recovery); err != nil {
		if panelImageTerminal(w.r) {
			retained, readErr := PanelImageStatus(data, id)
			return retained, errors.Join(err, readErr)
		}
		w.r.State, w.r.Error = "recovery_required", panelRestoreError(err)
		return w.r, errors.Join(err, w.save())
	}
	return w.r, nil
}
