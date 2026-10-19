package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"nginxpanel/internal/imageupdates"
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
	if err != nil || string(ready) != "native-install-v13\n" || !strings.HasPrefix(string(intent), "native-install-v13\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\npanel_mode=docker\n") {
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
	v, err := agentUpgradeProperties(ctx, panelImageUnit(id), "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ActiveState,SubState,MainPID,ControlPID")
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
		if v["MainPID"] != "0" || v["ControlPID"] != "0" || v["ActiveState"] == "inactive" && v["SubState"] != "dead" || v["ActiveState"] == "failed" && v["SubState"] != "failed" {
			return "", false, errors.New("独立镜像服务的进程尚未停止")
		}
		return secure.Hash(raw), false, nil
	default:
		return "", false, errors.New("独立镜像服务状态不明")
	}
}

func dispatchPanelImage(ctx context.Context, id string) error {
	v, err := agentUpgradeProperties(ctx, panelImageUnit(id), "ActiveState,MainPID,ControlPID")
	if err != nil {
		return err
	}
	if (v["ActiveState"] != "failed" && v["ActiveState"] != "inactive") || v["MainPID"] != "0" || v["ControlPID"] != "0" {
		return errors.New("独立镜像服务仍在运行，不能重复启动")
	}
	if v["ActiveState"] == "failed" {
		if _, err = installationSystemctl(ctx, "reset-failed", panelImageUnit(id)); err != nil {
			return err
		}
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", panelImageUnit(id))
	return err
}

// An explicit local-root rescue remains possible when a failed container leaves
// the Web/API unavailable. It appends the same bounded, durable authorization
// as API resume and can neither replace the original intent nor release it.
func RescuePanelImage(ctx context.Context, data, id, epoch string) (Record, error) {
	r, err := PanelImageStatus(data, id)
	if err != nil || panelImageTerminal(r) {
		return r, err
	}
	if len(r.PanelImage.Authorizations) == 0 {
		return r, errors.New("本机镜像事务应使用普通续办入口")
	}
	req := imageupdates.Request{Actor: "local-root", RequestID: secure.ID(), Protocol: Protocol, OperationID: id, Input: panelImageAPIInput(r.PanelImage.Intent.Input), Sequence: len(r.PanelImage.Authorizations) + 1, Command: "resume", Epoch: epoch, AuthorizationUntil: time.Now().Unix() + 300}
	return resumePanelImage(ctx, data, id, epoch, &req)
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
	if a := w.r.PanelImage.Authorizations; len(a) > 0 {
		last := &a[len(a)-1]
		if last.ClaimedAt != 0 || last.Request.AuthorizationUntil <= time.Now().Unix() {
			return r, errors.New("镜像替换启动授权已使用或过期，须显式续办")
		}
		access, err := panelUpdateAccess(ctx, j, id, last.Request.Input.MaintenanceID, last.Request.Epoch, false)
		if err != nil {
			return r, err
		}
		last.ClaimedAt = time.Now().Unix()
		if last.ClaimedAt >= last.Request.AuthorizationUntil {
			access()
			return r, errors.New("镜像替换授权在领取前过期")
		}
		err = w.save()
		access()
		if err != nil {
			return r, err
		}
	}
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
