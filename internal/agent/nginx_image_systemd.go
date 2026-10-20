package agent

import (
	"context"
	"errors"
	"fmt"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
	"os"
	"reflect"
	"strings"
	"time"
)

func nginxImageUnit(id string) string { return "nginxpanel-nginx-image@" + id + ".service" }
func nginxImageHost(ctx context.Context, data, id string) (string, bool, error) {
	if !validID(id) {
		return "", false, errors.New("Nginx 镜像替换服务实例标识无效")
	}
	intent, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return "", false, err
	}
	ready, err := nginxmodules.ReadTrusted("/etc/nginxpanel/install/ready", 64)
	if err != nil || string(ready) != "native-install-v14\n" || !strings.HasPrefix(string(intent), "native-install-v14\n") || !strings.Contains(string(intent), "\ndata="+data+"\n") || !strings.Contains(string(intent), "\npanel_mode=docker\n") || strings.Contains(string(intent), "\nnginx_image=\n") {
		return "", false, errors.New("Nginx 镜像替换缺少已完成的容器面板安装登记")
	}
	name := "/etc/systemd/system/" + nginxImageTemplate
	raw, err := nginxmodules.ReadTrusted(name, 64<<10)
	if err != nil {
		return "", false, err
	}
	command := "ExecStart=/opt/nginxpanel/current/nginxpanel nginx-image-worker --data-dir " + data + " --nginx-image-operation %i"
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			count++
			if line != command {
				return "", false, errors.New("Nginx 镜像替换服务入口与固定登记不一致")
			}
		}
	}
	if count != 1 {
		return "", false, errors.New("Nginx 镜像替换服务入口无效")
	}
	v, err := agentUpgradeProperties(ctx, nginxImageUnit(id), "LoadState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,Type,Restart,KillMode,ActiveState,SubState,MainPID,ControlPID")
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

func dispatchNginxImage(ctx context.Context, id string) error {
	v, err := agentUpgradeProperties(ctx, nginxImageUnit(id), "ActiveState,MainPID,ControlPID")
	if err != nil {
		return err
	}
	if (v["ActiveState"] != "failed" && v["ActiveState"] != "inactive") || v["MainPID"] != "0" || v["ControlPID"] != "0" {
		return errors.New("独立镜像服务仍在运行，不能重复启动")
	}
	if v["ActiveState"] == "failed" {
		if _, err = installationSystemctl(ctx, "reset-failed", nginxImageUnit(id)); err != nil {
			return err
		}
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", nginxImageUnit(id))
	return err
}

// This entry point is invoked only by its registered independent systemd unit.
// A failed continuation remains nonterminal and keeps the original lease held.
func RunNginxImage(ctx context.Context, data, id string) (Record, error) {
	j, unlock, err := nginxImageLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := NginxImageStatus(data, id)
	if err != nil || nginxImageTerminal(r) {
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
		fields := strings.SplitN(line, ":", 3)
		owned = owned || len(fields) == 3 && fields[2] == "/system.slice/"+nginxImageUnit(id)
	}
	if !owned {
		return r, errors.New("Nginx 镜像 worker 必须由独立 systemd 实例运行")
	}
	actual, err := agentUpgradeProperties(ctx, nginxImageUnit(id), "MainPID")
	if err != nil {
		return r, err
	}
	if actual["MainPID"] != fmt.Sprint(os.Getpid()) {
		return r, errors.New("Nginx 镜像 worker 不是原服务主进程")
	}
	w := &nginxImageWorker{j: j, r: r}
	if as := w.r.NginxImage.Authorizations; len(as) > 0 {
		last := &as[len(as)-1]
		if last.ClaimedAt != 0 || last.Request.AuthorizationUntil <= time.Now().Unix() {
			return r, errors.New("Nginx 镜像启动授权已使用或过期，须显式续办")
		}
		access, e := panelUpdateAccess(ctx, j, id, last.Request.Input.MaintenanceID, last.Request.Epoch, false)
		if e != nil {
			return r, e
		}
		last.ClaimedAt = time.Now().Unix()
		if last.ClaimedAt >= last.Request.AuthorizationUntil {
			access()
			return r, errors.New("Nginx 镜像启动授权在领取前过期")
		}
		e = w.save()
		access()
		if e != nil {
			return r, e
		}
	}
	if !r.NginxImage.Rollback {
		forward, cancel := context.WithDeadline(ctx, time.Unix(r.Deadline, 0))
		err = w.forward(forward)
		cancel()
		if err == nil {
			w.r.State, w.r.Stage, w.r.Error = "succeeded", "committed", ""
			return w.r, w.save()
		}
		// Direction is durable before any recovery mutation. Readiness obtained
		// for the candidate can never be reused as original-image confirmation.
		w.r.NginxImage.Rollback = true
		w.r.NginxImage.Failure = panelRestoreError(err)
		w.r.NginxImage.Confirmation = nil
		if saveErr := w.stage("rollback_stopping_agent"); saveErr != nil {
			return w.r, errors.Join(err, saveErr)
		}
	}
	recovery, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err = w.recover(recovery); err != nil {
		w.r.State, w.r.Error = "recovery_required", panelRestoreError(err)
		return w.r, errors.Join(err, w.save())
	}
	if w.r.NginxImage.Touched {
		w.r.State, w.r.Stage = "rolled_back", "compensated"
	} else {
		w.r.State, w.r.Stage = "failed", "rejected"
	}
	w.r.Error = w.r.NginxImage.Failure
	return w.r, w.save()
}
func (w *nginxImageWorker) forward(ctx context.Context) error {
	p := w.r.NginxImage
	i := p.Intent
	if err := w.guard(ctx); err != nil {
		return err
	}
	if err := w.candidate(ctx); err != nil {
		return err
	}
	if !p.Touched {
		c, b, err := w.container(ctx)
		if err != nil {
			return err
		}
		if b.ImageID != i.Before.ImageID || !reflect.DeepEqual(c, i.Container) {
			return errors.New("切换前原 Nginx 代次发生变化")
		}
		actual, err := agentUpgradeObserve(ctx, i.Before.DataDir, w.r.OperationID, i.Agent)
		if err != nil {
			return err
		}
		if actual != i.AgentProcess {
			return errors.New("切换前原 Agent 代次发生变化")
		}
		n := w.nginx(i.Before)
		m, err := w.publication(n)
		if err != nil {
			return err
		}
		if err = n.observe(ctx, m); err != nil {
			return err
		}
		lease, err := probeAgentUpgrade(ctx, i.Before.DataDir, i.Input.MaintenanceID, i.Agent)
		if err != nil {
			return err
		}
		if lease.Epoch != w.r.MaintenanceEpoch {
			return errors.New("切换前原维护代次发生变化")
		}
		p.Touched = true
		if err = w.stage("stopping_agent"); err != nil {
			return err
		}
	}
	return w.runtime(ctx)
}
func (w *nginxImageWorker) recover(ctx context.Context) error {
	if err := w.guard(ctx); err != nil {
		return err
	}
	if err := w.removeCheck(ctx); err != nil {
		return err
	}
	if !w.r.NginxImage.Touched {
		i := w.r.NginxImage.Intent
		return w.confirm(ctx, i.Before, i.BeforeCompose)
	}
	return w.runtime(ctx)
}

// The host root can append a bounded rescue authorization when restarting the
// Agent is necessary to make the managed Web/API workflow available again.
func RescueNginxImage(ctx context.Context, data, id, epoch string) (Record, error) {
	r, err := NginxImageStatus(data, id)
	if err != nil || nginxImageTerminal(r) {
		return r, err
	}
	if len(r.NginxImage.Authorizations) == 0 {
		return r, errors.New("本机 Nginx 镜像事务应使用普通续办入口")
	}
	req := imageupdates.Request{Actor: "local-root", RequestID: secure.ID(), Protocol: Protocol, OperationID: id, Input: nginxImageAPIInput(r.NginxImage.Intent.Input), Sequence: len(r.NginxImage.Authorizations) + 1, Command: "resume", Epoch: epoch, AuthorizationUntil: time.Now().Unix() + 300}
	return resumeNginxImage(ctx, data, id, epoch, &req)
}
