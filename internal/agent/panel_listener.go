package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

func SetPanelListen(data, address string) error { return SetPanelAccess(data, address, "") }

func SetPanelAccess(data, address, protocol string) error {
	if os.Geteuid() != 0 {
		return errors.New("修改管理地址需要本机 root")
	}
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.maintenanceLock()
	if err != nil {
		return err
	}
	defer unlock()
	g := &maintenanceGate{journal: j}
	records, err := g.rawRecords()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Kind == "maintenance.lock" && !(r.State == "succeeded" && r.Stage == "released") {
			return errors.New("存在未结束的维护任务，请沿原任务处理后再修改端口")
		}
	}
	release, err := storage.LockWriter(data, d.GID)
	if err != nil {
		return err
	}
	defer release()
	return panelruntime.SetAccess(data, address, protocol)
}

const panelAccessUnit = "nginxpanel-access-change"

func panelAccessTarget(d panelruntime.Deployment, port int, protocol string) (string, error) {
	if port < 1024 || port > 65535 || (protocol != "https" && protocol != "http") {
		return "", fault.Invalid("端口须为 1024–65535，访问协议须为 HTTP 或 HTTPS")
	}
	host, _, err := net.SplitHostPort(d.Listen)
	if err != nil {
		return "", err
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	if address != d.Listen {
		listener, err := panelruntime.Listen(address)
		if err != nil {
			return "", fault.Conflict("所选端口无法监听，请更换端口")
		}
		listener.Close()
	}
	return address, nil
}

func SchedulePanelAccess(ctx context.Context, data string, port int, protocol string) error {
	if err := panelNativeUnit(data); err != nil {
		return fault.Unavailable("无法修改本机面板的访问设置")
	}
	d, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return err
	}
	address, err := panelAccessTarget(d, port, protocol)
	if err != nil || (address == d.Listen && protocol == d.Protocol()) {
		return err
	}
	systemdRun, err := trustedFile("/usr/bin/systemd-run", true)
	if err != nil {
		return fault.Unavailable("本机无法安排面板重启")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The change runs independently so the requesting panel can be stopped.
	cmd := exec.CommandContext(call, systemdRun, "--quiet", "--collect", "--unit="+panelAccessUnit,
		"--on-active=2s", "--timer-property=AccuracySec=100ms", "--property=Type=oneshot", "--property=TimeoutStartSec=150s",
		"/opt/nginxpanel/current/nginxpanel", "panel-access-worker", "--data-dir", data, "--port", strconv.Itoa(port), "--protocol", protocol)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("could not schedule panel access change", "error", err, "systemd", strings.TrimSpace(string(out)))
		return fault.Conflict("无法安排面板重启，请检查服务状态后重试")
	}
	return nil
}

func ApplyPanelAccess(ctx context.Context, data string, port int, protocol string) error {
	if os.Geteuid() != 0 {
		return errors.New("修改面板访问设置需要本机 root")
	}
	lock, err := unix.Open("/run/nginxpanel-install/lock", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(lock)
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("另一个安装或管理入口修改操作正在执行")
	}
	if err := panelNativeUnit(data); err != nil {
		return err
	}
	before, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return err
	}
	address, err := panelAccessTarget(before, port, protocol)
	if err != nil || (address == before.Listen && protocol == before.Protocol()) {
		return err
	}
	if _, err := installationSystemctl(ctx, "stop", "nginxpanel.service"); err != nil {
		return err
	}
	if err := SetPanelAccess(data, address, protocol); err != nil {
		_, recoverErr := installationSystemctl(ctx, "start", "nginxpanel.service")
		return errors.Join(err, recoverErr)
	}
	if err := startPanelAccess(ctx, address); err != nil {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if _, stopErr := installationSystemctl(rollback, "stop", "nginxpanel.service"); stopErr != nil {
			return errors.Join(err, stopErr)
		}
		if restoreErr := SetPanelAccess(data, before.Listen, before.Protocol()); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		if restartErr := startPanelAccess(rollback, before.Listen); restartErr != nil {
			return errors.Join(err, restartErr)
		}
		return fmt.Errorf("新入口启动失败，已恢复原入口：%w", err)
	}
	return nil
}

func startPanelAccess(ctx context.Context, address string) error {
	if _, err := installationSystemctl(ctx, "start", "nginxpanel.service"); err != nil {
		return err
	}
	probe, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := installationSystemctl(probe, "show", "--property=MainPID", "--value", "nginxpanel.service")
		pid, _ := strconv.Atoi(strings.TrimSpace(raw))
		if err == nil && pid > 1 && panelReadinessListener(probe, pid, address) == nil {
			return nil
		}
		select {
		case <-probe.Done():
			return errors.New("面板未在配置地址开始监听")
		case <-ticker.C:
		}
	}
}
