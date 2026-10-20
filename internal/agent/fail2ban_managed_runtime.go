package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

// Isolation excludes site-packages and the working directory. The only added
// import directory is the complete, authenticated, root-owned code asset.
const fail2banManagedServer = "import sys;sys.path.insert(0,sys.argv.pop(1));from fail2ban.client.fail2banserver import exec_command_line;sys.argv[0]='fail2ban-server';exec_command_line(sys.argv)"
const fail2banManagedClient = "import sys;sys.path.insert(0,sys.argv.pop(1));from fail2ban.client.fail2banclient import exec_command_line;sys.argv[0]='fail2ban-client';exec_command_line(sys.argv)"

// Use the same authenticated official compiler as the running engine. Host
// tags are expanded by Fail2ban itself, never by a second Go regex dialect.
const fail2banManagedRegexValue = "import sys;sys.path.insert(0,sys.argv[1]);from fail2ban.server.failregex import FailRegex;print(FailRegex(sys.argv[2],useDns='no').getRegex())"

func (r fail2banManagedRecord) args(client bool, args ...string) []string {
	bootstrap := fail2banManagedServer
	if client {
		bootstrap = fail2banManagedClient
	}
	return append([]string{"-I", "-S", "-B", "-c", bootstrap, r.PackageRoot}, args...)
}
func fail2banManagedExec(ctx context.Context, tool fail2ban.Tool, args []string, budget time.Duration, limit int) ([]byte, error) {
	if !tool.Trusted || tool.Resolved == "" {
		return nil, errors.New("受管引擎程序不可核对")
	}
	call, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(call, tool.Resolved, args...)
	cmd.Args[0] = tool.Path
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1", "PYTHONDONTWRITEBYTECODE=1", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	out, diagnostic := firewallOutput{limit: limit}, firewallOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	if call.Err() != nil {
		return nil, errors.New("受管引擎操作超时或取消，须核对实际状态")
	}
	if out.exceeded || diagnostic.exceeded {
		return nil, errors.New("受管引擎操作输出超限")
	}
	if err != nil {
		return nil, fmt.Errorf("受管引擎固定命令未完成：%w", err)
	}
	return out.data.Bytes(), nil
}
func (r fail2banManagedRecord) python() fail2ban.Tool {
	return fail2ban.Tool{ID: "python3", Path: r.PythonPath, Resolved: r.PythonPath, Trusted: true}
}
func (r fail2banManagedRecord) run(ctx context.Context, client bool, args ...string) ([]byte, error) {
	return fail2banManagedExec(ctx, r.python(), r.args(client, args...), 5*time.Second, 16384)
}
func fail2banManagedSystemctl(ctx context.Context, args ...string) error {
	budget := 20 * time.Second
	if len(args) > 0 && args[0] == "start" {
		budget = 70 * time.Second
	}
	_, err := fail2banManagedExec(ctx, fail2banTool("systemctl"), args, budget, 8192)
	return err
}
func fail2banUnitArg(arg string) string {
	return strconv.Quote(strings.ReplaceAll(strings.ReplaceAll(arg, "%", "%%"), "$", "$$"))
}
func fail2banUnitCommand(args []string) string {
	values := make([]string, len(args))
	for i, arg := range args {
		values[i] = fail2banUnitArg(arg)
	}
	return strings.Join(values, " ")
}
func (r fail2banManagedRecord) startArgs() []string {
	return r.args(false, "-f", "-c", filepath.Join(r.work(), "config"), "-s", fail2banManagedSocket, "-p", "/run/nginxpanel-fail2ban/fail2ban.pid", "start")
}
func (r fail2banManagedRecord) unit() string {
	check := fail2banUnitCommand([]string{r.ManagerPath, "fail2ban-managed-check", "--data-dir", r.DataDir, "--fail2ban-scope", "host"})
	start := fail2banUnitCommand(append([]string{r.PythonPath}, r.startArgs()...))
	stop := fail2banUnitCommand(append([]string{r.PythonPath}, r.args(true, "-c", filepath.Join(r.work(), "config"), "-s", fail2banManagedSocket, "--timeout", "5", "stop")...))
	return "[Unit]\nDescription=NginxPanel managed Fail2ban\nAfter=network.target\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=simple\nUser=root\nGroup=root\nEnvironment=TZ=UTC\nUMask=0077\nRuntimeDirectory=nginxpanel-fail2ban\nRuntimeDirectoryMode=0700\nExecStartPre=" + check + "\nExecStart=" + start + "\nExecStop=" + stop + "\nTimeoutStartSec=60\nTimeoutStopSec=15\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=" + fail2banUnitArg(filepath.Join(r.work(), "state")) + " /run/nginxpanel-fail2ban\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (r fail2banManagedRecord) files() map[string]string {
	return map[string]string{
		fail2banManagedUnit: r.unit(),
		filepath.Join(r.work(), "config", "fail2ban.conf"): "[Definition]\nloglevel = INFO\nlogtarget = STDOUT\nsyslogsocket = auto\nsocket = " + fail2banManagedSocket + "\npidfile = /run/nginxpanel-fail2ban/fail2ban.pid\ndbfile = " + filepath.Join(r.work(), "state", "fail2ban.sqlite3") + "\ndbmaxmatches = 10\ndbpurgeage = 1d\nallowipv6 = auto\n",
		filepath.Join(r.work(), "config", "jail.conf"):     "[DEFAULT]\nenabled = false\nbackend = polling\nusedns = no\nlogencoding = utf-8\nfindtime = 600\nbantime = 600\nmaxretry = 10\n",
	}
}
func fail2banManagedFile(name, content string) error {
	mode := os.FileMode(0600)
	if name == fail2banManagedUnit {
		mode = 0644
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return errors.New("受管文件类型或权限发生变化")
	}
	raw, err := nginxmodules.ReadTrusted(name, 65536)
	if err != nil || string(raw) != content {
		return errors.New("受管文件内容或 root 保护发生变化")
	}
	return nil
}
func writeFail2banManagedFile(name, content string) error {
	if err := fail2banManagedFile(name, content); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := existingRootDirectory(filepath.Dir(name)); err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if name == fail2banManagedUnit {
		mode = 0644
	}
	tmpDir := filepath.Dir(name)
	if base := filepath.Base(name); base == "fail2ban.conf" || base == "jail.conf" {
		// An interrupted write must not leave an extra entry in the strict
		// configuration directory. Staging stays in its private parent.
		tmpDir = filepath.Dir(tmpDir)
	}
	tmp := filepath.Join(tmpDir, "."+filepath.Base(name)+"."+secure.ID()+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.WriteString(content); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	if tmpDir != filepath.Dir(name) {
		staging, err := os.Open(tmpDir)
		if err != nil {
			return err
		}
		syncErr := staging.Sync()
		closeErr := staging.Close()
		return errors.Join(syncErr, closeErr)
	}
	return nil
}
func fail2banManagedOverrides() error {
	for _, dir := range []string{"/etc/systemd/system", "/run/systemd/system", "/run/systemd/transient", "/run/systemd/generator.early", "/run/systemd/generator", "/run/systemd/generator.late", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		if dir != filepath.Dir(fail2banManagedUnit) {
			if _, err := os.Lstat(filepath.Join(dir, fail2banManagedService)); err == nil {
				return errors.New("受管服务名称已被其他 systemd 单元占用")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		for _, suffix := range []string{fail2banManagedService + ".d", "service.d"} {
			if _, err := os.Lstat(filepath.Join(dir, suffix)); err == nil {
				return errors.New("受管服务存在额外 systemd drop-in，须本机核对")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
func verifyFail2banManaged(ctx context.Context, r *fail2banManagedRecord, files bool) error {
	p, err := releases.Installed(ctx, r.releaseInput(), r.PlanID, r.ApprovedAt, r.TrustSHA256)
	if err != nil {
		return err
	}
	_, err = fail2banManagedRelease(p, r.AssetID)
	if err != nil {
		return err
	}
	if p.Plan.ManifestSHA256 != r.ManifestSHA256 || filepath.Join(p.Directory, r.AssetID) != r.PackageRoot {
		return errors.New("受管引擎组件身份发生变化")
	}
	// Installed already verifies every selected asset and its current runtime.
	for name, hash := range map[string]string{r.PythonPath: r.PythonSHA256, r.ManagerPath: r.ManagerSHA256} {
		actual, err := secure.HashRootFile(name, 256<<20)
		if err != nil || actual != hash {
			return errors.New("受管引擎解释器或管理程序发生变化，须重新批准")
		}
	}
	if err = fail2banManagedOverrides(); err != nil {
		return err
	}
	if !files {
		return ctx.Err()
	}
	for name, content := range r.files() {
		if err = fail2banManagedFile(name, content); err != nil {
			return err
		}
	}
	_, bundle, err := selectedFail2banJails(r)
	if err != nil {
		return err
	}
	if err = verifyFail2banJailConfig(r, filepath.Join(r.work(), "config"), bundle); err != nil {
		return err
	}
	return ctx.Err()
}
func checkFail2banManaged(ctx context.Context, r *fail2banManagedRecord) error {
	if err := verifyFail2banManaged(ctx, r, true); err != nil {
		return err
	}
	for _, client := range []bool{false, true} {
		raw, err := r.run(ctx, client, "--version")
		if err != nil || strings.TrimSpace(string(raw)) != "Fail2Ban v"+r.Version {
			return errors.New("受管引擎完整入口或版本无法核对")
		}
	}
	if _, err := r.run(ctx, true, "-c", filepath.Join(r.work(), "config"), "-s", fail2banManagedSocket, "-t"); err != nil {
		return errors.New("官方客户端未能完成受管配置校验")
	}
	return nil
}
func verifyFail2banManagedLive(ctx context.Context, r *fail2banManagedRecord) error {
	b := &fail2banBinding{Service: fail2banManagedService, Socket: fail2banManagedSocket, managed: r}
	before, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return err
	}
	raw, err := r.run(ctx, true, fail2banReadArgs(fail2banManagedSocket, "version")...)
	if err != nil || strings.TrimSpace(string(raw)) != r.Version {
		return errors.New("受管引擎服务端版本未核对")
	}
	raw, err = r.run(ctx, true, fail2banReadArgs(fail2banManagedSocket, "status")...)
	if err != nil {
		return err
	}
	names, err := parseFail2banJails(raw)
	if err != nil {
		return err
	}
	_, bundle, err := selectedFail2banJails(r)
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, name := range fail2banJailNames(bundle) {
		expected[name] = true
	}
	if len(names) != len(expected) {
		return errors.New("受管引擎实际 jail 与登记不一致")
	}
	for _, name := range names {
		if !expected[name.Name] {
			return errors.New("受管引擎包含未登记的 jail")
		}
	}
	after, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return err
	}
	if before.invocation != after.invocation || before.inode != after.inode || *before.view.MainPID != *after.view.MainPID || !os.SameFile(before.file, after.file) {
		return errors.New("受管引擎在核对期间发生变化")
	}
	return verifyFail2banManaged(ctx, r, true)
}

func waitFail2banManagedLive(ctx context.Context, r *fail2banManagedRecord) error {
	call, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	for {
		err := verifyFail2banManagedLive(call, r)
		if err == nil {
			return nil
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-call.Done():
			timer.Stop()
			return fmt.Errorf("受管引擎启动后的实例健康未确认：%w", err)
		case <-timer.C:
		}
	}
}
