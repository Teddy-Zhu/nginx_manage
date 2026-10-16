package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/secure"
)

const fail2banPythonKind = "nginx.fail2ban-python"
const fail2banPythonLimit int64 = 1 << 30

var errFail2banPythonBusy = errors.New("系统包管理器仍有进行中的操作")

type fail2banPythonPlan struct {
	Schema        int                 `json:"schema"`
	Plan          fail2ban.PythonPlan `json:"plan"`
	Configuration string              `json:"configuration"`
	Installed     string              `json:"installed"`
	Tools         map[string]string   `json:"tools"`
}
type fail2banPythonIntent struct {
	Request        fail2ban.PythonTaskRequest `json:"request"`
	Plan           fail2banPythonPlan         `json:"plan"`
	Sent           bool                       `json:"sent"`
	Submission     string                     `json:"submission"`
	ExecutionError string                     `json:"execution_error"`
	Python         fail2ban.Python            `json:"python"`
}
type Fail2banPythonOptions struct {
	DataDir, Scope, OperationID, PlanID string
	Refresh, Confirm                    bool
}

func fail2banPythonDir(data string) string { return filepath.Join(fail2banBindingDir(data), "python") }
func fail2banPythonJournal(data string) *Journal {
	return &Journal{Dir: filepath.Join(data, "agent", "operations")}
}

// The program, working directory, environment and arguments are all selected
// internally. Native package tools retain their own locks and verification.
func fail2banPackageRun(ctx context.Context, tool fail2ban.Tool, args []string, dir string, input []byte, budget time.Duration, limit int) ([]byte, error) {
	if !tool.Trusted || tool.Resolved == "" {
		return nil, errors.New("系统包程序未通过 root 路径核对")
	}
	call, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(call, tool.Resolved, args...)
	cmd.Args[0] = tool.Path
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1", "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	out, diagnostic := firewallOutput{limit: limit}, firewallOutput{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	if call.Err() != nil {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil, errors.New("系统包操作超时或中断，可能需要原生包管理器恢复；须查询原操作，不会自动重发")
	}
	if out.exceeded || diagnostic.exceeded {
		return nil, errors.New("系统包操作输出超过限制，须核对原操作")
	}
	if err != nil {
		return out.data.Bytes(), fmt.Errorf("系统包程序未完成（%s），详见系统包日志", err)
	}
	return out.data.Bytes(), nil
}
func fail2banPackageSource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Opaque != "" || len(raw) > 4096 {
		return "", errors.New("系统包来源须为已配置的 HTTP(S) 软件仓库")
	}
	u.User = nil
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String(), nil
}
func fail2banPythonHost() (string, string, error) {
	if _, err := trustedFile("/etc/os-release", false); err != nil {
		return "", "", err
	}
	host := platform.Detect()
	supported := host.OS == "debian" && (host.Version == "12" || host.Version == "13") || host.OS == "ubuntu" && (host.Version == "22.04" || host.Version == "24.04" || host.Version == "26.04") || host.OS == "centos" && (host.Version == "9" || host.Version == "10")
	if !supported || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", "", errors.New("当前发行版或架构未纳入固定 Python 系统包适配")
	}
	if host.OS == "centos" {
		raw, err := nginxmodules.ReadTrusted("/etc/centos-release", 4096)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(raw)), "CentOS Stream release "+host.Version) {
			return "", "", errors.New("仅接入 CentOS Stream 9/10 的系统包管理器")
		}
	}
	return host.OS, host.Version, nil
}
func fail2banPythonConfiguration(manager string) (string, error) {
	paths := []string{"/etc/os-release"}
	if manager == "apt" {
		paths = append(paths, "/etc/apt")
	} else {
		paths = append(paths, "/etc/dnf", "/etc/yum.repos.d", "/etc/yum.conf")
	}
	values := map[string]string{}
	total := 0
	var visit func(string) error
	visit = func(path string) error {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			values[path] = "absent"
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err = existingRootDirectory(path); err != nil {
				return err
			}
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(entries) > 256 {
				return errors.New("系统包配置目录条目超限")
			}
			for _, entry := range entries {
				if err = visit(filepath.Join(path, entry.Name())); err != nil {
					return err
				}
			}
			return nil
		}
		resolved, err := trustedFile(path, false)
		if err != nil {
			return err
		}
		raw, err := nginxmodules.ReadTrusted(resolved, 1<<20)
		if err != nil {
			return err
		}
		if manager == "apt" && (strings.HasSuffix(path, ".list") || strings.HasSuffix(path, ".sources")) && fail2banAPTInsecureSource(raw) {
			return errors.New("APT 源配置关闭了来源或有效期校验，须由本机管理员复核")
		}
		total += len(raw)
		if total > 4<<20 || len(values) >= 512 {
			return errors.New("系统包配置材料超限")
		}
		values[path] = resolved + ":" + secure.Hash(raw)
		return nil
	}
	for _, path := range paths {
		if err := visit(path); err != nil {
			return "", err
		}
	}
	raw, _ := json.Marshal(values)
	return secure.Hash(raw), nil
}
func fail2banPythonToolIdentity(manager string) (map[string]string, error) {
	names := []string{"apt-get", "apt-cache", "dpkg", "dpkg-query", "dpkg-deb"}
	if manager == "dnf" {
		names = []string{"rpm", "dnf"}
	}
	out := map[string]string{}
	for _, name := range names {
		tool := fail2banTool(name)
		if !tool.Trusted {
			return nil, errors.New("缺少受信系统包程序：" + name)
		}
		hash, err := secure.HashRootFile(tool.Resolved, 128<<20)
		if err != nil {
			return nil, err
		}
		out[name] = tool.Resolved + ":" + hash
	}
	if manager == "dnf" {
		tool, err := fail2banDNFPython()
		if err != nil {
			return nil, err
		}
		hash, err := secure.HashRootFile(tool.Resolved, 128<<20)
		if err != nil {
			return nil, err
		}
		out["dnf-python"] = tool.Resolved + ":" + hash
	}
	return out, nil
}
func validFail2banPythonPlan(p fail2banPythonPlan) error {
	if p.Schema != 1 || !fail2banDigest.MatchString(p.Plan.ID) || p.Plan.At <= 0 || p.Plan.ExpiresAt != p.Plan.At+3600 || (p.Plan.Manager != "apt" && p.Plan.Manager != "dnf") || p.Plan.Architecture != "amd64" && p.Plan.Architecture != "arm64" || len(p.Plan.Packages) == 0 || len(p.Plan.Packages) > 64 || !fail2banDigest.MatchString(p.Configuration) || !fail2banDigest.MatchString(p.Installed) || len(p.Tools) == 0 {
		return errors.New("Python 系统包计划合同无效")
	}
	copy := p
	copy.Plan.ID = ""
	raw, _ := json.Marshal(copy)
	if secure.Hash(raw) != p.Plan.ID {
		return errors.New("Python 系统包计划摘要不一致")
	}
	var download, installed int64
	seen := map[string]bool{}
	files := map[string]bool{}
	hasPython := false
	nativeArch, independent := "amd64", "all"
	if p.Plan.Architecture == "arm64" {
		nativeArch = "arm64"
	}
	if p.Plan.Manager == "dnf" {
		nativeArch, independent = "x86_64", "noarch"
		if p.Plan.Architecture == "arm64" {
			nativeArch = "aarch64"
		}
	}
	for _, pkg := range p.Plan.Packages {
		source, err := fail2banPackageSource(pkg.Source)
		key := pkg.Name + ":" + pkg.Architecture
		if err != nil || source != pkg.Source || !fail2banPackageName.MatchString(pkg.Name) || strings.Contains(pkg.Name, ":") || !fail2banPackageVersion.MatchString(pkg.Version) || pkg.Architecture != nativeArch && pkg.Architecture != independent || !fail2banDigest.MatchString(pkg.SHA256) || pkg.DownloadBytes <= 0 || pkg.DownloadBytes > 128<<20 || pkg.InstalledBytes <= 0 || pkg.InstalledBytes > fail2banPythonLimit || len(pkg.Repository) > 256 || seen[key] {
			return errors.New("Python 系统包条目无效")
		}
		if p.Plan.Manager == "apt" {
			if !fail2banAPTArchiveName.MatchString(pkg.Filename) || files[pkg.Filename] {
				return errors.New("Python 归档文件名无效或重复")
			}
			files[pkg.Filename] = true
		} else if pkg.Filename != "" {
			return errors.New("DNF 包不接受外部归档路径")
		}
		hasPython = hasPython || pkg.Name == "python3"
		seen[key] = true
		download += pkg.DownloadBytes
		installed += pkg.InstalledBytes
	}
	if !hasPython || download != p.Plan.DownloadBytes || installed != p.Plan.InstalledBytes || download > fail2banPythonLimit || installed > fail2banPythonLimit {
		return errors.New("Python 系统包资源计划无效")
	}
	return nil
}
func fail2banPythonDecode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("Python 系统包材料格式无效")
	}
	return nil
}

func PlanFail2banPython(ctx context.Context, in Fail2banPythonOptions) (fail2ban.PythonPlan, error) {
	var out fail2ban.PythonPlan
	if err := fail2banManagedRoot(in.DataDir, in.Scope); err != nil {
		return out, err
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(in.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(in.DataDir, ""); err != nil {
		return out, err
	}
	p, err := planFail2banPython(ctx, in.DataDir, in.Refresh)
	if err != nil {
		return out, err
	}
	if err = storeFail2banPythonPlan(in.DataDir, p); err != nil {
		return out, err
	}
	return p.Plan, nil
}
func storeFail2banPythonPlan(data string, p fail2banPythonPlan) error {
	if err := validFail2banPythonPlan(p); err != nil {
		return err
	}
	dir := filepath.Join(fail2banPythonDir(data), "plans")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) >= 256 {
		return errors.New("Python 系统包计划数量已达上限，须本机维护")
	}
	if err = rootJSONWrite(filepath.Join(dir, p.Plan.ID+".json"), p, 128<<10); err != nil {
		return err
	}
	return nil
}
func planFail2banPython(ctx context.Context, data string, refresh bool) (fail2banPythonPlan, error) {
	var out fail2banPythonPlan
	registered, err := loadFail2banManaged(data)
	if err != nil {
		return out, err
	}
	if registered != nil && registered.State != "rolled-back" {
		return out, errors.New("已有受管引擎安装登记，不通过依赖安装更换其 Python")
	}
	if err := fail2banManagedNoOther(ctx, data, true); err != nil {
		return out, err
	}
	python := readFail2banPython(ctx)
	if python.Executable.Present == nil || *python.Executable.Present {
		return out, errors.New("已有或无法完整核对系统 Python；不通过安装替换、修复或降级解释器，请先诊断现有能力")
	}
	osName, version, err := fail2banPythonHost()
	if err != nil {
		return out, err
	}
	manager := "apt"
	if osName == "centos" {
		manager = "dnf"
	}
	configuration, err := fail2banPythonConfiguration(manager)
	if err != nil {
		return out, err
	}
	tools, err := fail2banPythonToolIdentity(manager)
	if err != nil {
		return out, err
	}
	if err = fail2banPythonPackageIdle(manager); err != nil {
		return out, err
	}
	var packages []fail2ban.PythonPackage
	var installed string
	if manager == "apt" {
		packages, installed, err = planFail2banAPT(ctx, refresh)
	} else {
		packages, installed, err = planFail2banDNF(ctx, refresh)
	}
	if err != nil {
		return out, err
	}
	after, err := fail2banPythonConfiguration(manager)
	if err != nil {
		return out, err
	}
	if after != configuration {
		return out, ErrExternalChange
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name+":"+packages[i].Architecture < packages[j].Name+":"+packages[j].Architecture
	})
	now := time.Now().Unix()
	out = fail2banPythonPlan{Schema: 1, Configuration: configuration, Installed: installed, Tools: tools, Plan: fail2ban.PythonPlan{At: now, ExpiresAt: now + 3600, OS: osName, Version: version, Architecture: runtime.GOARCH, Manager: manager, Packages: packages, Impacts: []string{"仅为缺失的系统 Python 新增所列包及必要依赖；不升级、降级、删除或替换已有软件包", "软件仓库沿用现有 root 配置，安装保留原生锁与签名检查；不新增仓库、导入密钥或执行 pip", "系统包维护脚本及既有包管理器钩子可能运行；不安装或启动 Fail2ban，Python 系统包不随组件撤回自动卸载"}}}
	for _, pkg := range packages {
		out.Plan.DownloadBytes += pkg.DownloadBytes
		out.Plan.InstalledBytes += pkg.InstalledBytes
	}
	raw, _ := json.Marshal(out)
	out.Plan.ID = secure.Hash(raw)
	return out, validFail2banPythonPlan(out)
}
