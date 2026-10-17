package agent

import (
	"context"
	"regexp"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/releases"
)

var fail2banPythonPath = regexp.MustCompile(`^/(usr/)?bin/python3(\.[0-9]{1,2})?$`)
var fail2banPackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+_.:-]{0,127}$`)
var fail2banPackageVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+_.:~%-]{0,127}$`)

var fail2banPythonModules = releases.SystemPythonModules()

func readFail2banPython(ctx context.Context) fail2ban.Python {
	out := fail2ban.Python{Executable: fail2banTool("python3"), Modules: []fail2ban.Module{}, Package: fail2ban.Package{Reason: "尚未核对软件包归属"}, Reason: "系统 Python 不可用或无法隔离读取"}
	if !out.Executable.Trusted {
		return out
	}
	probe, err := releases.InspectSystemPython(ctx)
	if err != nil || probe.Resolved != out.Executable.Resolved {
		out.Reason = "固定系统 Python 隔离探测失败或解释器已变化"
		return out
	}
	ready := probe.Check(releases.PythonRuntime{Implementation: "cpython", MinimumMinor: 9, MaximumMinor: 14}) == nil
	out.Version, out.SQLiteVersion, out.StandardLibrary = probe.VersionString(), probe.SQLiteVersion, &ready
	for _, module := range probe.Modules {
		out.Modules = append(out.Modules, fail2ban.Module{Name: module.Name, Available: module.Available})
	}
	out.Reason = "标准库和兼容范围探测不替代所选签名组件的安装批准及完整启动核对"
	if !ready {
		out.Reason = "系统 Python 版本、运行模式、标准库或 SQLite 能力不满足受管引擎要求"
	}
	out.Package = readFail2banPythonPackage(ctx, out.Executable.Resolved)
	return out
}

func readFail2banPythonPackage(ctx context.Context, path string) fail2ban.Package {
	out := fail2ban.Package{Reason: "系统包归属或版本未知；不据此批准组件接入"}
	if query := fail2banTool("dpkg-query"); query.Trusted {
		raw, err := fail2banRun(ctx, query, []string{"-S", path}, 4096)
		if err != nil {
			return out
		}
		line := strings.TrimSpace(string(raw))
		owner, found := strings.CutSuffix(line, ": "+path)
		if !found || !fail2banPackageName.MatchString(owner) {
			return out
		}
		raw, err = fail2banRun(ctx, query, []string{"-W", "-f=${binary:Package}\t${Version}\n", owner}, 4096)
		if err != nil {
			return out
		}
		name, version, found := strings.Cut(strings.TrimSpace(string(raw)), "\t")
		if !found || !fail2banPackageName.MatchString(name) || !fail2banPackageVersion.MatchString(version) {
			return out
		}
		return fail2ban.Package{Available: true, Manager: "dpkg", Name: name, Version: version}
	}
	if query := fail2banTool("rpm"); query.Trusted {
		raw, err := fail2banRun(ctx, query, []string{"-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path}, 4096)
		if err != nil {
			return out
		}
		name, version, found := strings.Cut(strings.TrimSpace(string(raw)), "\t")
		if !found || !fail2banPackageName.MatchString(name) || !fail2banPackageVersion.MatchString(version) {
			return out
		}
		return fail2ban.Package{Available: true, Manager: "rpm", Name: name, Version: version}
	}
	return out
}
