package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

var fail2banAPTInst = regexp.MustCompile(`^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) \(([^ ]+) .+\)$`)
var fail2banAPTSummary = regexp.MustCompile(`^0 upgraded, ([0-9]+) newly installed, 0 to remove and [0-9]+ not upgraded\.$`)

const fail2banAPTArchivePattern = `[a-zA-Z0-9+_.:%~=-]+\.deb`

var fail2banAPTArchiveName = regexp.MustCompile(`^` + fail2banAPTArchivePattern + `$`)
var fail2banAPTURI = regexp.MustCompile(`^'([^'\r\n]+)' (` + fail2banAPTArchivePattern + `) ([0-9]+) SHA256:([0-9a-f]{64})$`)
var fail2banAPTWeakOption = regexp.MustCompile(`(?i)(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*[=:]\s*["']?\s*(yes|true|on|enabled|1)\b|check-valid-until\s*[=:]\s*["']?\s*(no|false|off|disabled|0)\b`)

func fail2banAPTInsecureSource(raw []byte) bool {
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		lines = append(lines, line)
	}
	return fail2banAPTWeakOption.MatchString(strings.Join(lines, "\n"))
}

func fail2banAPTArgs() []string {
	return []string{"-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowWeakRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "Acquire::Check-Valid-Until=true", "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::Retries=0", "-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30", "-o", "Dpkg::Use-Pty=0", "-o", "DPkg::Lock::Timeout=0"}
}
func fail2banAPTCommand(ctx context.Context, name string, args []string, dir string, budget time.Duration, limit int) ([]byte, error) {
	return fail2banPackageRun(ctx, fail2banTool(name), args, dir, nil, budget, limit)
}
func fail2banAPTInstalled(ctx context.Context) (string, error) {
	raw, err := fail2banAPTCommand(ctx, "dpkg", []string{"--audit"}, "/", 10*time.Second, 64<<10)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(raw)) != "" {
		return "", errors.New("系统 dpkg 存在未完成或损坏的软件包，须先通过原生包管理器恢复")
	}
	raw, err = fail2banAPTCommand(ctx, "dpkg-query", []string{"-W", "-f=${binary:Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n"}, "/", 10*time.Second, 16<<20)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || len(lines) > 100000 {
		return "", errors.New("系统 dpkg 清单无法完整核对")
	}
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || !fail2banPackageName.MatchString(fields[0]) || !fail2banServiceWord.MatchString(fields[1]) || !fail2banPackageVersion.MatchString(fields[2]) || len(fields[3]) != 3 {
			return "", errors.New("系统 dpkg 清单格式未知")
		}
		// Residual configuration is harmless; unpacked, half configured and trigger
		// pending packages must be resolved before adding an optional dependency.
		if fields[3] != "ii " && fields[3] != "rc " && fields[3] != "hi " {
			return "", errors.New("系统 dpkg 仍有待处理状态，不启动额外安装")
		}
	}
	sort.Strings(lines)
	return secure.Hash([]byte(strings.Join(lines, "\n"))), nil
}
func planFail2banAPT(ctx context.Context, refresh bool) ([]fail2ban.PythonPackage, string, error) {
	before, err := fail2banAPTInstalled(ctx)
	if err != nil {
		return nil, "", err
	}
	if refresh {
		args := append(fail2banAPTArgs(), "-o", "APT::Update::Error-Mode=any", "update")
		if _, err = fail2banAPTCommand(ctx, "apt-get", args, "/", 3*time.Minute, 1<<20); err != nil {
			return nil, "", err
		}
	}
	args := append(fail2banAPTArgs(), "--simulate", "--no-install-recommends", "--no-remove", "--no-upgrade", "install", "python3")
	raw, err := fail2banAPTCommand(ctx, "apt-get", args, "/", 30*time.Second, 512<<10)
	if err != nil {
		return nil, "", errors.New("无法从现有 APT 索引解析最小 Python 计划；可明确刷新索引后再生成计划")
	}
	type selected struct{ name, version string }
	selectedPackages := []selected{}
	count := -1
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "Inst ") {
			match := fail2banAPTInst.FindStringSubmatch(line)
			if match == nil || !fail2banPackageVersion.MatchString(match[2]) {
				return nil, "", errors.New("Python 计划包含已有软件包升级、替换或无法识别的动作")
			}
			selectedPackages = append(selectedPackages, selected{match[1], match[2]})
		}
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") {
			return nil, "", errors.New("Python 计划需要删除已有软件包，拒绝执行")
		}
		if match := fail2banAPTSummary.FindStringSubmatch(line); match != nil {
			count, _ = strconv.Atoi(match[1])
		}
	}
	if len(selectedPackages) == 0 || len(selectedPackages) > 64 || count != len(selectedPackages) {
		return nil, "", errors.New("APT 计划不是可完整核对的纯新增事务；不修复或重装已有解释器")
	}
	out := make([]fail2ban.PythonPackage, 0, len(selectedPackages))
	for _, item := range selectedPackages {
		pkg, err := fail2banAPTMetadata(ctx, item.name, item.version)
		if err != nil {
			return nil, "", err
		}
		out = append(out, pkg)
	}
	after, err := fail2banAPTInstalled(ctx)
	if err != nil {
		return nil, "", err
	}
	if before != after {
		return nil, "", ErrExternalChange
	}
	return out, before, nil
}
func fail2banAPTMetadata(ctx context.Context, name, version string) (fail2ban.PythonPackage, error) {
	var out fail2ban.PythonPackage
	raw, err := fail2banAPTCommand(ctx, "apt-cache", []string{"show", name + "=" + version}, "/", 10*time.Second, 256<<10)
	if err != nil {
		return out, err
	}
	var selected map[string]string
	for _, block := range strings.Split(strings.TrimSpace(string(raw)), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, ok := strings.Cut(line, ": ")
			if !ok {
				return out, errors.New("APT 软件包元数据格式未知")
			}
			if _, duplicate := fields[key]; duplicate {
				return out, errors.New("APT 软件包元数据重复")
			}
			fields[key] = value
		}
		baseName := strings.Split(name, ":")[0]
		if fields["Package"] != baseName || fields["Version"] != version {
			return out, errors.New("APT 软件包版本与求解计划不一致")
		}
		if selected != nil {
			for _, key := range []string{"Package", "Version", "Architecture", "Installed-Size", "Size", "SHA256"} {
				if fields[key] != selected[key] {
					return out, errors.New("同版本 APT 软件包来源存在内容歧义")
				}
			}
		}
		selected = fields
	}
	if selected == nil {
		return out, errors.New("APT 软件包元数据缺失")
	}
	size, err := strconv.ParseInt(selected["Size"], 10, 64)
	if err != nil || size <= 0 {
		return out, errors.New("APT 软件包下载大小未知")
	}
	installed, err := strconv.ParseInt(selected["Installed-Size"], 10, 64)
	if err != nil || installed <= 0 || installed > fail2banPythonLimit/1024 {
		return out, errors.New("APT 软件包安装占用未知")
	}
	args := append(fail2banAPTArgs(), "-o", "Acquire::ForceHash=sha256", "--print-uris", "download", name+"="+version)
	raw, err = fail2banAPTCommand(ctx, "apt-get", args, "/", 10*time.Second, 16<<10)
	if err != nil {
		return out, err
	}
	match := fail2banAPTURI.FindStringSubmatch(strings.TrimSpace(string(raw)))
	if match == nil || match[4] != selected["SHA256"] || match[3] != selected["Size"] {
		return out, errors.New("APT 下载身份、强摘要或大小无法核对")
	}
	source, err := fail2banPackageSource(match[1])
	if err != nil {
		return out, err
	}
	out = fail2ban.PythonPackage{Name: selected["Package"], Version: version, Architecture: selected["Architecture"], Source: source, Repository: "configured-apt", Filename: match[2], SHA256: match[4], DownloadBytes: size, InstalledBytes: installed * 1024}
	return out, nil
}
func installFail2banAPT(ctx context.Context, data, operation string, p fail2banPythonPlan) error {
	work := filepath.Join(fail2banPythonDir(data), "downloads", operation)
	if err := secure.RootDirectory(work, 0700); err != nil {
		return err
	}
	args := append(fail2banAPTArgs(), "download")
	for _, pkg := range p.Plan.Packages {
		args = append(args, pkg.Name+":"+pkg.Architecture+"="+pkg.Version)
	}
	if _, err := fail2banAPTCommand(ctx, "apt-get", args, work, 10*time.Minute, 2<<20); err != nil {
		return err
	}
	for _, pkg := range p.Plan.Packages {
		path := filepath.Join(work, pkg.Filename)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != pkg.DownloadBytes {
			return errors.New("下载的软件包文件或大小与批准计划不一致")
		}
		hash, err := secure.HashRootFile(path, pkg.DownloadBytes)
		if err != nil || hash != pkg.SHA256 {
			return errors.New("下载的软件包强摘要与批准计划不一致")
		}
		raw, err := fail2banAPTCommand(ctx, "dpkg-deb", []string{"--show", "--showformat=${Package}\t${Version}\t${Architecture}\n", path}, "/", 5*time.Second, 4096)
		if err != nil {
			return err
		}
		if strings.TrimSuffix(string(raw), "\n") != strings.Join([]string{pkg.Name, pkg.Version, pkg.Architecture}, "\t") {
			return errors.New("归档内部的软件包身份与批准计划不一致")
		}
	}
	// Only the approved local archives enter the resolver. Empty source lists
	// and private empty package lists prevent it adding a cached, unapproved
	// repository dependency if the host changed after the final preview.
	lists := filepath.Join(work, "lists")
	if err := secure.RootDirectory(filepath.Join(lists, "partial"), 0700); err != nil {
		return err
	}
	args = append(fail2banAPTArgs(), "-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::lists="+lists, "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "--no-download", "--no-install-recommends", "--no-remove", "--no-upgrade", "--yes", "install")
	for _, pkg := range p.Plan.Packages {
		args = append(args, filepath.Join(work, pkg.Filename))
	}
	_, err := fail2banAPTCommand(ctx, "apt-get", args, "/", 10*time.Minute, 4<<20)
	return err
}
func proveFail2banAPT(ctx context.Context, p fail2banPythonPlan) error {
	if _, err := fail2banAPTInstalled(ctx); err != nil {
		return err
	}
	for _, pkg := range p.Plan.Packages {
		raw, err := fail2banAPTCommand(ctx, "dpkg-query", []string{"-W", "-f=${Package}\t${Architecture}\t${Version}\t${Status}\n", pkg.Name + ":" + pkg.Architecture}, "/", 5*time.Second, 4096)
		if err != nil {
			return err
		}
		if strings.TrimSuffix(string(raw), "\n") != strings.Join([]string{pkg.Name, pkg.Architecture, pkg.Version, "install ok installed"}, "\t") {
			return errors.New("Python 计划中的系统包尚未按原版本完成配置")
		}
	}
	return nil
}
