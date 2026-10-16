package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
)

// DNF 4 is the native package API on the supported CentOS Stream releases.
// Its private platform Python is reused only to operate DNF, never selected
// as the managed Fail2ban interpreter or copied into the panel image.
func fail2banDNFPython() (fail2ban.Tool, error) {
	for _, path := range []string{"/usr/libexec/platform-python", "/usr/bin/python3"} {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		resolved, err := trustedFile(path, true)
		if err != nil {
			return fail2ban.Tool{}, err
		}
		present := true
		return fail2ban.Tool{ID: "dnf-python", Path: path, Resolved: resolved, Present: &present, Trusted: true}, nil
	}
	return fail2ban.Tool{}, errors.New("DNF 的系统 Python 不可用，须由原生包管理器恢复")
}

const fail2banDNFProgram = `import sys,os,json,hashlib,urllib.parse,stat
output_fd=os.dup(1)
null_fd=os.open(os.devnull,os.O_WRONLY)
os.dup2(null_fd,1)
os.close(null_fd)
def trusted_directory(path):
    resolved=os.path.realpath(path)
    current=resolved
    while current!="/":
        info=os.stat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise RuntimeError("untrusted_module_directory")
        current=os.path.dirname(current)
    return resolved
def run(request):
    version="python%d.%d"%sys.version_info[:2]
    sys.path=[trusted_directory(path) for path in sys.path if path.startswith(("/usr/lib/","/usr/lib64/")) and os.path.isdir(path)]
    for parent in ("/usr/lib64","/usr/lib"):
        path=os.path.join(parent,version,"site-packages")
        if os.path.isdir(path):
            sys.path.append(trusted_directory(path))
    import dnf,dnf.transaction,hawkey,rpm
    if dnf.__version__.split(".")[0]!="4":
        raise RuntimeError("unsupported_dnf_api")
    with dnf.Base() as base:
        base.conf.read()
        if base.conf.tsflags:
            raise RuntimeError("unsupported_rpm_transaction_flags")
        base.conf.installroot="/"
        base.conf.plugins=False
        base.conf.install_weak_deps=False
        base.conf.obsoletes=False
        base.conf.gpgcheck=True
        base.conf.localpkg_gpgcheck=True
        base.conf.assumeyes=False
        base.conf.exit_on_lock=True
        base.conf.skip_if_unavailable=False
        base.conf.cachedir="/var/cache/dnf"
        base.conf.persistdir="/var/lib/dnf"
        base.conf.logdir="/var/log"
        base.conf.timeout=30
        base.conf.retries=1
        base.conf.cacheonly=not request["refresh"]
        base.conf.substitutions["releasever"]=request["release"]
        base.read_all_repos()
        for repo in base.repos.iter_enabled():
            repo.gpgcheck=True
            repo.skip_if_unavailable=False
        proving=request["mode"]=="prove"
        base.fill_sack(load_system_repo=True,load_available_repos=not proving)
        installed=list(base.sack.query().installed())
        rows=sorted("%s\t%s\t%s"%(p.name,p.arch,p.evr) for p in installed)
        state=hashlib.sha256("\n".join(rows).encode()).hexdigest()
        if proving:
            current={(p.name,p.arch):p.evr for p in installed}
            for package in request["packages"]:
                if current.get((package["name"],package["architecture"]))!=package["version"]:
                    raise RuntimeError("package_state_unconfirmed")
            return {"installed":state,"packages":[],"error":""}
        base.install("python3",strict=True)
        base.resolve(allow_erasing=False)
        packages=[]
        installed_names={p.name for p in installed}
        for item in base.transaction:
            if item.action!=dnf.transaction.PKG_INSTALL or item.pkg.name in installed_names:
                raise RuntimeError("transaction_changes_existing_packages")
            package=item.pkg
            checksum=package.chksum
            if not checksum or hawkey.chksum_name(checksum[0]).lower()!="sha256":
                raise RuntimeError("missing_strong_package_digest")
            location=package.remote_location()
            source=urllib.parse.urlsplit(location or "")
            if source.scheme not in ("http","https") or not source.netloc:
                raise RuntimeError("unsupported_repository_source")
            host=source.netloc.rsplit("@",1)[-1]
            source=urllib.parse.urlunsplit((source.scheme,host,"","",""))
            packages.append({"name":package.name,"version":package.evr,"architecture":package.arch,"source":source,"repository":package.reponame,"filename":"","sha256":checksum[1].hex(),"download_bytes":package.downloadsize,"installed_bytes":package.installsize})
        packages.sort(key=lambda p:p["name"]+":"+p["architecture"])
        if not 0<len(packages)<=64:
            raise RuntimeError("not_an_additive_transaction")
        result={"installed":state,"packages":packages,"error":""}
        if request["mode"]=="install":
            if state!=request["installed"] or packages!=request["packages"]:
                raise RuntimeError("approved_transaction_changed")
            base.download_packages(base.transaction.install_set)
            for package in base.transaction.install_set:
                code,message=base.package_signature_check(package)
                if code!=0:
                    raise RuntimeError("package_signature_or_existing_key_unconfirmed")
                with open(package.localPkg(),"rb") as archive:
                    digest=hashlib.sha256()
                    for chunk in iter(lambda:archive.read(1024*1024),b""):
                        digest.update(chunk)
                if digest.digest()!=package.chksum[1]:
                    raise RuntimeError("downloaded_package_digest_changed")
                with open(package.localPkg(),"rb") as archive:
                    header=rpm.TransactionSet("/").hdrFromFdno(archive.fileno())
                if (header["name"],header["version"],header["release"],int(header["epoch"] or 0),header["arch"])!=(package.name,package.version,package.release,int(package.epoch),package.arch):
                    raise RuntimeError("archive_package_identity_changed")
            base.do_transaction()
        return result
request=json.load(sys.stdin)
try:
    result=run(request)
except Exception as error:
    codes={"untrusted_module_directory","unsupported_dnf_api","unsupported_rpm_transaction_flags","package_state_unconfirmed","transaction_changes_existing_packages","missing_strong_package_digest","unsupported_repository_source","not_an_additive_transaction","approved_transaction_changed","package_signature_or_existing_key_unconfirmed","downloaded_package_digest_changed","archive_package_identity_changed"}
    message=str(error) if str(error) in codes else type(error).__name__
    result={"installed":"","packages":[],"error":message[:128]}
    os.write(output_fd,(json.dumps(result,separators=(",",":"))+"\n").encode())
    os.close(output_fd)
    sys.exit(1)
os.write(output_fd,(json.dumps(result,separators=(",",":"))+"\n").encode())
os.close(output_fd)
`

type fail2banDNFRequest struct {
	Mode      string                   `json:"mode"`
	Refresh   bool                     `json:"refresh"`
	Release   string                   `json:"release"`
	Installed string                   `json:"installed"`
	Packages  []fail2ban.PythonPackage `json:"packages"`
}
type fail2banDNFResult struct {
	Installed string                   `json:"installed"`
	Packages  []fail2ban.PythonPackage `json:"packages"`
	Error     string                   `json:"error"`
}

func fail2banDNFCall(ctx context.Context, in fail2banDNFRequest) (fail2banDNFResult, error) {
	var out fail2banDNFResult
	tool, err := fail2banDNFPython()
	if err != nil {
		return out, err
	}
	raw, _ := json.Marshal(in)
	budget := 45 * time.Second
	if in.Refresh {
		budget = 3 * time.Minute
	}
	if in.Mode == "install" {
		budget = 15 * time.Minute
	}
	result, callErr := fail2banPackageRun(ctx, tool, []string{"-I", "-S", "-B", "-c", fail2banDNFProgram}, "/", raw, budget, 256<<10)
	if err = fail2banPythonDecode(result, &out); err != nil {
		if callErr != nil {
			return out, callErr
		}
		return out, err
	}
	if out.Error != "" {
		if !fail2banServiceWord.MatchString(out.Error) {
			return out, errors.New("系统 DNF 返回的错误类别无效")
		}
		reasons := map[string]string{"unsupported_dnf_api": "系统 DNF API 不在受支持版本内", "transaction_changes_existing_packages": "计划会变更已有软件包，拒绝安装", "not_an_additive_transaction": "没有可核对的纯新增 Python 事务", "approved_transaction_changed": "软件包计划或已安装清单已经变化，请重新规划", "package_signature_or_existing_key_unconfirmed": "包签名或现有 RPM 信任密钥无法核对；不自动导入密钥", "downloaded_package_digest_changed": "下载的软件包摘要发生变化", "package_state_unconfirmed": "计划中的系统包尚未按原版本完整安装", "unsupported_rpm_transaction_flags": "系统配置含额外 RPM 事务标记，须本机复核", "archive_package_identity_changed": "归档内部的软件包身份与批准计划不一致"}
		if reason := reasons[out.Error]; reason != "" {
			return out, errors.New(reason)
		}
		return out, errors.New("系统 DNF 无法完成依赖操作（" + strings.Trim(out.Error, "\x00\r\n") + "），请检查索引、锁及系统包日志")
	}
	if callErr != nil {
		return out, callErr
	}
	if !fail2banDigest.MatchString(out.Installed) || out.Packages == nil || len(out.Packages) > 64 {
		return out, errors.New("系统 DNF 返回材料无效")
	}
	return out, nil
}
func planFail2banDNF(ctx context.Context, refresh bool) ([]fail2ban.PythonPackage, string, error) {
	_, version, err := fail2banPythonHost()
	if err != nil {
		return nil, "", err
	}
	out, err := fail2banDNFCall(ctx, fail2banDNFRequest{Mode: "plan", Refresh: refresh, Release: version, Packages: []fail2ban.PythonPackage{}})
	return out.Packages, out.Installed, err
}
func installFail2banDNF(ctx context.Context, p fail2banPythonPlan) error {
	_, err := fail2banDNFCall(ctx, fail2banDNFRequest{Mode: "install", Release: p.Plan.Version, Installed: p.Installed, Packages: p.Plan.Packages})
	return err
}
func proveFail2banDNF(ctx context.Context, p fail2banPythonPlan) error {
	_, err := fail2banDNFCall(ctx, fail2banDNFRequest{Mode: "prove", Release: p.Plan.Version, Packages: p.Plan.Packages})
	return err
}
