package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"

	"nginxpanel/internal/fail2ban"
)

var fail2banPythonPath = regexp.MustCompile(`^/(usr/)?bin/python3(\.[0-9]{1,2})?$`)
var fail2banPackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+_.:-]{0,127}$`)
var fail2banPackageVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+_.:~%-]{0,127}$`)

var fail2banPythonModules = []string{"configparser", "datetime", "fcntl", "hashlib", "ipaddress", "json", "logging", "multiprocessing", "queue", "re", "select", "signal", "socket", "sqlite3", "ssl", "threading"}

const fail2banPythonProbe = `import importlib,json,sys
modules=[]
sqlite_version=""
sqlite_memory=False
for name in ("configparser","datetime","fcntl","hashlib","ipaddress","json","logging","multiprocessing","queue","re","select","signal","socket","sqlite3","ssl","threading"):
    try:
        module=importlib.import_module(name)
        if name=="sqlite3":
            sqlite_version=module.sqlite_version
            connection=module.connect(":memory:")
            try:
                connection.execute("CREATE TABLE probe (value INTEGER)")
                connection.execute("INSERT INTO probe VALUES (1)")
                sqlite_memory=connection.execute("SELECT value FROM probe").fetchone()==(1,)
            finally:
                connection.close()
        modules.append({"name":name,"available":True})
    except Exception:
        modules.append({"name":name,"available":False})
print(json.dumps({"version":list(sys.version_info[:3]),"modules":modules,"sqlite_version":sqlite_version,"sqlite_memory":sqlite_memory},separators=(",",":")))
`

func readFail2banPython(ctx context.Context) fail2ban.Python {
	out := fail2ban.Python{Executable: fail2banTool("python3"), Modules: []fail2ban.Module{}, Package: fail2ban.Package{Reason: "尚未核对软件包归属"}, Reason: "系统 Python 不可用或无法隔离读取"}
	if !out.Executable.Trusted {
		return out
	}
	if !fail2banPythonPath.MatchString(out.Executable.Resolved) {
		out.Reason = "Python 指向非标准系统解释器，须在组件接入时明确批准"
		return out
	}
	raw, err := fail2banRun(ctx, out.Executable, []string{"-I", "-S", "-B", "-c", fail2banPythonProbe}, 16<<10)
	if err != nil {
		return out
	}
	var probe struct {
		Version       []int             `json:"version"`
		Modules       []fail2ban.Module `json:"modules"`
		SQLiteVersion string            `json:"sqlite_version"`
		SQLiteMemory  bool              `json:"sqlite_memory"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&probe) != nil || d.Decode(new(any)) != io.EOF || len(probe.Version) != 3 || probe.Version[0] != 3 || probe.Version[1] < 0 || probe.Version[1] > 99 || probe.Version[2] < 0 || probe.Version[2] > 999 || len(probe.Modules) != len(fail2banPythonModules) || len(probe.SQLiteVersion) > 32 {
		return out
	}
	ready := probe.SQLiteMemory
	for i, module := range probe.Modules {
		if module.Name != fail2banPythonModules[i] {
			return out
		}
		ready = ready && module.Available
	}
	out.Version = strconv.Itoa(probe.Version[0]) + "." + strconv.Itoa(probe.Version[1]) + "." + strconv.Itoa(probe.Version[2])
	out.StandardLibrary, out.Modules, out.SQLiteVersion = &ready, probe.Modules, probe.SQLiteVersion
	out.Reason = "标准库探测不替代所选签名组件的解释器约束及完整启动核对"
	if !ready {
		out.Reason = "缺少必要标准库或 SQLite 内存读写能力"
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
