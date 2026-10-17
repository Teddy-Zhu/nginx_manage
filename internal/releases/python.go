package releases

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PythonRuntime describes a code-only component's interpreter contract. The
// interpreter stays owned by the host's package manager, never by this asset.
type PythonRuntime struct {
	Implementation string `json:"implementation"`
	MinimumMinor   int    `json:"minimum_minor"`
	MaximumMinor   int    `json:"maximum_minor"`
}

func (p PythonRuntime) Valid() bool {
	return p.Implementation == "cpython" && p.MinimumMinor >= 9 && p.MaximumMinor <= 14 && p.MaximumMinor >= p.MinimumMinor
}
func (p PythonRuntime) AcceptsVersion(version string) bool {
	parts := strings.Split(version, ".")
	if !p.Valid() || len(parts) != 3 || parts[0] != "3" {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	patch, patchErr := strconv.Atoi(parts[2])
	return err == nil && patchErr == nil && patch >= 0 && patch <= 999 && minor >= p.MinimumMinor && minor <= p.MaximumMinor
}

type PythonModule struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}
type SystemPython struct {
	Path, Resolved, SHA256 string         `json:"-"`
	Version                []int          `json:"version"`
	Implementation         string         `json:"implementation"`
	FreeThreaded           bool           `json:"free_threaded"`
	Modules                []PythonModule `json:"modules"`
	SQLiteVersion          string         `json:"sqlite_version"`
	SQLiteMemory           bool           `json:"sqlite_memory"`
}

func SystemPythonModules() []string {
	return []string{"configparser", "datetime", "fcntl", "hashlib", "ipaddress", "json", "logging", "multiprocessing", "queue", "re", "select", "signal", "socket", "sqlite3", "ssl", "threading"}
}

const systemPythonProbe = `import importlib,json,sys,sysconfig
modules=[]
sqlite_version=""
sqlite_memory=False
for name in sys.argv[1].split(","):
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
print(json.dumps({"version":list(sys.version_info[:3]),"implementation":sys.implementation.name,"free_threaded":bool(sysconfig.get_config_var("Py_GIL_DISABLED")),"modules":modules,"sqlite_version":sqlite_version,"sqlite_memory":sqlite_memory},separators=(",",":")))
`

// A writer error stops collection; WaitDelay bounds a child retaining pipes.
type pythonOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *pythonOutput) Write(raw []byte) (int, error) {
	if b.buffer.Len()+len(raw) > b.limit {
		return 0, errors.New("系统 Python 探测输出超限")
	}
	return b.buffer.Write(raw)
}

func InspectSystemPython(ctx context.Context) (SystemPython, error) {
	var out SystemPython
	const path = "/usr/bin/python3"
	if err := rootParents(path); err != nil {
		return out, err
	}
	alias, err := os.Lstat(path)
	if err != nil {
		return out, err
	}
	owner, ok := alias.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return out, errors.New("系统 Python 入口不受 root 保护")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !pythonInterpreter.MatchString(resolved) {
		return out, errors.New("Python 须指向固定 /usr/bin 系统解释器")
	}
	f, before, err := openRoot(resolved, 64<<20)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if before.Mode().Perm()&0111 == 0 {
		return out, errors.New("系统 Python 不可执行")
	}
	sha, err := fileHash(resolved, before.Size())
	if err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, resolved, "-I", "-S", "-B", "-c", systemPythonProbe, strings.Join(SystemPythonModules(), ","))
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	stdout, stderr := &pythonOutput{limit: 16 << 10}, &pythonOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return out, errors.New("系统 Python 隔离探测失败或超时")
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.buffer.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || len(out.Version) != 3 || out.Version[0] != 3 || out.Version[1] < 0 || out.Version[1] > 99 || out.Version[2] < 0 || out.Version[2] > 999 || !text(out.Implementation, 32) || len(out.SQLiteVersion) > 32 || len(out.Modules) != len(SystemPythonModules()) {
		return SystemPython{}, errors.New("系统 Python 返回的版本或标准库记录无效")
	}
	for i, name := range SystemPythonModules() {
		if out.Modules[i].Name != name {
			return SystemPython{}, errors.New("系统 Python 标准库清单不完整")
		}
	}
	current, err := os.Stat(resolved)
	aliasNow, aliasErr := filepath.EvalSymlinks(path)
	currentHash, hashErr := fileHash(resolved, before.Size())
	if err != nil || aliasErr != nil || hashErr != nil || aliasNow != resolved || !os.SameFile(current, before) || !unchanged(f, before) || currentHash != sha {
		return SystemPython{}, errors.New("系统 Python 在探测期间变化")
	}
	out.Path, out.Resolved, out.SHA256 = path, resolved, sha
	return out, ctx.Err()
}

func (p SystemPython) VersionString() string {
	if len(p.Version) != 3 {
		return ""
	}
	return strconv.Itoa(p.Version[0]) + "." + strconv.Itoa(p.Version[1]) + "." + strconv.Itoa(p.Version[2])
}
func (p SystemPython) Check(requirement PythonRuntime) error {
	if !requirement.Valid() || p.Implementation != requirement.Implementation || p.FreeThreaded || !requirement.AcceptsVersion(p.VersionString()) {
		return fmt.Errorf("系统 Python 须为 CPython 3.%d–3.%d 的标准 GIL 模式；当前为 %s %s", requirement.MinimumMinor, requirement.MaximumMinor, p.Implementation, p.VersionString())
	}
	if !p.SQLiteMemory || len(p.Modules) != len(SystemPythonModules()) {
		return errors.New("系统 Python 缺少必要标准库或 SQLite 内存读写能力")
	}
	for i, name := range SystemPythonModules() {
		if p.Modules[i].Name != name || !p.Modules[i].Available {
			return errors.New("系统 Python 缺少必要标准库: " + name)
		}
	}
	return nil
}
