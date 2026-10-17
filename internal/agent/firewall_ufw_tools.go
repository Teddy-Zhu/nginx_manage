package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

var ufwSourceModules = []string{"ufw", "ufw.applications", "ufw.backend", "ufw.backend_iptables", "ufw.common", "ufw.frontend", "ufw.parser", "ufw.util"}

// -S permits querying system site directories without executing .pth files or
// sitecustomize. PathFinder locates source files without importing UFW code.
const ufwLocateSources = `import sys,os,json,site
from importlib.machinery import PathFinder,SourceFileLoader
if sys.version_info.major!=3:
 raise ValueError('Python 3 is required')
names=json.loads(sys.argv[1])
package=PathFinder.find_spec('ufw',site.getsitepackages())
if package is None or not isinstance(package.loader,SourceFileLoader) or len(package.submodule_search_locations or ())!=1:
 raise ValueError('a regular system UFW source package is required')
modules=[]
for name in names:
 spec=package if name=='ufw' else PathFinder.find_spec(name,package.submodule_search_locations)
 if spec is None or not isinstance(spec.loader,SourceFileLoader):
  raise ValueError('UFW source module is unavailable')
 modules.append({'name':name,'path':spec.origin})
print(json.dumps({'protocol':1,'python':sys.version.split()[0],'executable':os.path.realpath(sys.executable),'modules':modules}))
`

// Both description and official CLI dry-runs load the same private source
// files. No host bytecode, global site hook, cwd or user package supplies UFW.
// There is deliberately no mode that submits a real firewall write.
const ufwFrozenRunner = `import sys,os,json,importlib,runpy
root,mode,names_text=sys.argv[1:4]
names=json.loads(names_text)
sys.path.insert(0,os.path.join(root,'lib'))
for name in names:
 importlib.import_module(name)
for name,module in list(sys.modules.items()):
 if name=='ufw' or name.startswith('ufw.'):
  leaf='__init__' if name=='ufw' else name.split('.')[1]
  expected=os.path.join(root,'lib','ufw',leaf+'.py')
  if name not in names or os.path.abspath(module.__file__)!=expected:
   raise ValueError('UFW import escaped frozen sources')
import ufw.common
if mode=='describe':
 print(json.dumps({'protocol':1,'python':sys.version.split()[0],'program':ufw.common.programName,'checks':ufw.common.do_checks,'config_dir':ufw.common.config_dir,'state_dir':ufw.common.state_dir,'iptables_dir':ufw.common.iptables_dir}))
elif mode=='prepend':
 sys.argv=[os.path.join(root,'ufw-cli.py'),'--datadir='+root,'--dry-run','prepend']+sys.argv[4:]
 runpy.run_path(sys.argv[0],run_name='__main__')
else:
 raise ValueError('unsupported UFW operation')
`

type ufwBoundFile struct {
	Role       string
	Invoked    string
	Executable bool
	File       ufwFileSnapshot
	Raw        []byte `json:"-"`
}
type ufwToolDescription struct {
	Protocol    int    `json:"protocol"`
	Python      string `json:"python"`
	Program     string `json:"program"`
	Checks      bool   `json:"checks"`
	ConfigDir   string `json:"config_dir"`
	StateDir    string `json:"state_dir"`
	IptablesDir string `json:"iptables_dir"`
}
type ufwToolBinding struct {
	Files       []ufwBoundFile
	Description ufwToolDescription
	Hash        string
}

func readUFWBoundFile(role, path string, executable bool, limit int64) (ufwBoundFile, error) {
	out := ufwBoundFile{Role: role, Invoked: path, Executable: executable}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return out, errors.New("UFW 工具路径无效")
	}
	resolved, err := trustedFile(path, executable)
	if err != nil {
		return out, err
	}
	before, err := os.Lstat(resolved)
	if err != nil {
		return out, err
	}
	raw, err := nginxmodules.ReadTrusted(resolved, limit)
	if err != nil {
		return out, err
	}
	after, err := os.Lstat(resolved)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return out, errors.New("UFW 工具在读取期间变化")
	}
	first, firstOK := before.Sys().(*syscall.Stat_t)
	last, lastOK := after.Sys().(*syscall.Stat_t)
	current, resolveErr := trustedFile(path, executable)
	if !firstOK || !lastOK || first.Ctim != last.Ctim || resolveErr != nil || current != resolved {
		return out, errors.New("UFW 工具文件身份在读取期间变化")
	}
	out.File = ufwFileSnapshot{Path: resolved, Present: true, Hash: secure.Hash(raw), Bytes: int64(len(raw)), Device: uint64(last.Dev), Inode: last.Ino, Mode: uint32(after.Mode()), Modified: after.ModTime().UnixNano(), Changed: last.Ctim.Sec*1e9 + last.Ctim.Nsec}
	out.Raw = raw
	return out, nil
}

func ufwSystemCommand(name string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		// Match execvp's first existing entry; never bypass an untrusted shadow.
		if _, err := trustedFile(path, true); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", errors.New("UFW 固定系统工具不可用")
}

func ufwPythonPath(script []byte) (string, error) {
	line, _, _ := strings.Cut(string(script), "\n")
	line, found := strings.CutPrefix(line, "#!")
	words := strings.Fields(line)
	if !found || len(words) < 1 || len(words) > 2 {
		return "", errors.New("UFW Python 启动方式不可核对")
	}
	if words[0] == "/usr/bin/env" || words[0] == "/bin/env" {
		if len(words) != 2 || words[1] != "python" && words[1] != "python3" {
			return "", errors.New("UFW env 解释器选择不受支持")
		}
		return ufwSystemCommand(words[1])
	}
	name := filepath.Base(words[0])
	minor := strings.TrimPrefix(name, "python3.")
	if !filepath.IsAbs(words[0]) || name != "python" && name != "python3" && (!strings.HasPrefix(name, "python3.") || minor == "" || strings.Trim(minor, "0123456789") != "") || len(words) == 2 && !slices.Contains([]string{"-E", "-s", "-Es", "-sE", "-I", "-B"}, words[1]) {
		return "", errors.New("UFW Python shebang 不受支持")
	}
	return words[0], nil
}

func ufwSourceLeaf(name string) string {
	if name == "ufw" {
		return "__init__.py"
	}
	return strings.TrimPrefix(name, "ufw.") + ".py"
}

func ufwToolJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("UFW 工具描述结构无效")
	}
	return nil
}

func prepareUFWTools(ctx context.Context, w *ufwDryRunWorkspace, binary string, baseline ufwConfigurationSnapshot) (*ufwToolBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := &ufwToolBinding{Files: []ufwBoundFile{}}
	cli, err := readUFWBoundFile("cli", binary, true, firewall.UFWReadBytes)
	if err != nil || cli.File.Hash != baseline.ToolHash {
		return nil, errors.New("UFW CLI 与原配置快照的工具不一致")
	}
	pythonPath, err := ufwPythonPath(cli.Raw)
	if err != nil {
		return nil, err
	}
	python, err := readUFWBoundFile("python", pythonPath, true, 16<<20)
	if err != nil {
		return nil, errors.New("UFW 系统 Python 解释器无法完整核对")
	}
	python.Raw = nil
	out.Files = append(out.Files, cli, python)
	total := cli.File.Bytes + python.File.Bytes
	names, err := json.Marshal(ufwSourceModules)
	if err != nil {
		return nil, err
	}
	raw, err := runUFWBoundCommand(ctx, python, []string{"-I", "-S", "-B", "-c", ufwLocateSources, string(names)}, w.root, 64<<10)
	if err != nil {
		return nil, errors.New("UFW 系统源包位置无法在隔离 Python 中读取")
	}
	var located struct {
		Protocol   int    `json:"protocol"`
		Python     string `json:"python"`
		Executable string `json:"executable"`
		Modules    []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"modules"`
	}
	if err = ufwToolJSON(raw, &located); err != nil || located.Protocol != 1 || !strings.HasPrefix(located.Python, "3.") || len(located.Python) > 64 || located.Executable != python.File.Path || len(located.Modules) != len(ufwSourceModules) {
		return nil, errors.New("UFW 系统源包描述与固定解释器不一致")
	}
	packageDir := ""
	for index, item := range located.Modules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if index == 0 {
			packageDir = filepath.Dir(item.Path)
		}
		if item.Name != ufwSourceModules[index] || item.Path != filepath.Join(packageDir, ufwSourceLeaf(item.Name)) {
			return nil, errors.New("UFW 模块不属于同一常规系统源包")
		}
		file, err := readUFWBoundFile(item.Name, item.Path, false, min(firewall.UFWReadBytes, 64<<20-total))
		if err != nil {
			return nil, errors.New("UFW 系统源文件归属或内容不可核对")
		}
		total += file.File.Bytes
		out.Files = append(out.Files, file)
	}
	if err = w.installUFWTools(out); err != nil {
		return nil, err
	}
	raw, err = out.python(ctx, w.root, "describe", nil, 64<<10)
	if err != nil {
		return nil, errors.New("固定 UFW 源码无法描述其后端工具")
	}
	if err = ufwToolJSON(raw, &out.Description); err != nil || out.Description.Protocol != 1 || out.Description.Python != located.Python || out.Description.Program != "ufw" || !out.Description.Checks || out.Description.ConfigDir != "/etc" || !slices.Contains([]string{"/lib/ufw", "/usr/lib/ufw"}, out.Description.StateDir) || !slices.Contains([]string{"/sbin", "/usr/sbin"}, out.Description.IptablesDir) {
		return nil, errors.New("UFW 配置目录、完整性检查或编译后端路径不受支持")
	}
	for _, name := range []string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "iptables-save", "ip6tables-save", "ufw-init", "cat", "false"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := filepath.Join(out.Description.IptablesDir, name)
		if name == "ufw-init" {
			path = filepath.Join(out.Description.StateDir, name)
		} else if name == "cat" || name == "false" {
			path, err = ufwSystemCommand(name)
			if err != nil {
				return nil, err
			}
		}
		file, err := readUFWBoundFile(name, path, true, min(16<<20, 64<<20-total))
		if err != nil {
			return nil, errors.New("UFW 声明的工具不可核对或绑定材料超过 64 MiB")
		}
		total += file.File.Bytes
		file.Raw = nil
		out.Files = append(out.Files, file)
	}
	encoded, err := json.Marshal(struct {
		Files       []ufwBoundFile
		Description ufwToolDescription
		LocatorHash string
		RunnerHash  string
	}{out.Files, out.Description, secure.Hash([]byte(ufwLocateSources)), secure.Hash([]byte(ufwFrozenRunner))})
	if err != nil {
		return nil, err
	}
	out.Hash = secure.Hash(append([]byte("ufw:tools:v1:\x00"), encoded...))
	return out, nil
}

func (b *ufwToolBinding) tool(role string) (ufwBoundFile, error) {
	for _, file := range b.Files {
		if file.Role == role {
			return file, nil
		}
	}
	return ufwBoundFile{}, errors.New("UFW 操作未绑定对应固定工具")
}

func (b *ufwToolBinding) verify(ctx context.Context) error {
	for _, before := range b.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		after, err := readUFWBoundFile(before.Role, before.Invoked, before.Executable, 16<<20)
		if err != nil || after.File != before.File {
			return errors.New("UFW 原 CLI、Python、源包或后端工具已变化，请重新计划")
		}
	}
	return nil
}

func (b *ufwToolBinding) python(ctx context.Context, root, mode string, args []string, limit int) ([]byte, error) {
	python, err := b.tool("python")
	if err != nil || !slices.Contains([]string{"describe", "prepend"}, mode) {
		return nil, errors.New("UFW 固定 Python 操作无效")
	}
	names, err := json.Marshal(ufwSourceModules)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"-I", "-S", "-B", "-c", ufwFrozenRunner, root, mode, string(names)}, args...)
	return runUFWBoundCommand(ctx, python, argv, root, limit)
}

func (b *ufwToolBinding) read(ctx context.Context, role, action, root string) ([]byte, error) {
	tool, err := b.tool(role)
	if err != nil {
		return nil, err
	}
	args, limit := []string{"--version"}, 1024
	if action == "rules" && (role == "iptables-save" || role == "ip6tables-save") {
		blocker, err := b.tool("false")
		if err != nil {
			return nil, err
		}
		args, limit = []string{"--modprobe", blocker.Invoked}, 1<<20
	} else if action != "version" || !slices.Contains([]string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "iptables-save", "ip6tables-save"}, role) {
		return nil, errors.New("UFW 后端只允许固定版本及规则读取")
	}
	return runUFWBoundCommand(ctx, tool, args, root, limit)
}

func runUFWBoundCommand(ctx context.Context, tool ufwBoundFile, args []string, root string, limit int) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(call, tool.File.Path, args...)
	command.Args[0] = tool.Invoked
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1", "TMPDIR=" + filepath.Join(root, "tmp")}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 250 * time.Millisecond
	stdout, stderr := firewallOutput{limit: limit}, firewallOutput{limit: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded || stderr.data.Len() != 0 || call.Err() != nil {
		return nil, errors.New("UFW 固定工具调用失败、超时、警告或输出超限")
	}
	return stdout.data.Bytes(), nil
}
