package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

// Existing binding files authorize only the system client. A managed selection
// is derived from its root installation receipt and is never saved as one.
func selectFail2banBinding(data string) (*fail2banBinding, error) {
	b, err := loadFail2banBinding(data)
	if err != nil {
		return nil, err
	}
	if !fail2banManagedData(data) {
		return b, nil
	}
	r, err := loadFail2banManaged(data)
	if err != nil {
		return nil, err
	}
	if r == nil || r.State == "rolled-back" {
		return b, nil
	}
	if b != nil && b.State == "bound" {
		return nil, errors.New("已有实例授权与受管安装同时存在，须本机处理冲突")
	}
	if r.State != "installed" {
		return nil, errors.New("受管引擎安装尚未完成或正在撤回，请先续办或处理安装")
	}
	return r.binding(), nil
}
func (r *fail2banManagedRecord) binding() *fail2banBinding {
	client := filepath.Join(r.PackageRoot, "bin", "fail2ban-client")
	return &fail2banBinding{Schema: 1, ID: r.EventID, State: "bound", Service: fail2banManagedService, Socket: fail2banManagedSocket, ClientPath: client, ClientResolved: client, ClientVersion: r.Version, ApprovedAt: r.ApprovedAt, managed: r}
}
func (r fail2banManagedRecord) engine() fail2ban.EngineIdentity {
	return fail2ban.EngineIdentity{Owner: "managed", InstallationID: r.OperationID, PlanID: r.PlanID, AssetID: r.AssetID, ManifestSHA256: r.ManifestSHA256, PythonPath: r.PythonPath, PythonSHA256: r.PythonSHA256}
}

const fail2banManagedRegex = "import sys;sys.path.insert(0,sys.argv.pop(1));from fail2ban.client.fail2banregex import exec_command_line;sys.argv[0]='fail2ban-regex';exec_command_line()"

// The selection identity is a cache key. Managed component authentication and
// execution run inside the bounded job; cached samples keep their original time.
type fail2banProgram struct {
	kind    string
	tool    fail2ban.Tool
	hash    string
	managed *fail2banManagedRecord
	// Only the root upgrade inspector may use unselected code, and only for
	// fixed regex diagnostics. It grants no client or running-engine access.
	unselected bool
}

func (p fail2banProgram) engine() fail2ban.EngineIdentity {
	if p.managed != nil {
		return p.managed.engine()
	}
	return fail2ban.EngineIdentity{Owner: "existing"}
}
func (p fail2banProgram) key() string {
	if p.managed != nil {
		raw, _ := json.Marshal(struct {
			Event, Kind, Jails string
			Unselected         bool
			Engine             fail2ban.EngineIdentity
		}{p.managed.EventID, p.kind, p.managed.JailSelection, p.unselected, p.engine()})
		return "managed/" + secure.Hash(raw)
	}
	return "existing/" + p.kind + "/" + p.tool.Path + "\x00" + p.tool.Resolved + "\x00" + p.hash
}
func selectFail2banRegex(data string) (fail2banProgram, error) {
	b, err := selectFail2banBinding(data)
	if err != nil {
		return fail2banProgram{}, err
	}
	if b != nil && b.managed != nil {
		return fail2banProgram{kind: "fail2ban-regex", managed: b.managed}, nil
	}
	tool, hash, err := fail2banRegexTool()
	return fail2banProgram{kind: "fail2ban-regex", tool: tool, hash: hash}, err
}
func selectFail2banClient(b *fail2banBinding) (fail2banProgram, error) {
	if b.managed != nil {
		return fail2banProgram{kind: "fail2ban-client", managed: b.managed}, nil
	}
	tool, err := fail2banBoundTool(b)
	if err != nil {
		return fail2banProgram{}, err
	}
	return fail2banProgram{kind: "fail2ban-client", tool: tool, hash: b.ClientSHA256}, nil
}
func (p fail2banProgram) authenticate(ctx context.Context) (fail2banProgram, error) {
	if p.unselected && (p.managed == nil || p.kind != "fail2ban-regex") {
		return p, errors.New("未选择的候选仅允许官方正则诊断")
	}
	if p.managed != nil {
		if err := verifyFail2banManaged(ctx, p.managed, !p.unselected); err != nil {
			return p, fmt.Errorf("受管组件、解释器或安装材料无法重新认证，须本机检查：%w", err)
		}
		path := filepath.Join(p.managed.PackageRoot, "bin", p.kind)
		hash, err := secure.HashRootFile(path, 4<<20)
		if err != nil {
			return p, errors.New("受管程序入口摘要不可核对")
		}
		p.tool, p.hash = fail2ban.Tool{ID: p.kind, Path: path, Resolved: path, Trusted: true}, hash
		return p, ctx.Err()
	}
	current := fail2banTool(p.kind)
	if !current.Trusted || current.Path != p.tool.Path || current.Resolved != p.tool.Resolved {
		return p, errors.New("固定系统程序路径或权限发生变化")
	}
	hash, err := secure.HashRootFile(current.Resolved, 4<<20)
	if err != nil || hash != p.hash {
		return p, errors.New("固定系统程序内容发生变化")
	}
	return p, ctx.Err()
}
func (p fail2banProgram) unchanged(ctx context.Context, data string) error {
	if p.managed != nil && !p.unselected {
		b, err := selectFail2banBinding(data)
		if err != nil || b == nil || b.managed == nil {
			return errors.New("受管安装授权已变化，请重新读取")
		}
		selected := fail2banProgram{kind: p.kind, managed: b.managed}
		if selected.key() != p.key() {
			return errors.New("受管安装授权已变化，请重新读取")
		}
	}
	current, err := p.authenticate(ctx)
	if err != nil {
		return err
	}
	if current.hash != p.hash || current.tool.Path != p.tool.Path || current.tool.Resolved != p.tool.Resolved {
		return errors.New("读取期间程序入口发生变化")
	}
	return nil
}
func (p fail2banProgram) run(ctx context.Context, args []string, limit int) ([]byte, error) {
	if p.unselected && (p.managed == nil || p.kind != "fail2ban-regex") {
		return nil, errors.New("未选择的候选仅允许官方正则诊断")
	}
	if p.managed == nil {
		return fail2banRun(ctx, p.tool, args, limit)
	}
	if !p.tool.Trusted || p.hash == "" {
		return nil, errors.New("受管程序未经认证")
	}
	var argv []string
	switch p.kind {
	case "fail2ban-client":
		argv = p.managed.args(true, args...)
	case "fail2ban-regex":
		argv = append([]string{"-I", "-S", "-B", "-c", fail2banManagedRegex, p.managed.PackageRoot}, args...)
	default:
		return nil, errors.New("不支持的受管读取入口")
	}
	return fail2banManagedExec(ctx, p.managed.python(), argv, 2*time.Second, limit)
}

// readManagedFail2banBatch keeps the official CLI's ordered reads and formatting
// while paying interpreter startup once. The caller supplies the output budget.
func readManagedFail2banBatch(ctx context.Context, r *fail2banManagedRecord, queries [][]string, limit int) ([]string, error) {
	input, err := json.Marshal(queries)
	if err != nil {
		return nil, err
	}
	budget := min(5*time.Second, time.Duration(len(queries))*2*time.Second)
	raw, err := fail2banManagedExec(ctx, r.python(), []string{"-I", "-S", "-B", "-c", fail2banManagedClientBatch, r.PackageRoot, string(input)}, budget, limit)
	if err != nil {
		return nil, err
	}
	var values []string
	if err = json.Unmarshal(raw, &values); err != nil || len(values) != len(queries) {
		return nil, errors.New("官方 jail 只读查询结果不完整")
	}
	return values, nil
}

func (p fail2banProgram) readBatch(ctx context.Context, queries [][]string, limit int) ([]string, error) {
	if p.unselected || p.kind != "fail2ban-client" || !p.tool.Trusted || p.hash == "" || len(queries) < 1 || len(queries) > 3 || limit <= 0 || limit > 128<<10 {
		return nil, errors.New("官方只读查询批次无效或程序未经认证")
	}
	if p.managed == nil {
		values := make([]string, len(queries))
		for i, args := range queries {
			raw, err := p.run(ctx, args, limit)
			if err != nil {
				return nil, err
			}
			values[i] = string(raw)
		}
		return values, nil
	}
	// JSON may expand each byte to a six-byte escape; retain the per-read bound.
	values, err := readManagedFail2banBatch(ctx, p.managed, queries, 6*len(queries)*limit+1024)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if len(value) > limit {
			return nil, errors.New("官方只读查询结果超过限制")
		}
	}
	return values, nil
}

func fail2banManagedProcess(ctx context.Context, r *fail2banManagedRecord, pid int64) error {
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := fail2banManagedEffective(call); err != nil {
		return err
	}
	proc := filepath.Join("/proc", strconv.FormatInt(pid, 10))
	target, err := os.Readlink(filepath.Join(proc, "exe"))
	if err != nil || target != r.PythonPath {
		return errors.New("受管服务实际解释器与批准路径不一致")
	}
	running, err := os.Stat(filepath.Join(proc, "exe"))
	if err != nil {
		return errors.New("受管服务解释器身份无法读取")
	}
	approved, err := os.Stat(r.PythonPath)
	if err != nil || !os.SameFile(running, approved) {
		return errors.New("受管服务未使用当前已批准的解释器文件")
	}
	raw, err := fail2banReadLimited(filepath.Join(proc, "cmdline"), 64<<10)
	if err != nil {
		return err
	}
	argv := append([]string{r.PythonPath}, r.startArgs()...)
	if string(raw) != strings.Join(argv, "\x00")+"\x00" {
		return errors.New("受管服务实际入口、组件路径或配置参数发生变化")
	}
	return ctx.Err()
}
