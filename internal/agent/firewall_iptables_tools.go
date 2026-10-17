package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/secure"
)

const iptablesExportBytes = 1 << 20

type iptablesToolVersion struct {
	Role, Version string
}

// File identities and pinned ELF checks are shared with the UFW transport.
// No source, script, default applet or PATH-selected backend is executable here.
type iptablesToolBinding struct {
	Backend  string
	Files    []ufwBoundFile
	Versions []iptablesToolVersion
	Hash     string
}

func iptablesToolRoles(backend string) []string {
	if !validIPTablesBackend(backend) {
		return nil
	}
	out := []string{}
	for _, name := range []string{backend, "ip6tables-" + strings.TrimPrefix(backend, "iptables-")} {
		out = append(out, name, name+"-save", name+"-restore")
	}
	return append(out, "false")
}

func iptablesToolsHash(binding *iptablesToolBinding) string {
	raw, _ := json.Marshal(struct {
		Backend  string
		Files    []ufwBoundFile
		Versions []iptablesToolVersion
	}{binding.Backend, binding.Files, binding.Versions})
	return secure.Hash(append([]byte("iptables:tools:v1:\x00"), raw...))
}

func bindIPTablesTools(ctx context.Context, backend string) (*iptablesToolBinding, error) {
	roles := iptablesToolRoles(backend)
	if len(roles) == 0 {
		return nil, errors.New("iptables 工具必须绑定显式 nft 或 legacy 后端")
	}
	binding := &iptablesToolBinding{Backend: backend, Files: []ufwBoundFile{}, Versions: []iptablesToolVersion{}}
	var total int64
	for _, role := range roles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, err := ufwSystemCommand(role)
		if err != nil {
			return nil, errors.New("iptables 固定系统工具路径无法核对：" + role)
		}
		tool, err := readUFWBoundFile(role, path, true, 16<<20)
		if err != nil {
			return nil, errors.New("iptables 工具文件身份无法核对：" + role)
		}
		total += tool.File.Bytes
		if total > 64<<20 {
			return nil, errors.New("iptables 工具合计超过 64 MiB")
		}
		tool.Raw = nil
		// Require the same ELF and permission constraints even for tools that
		// are currently only bound for later native rule reads.
		file, err := openUFWRestoreELF(tool)
		if err != nil {
			return nil, errors.New("iptables 工具不是可固定的受信普通 ELF：" + role)
		}
		file.Close()
		binding.Files = append(binding.Files, tool)
	}
	blocker, err := binding.tool("false")
	if err != nil {
		return nil, err
	}
	wanted := "nftables"
	if backend == "iptables-legacy" {
		wanted = "legacy"
	}
	var release string
	for _, tool := range binding.Files[:6] {
		raw, err := runIPTablesBound(ctx, tool, blocker, "version", nil)
		if err != nil {
			return nil, err
		}
		kind, version, err := firewallVersion(raw)
		_, current, found := strings.Cut(version, " ")
		if err != nil || kind != wanted || !found || release != "" && current != release {
			return nil, errors.New("iptables command/save/restore 的后端或发行版本不一致")
		}
		release = current
		binding.Versions = append(binding.Versions, iptablesToolVersion{Role: tool.Role, Version: version})
	}
	binding.Hash = iptablesToolsHash(binding)
	if err = binding.verify(ctx); err != nil {
		return nil, err
	}
	return binding, nil
}

func (binding *iptablesToolBinding) tool(role string) (ufwBoundFile, error) {
	if binding == nil || !slices.Contains(iptablesToolRoles(binding.Backend), role) {
		return ufwBoundFile{}, errors.New("iptables 工具角色未绑定")
	}
	for _, tool := range binding.Files {
		if tool.Role == role {
			return tool, nil
		}
	}
	return ufwBoundFile{}, errors.New("iptables 固定工具缺失")
}

func (binding *iptablesToolBinding) verify(ctx context.Context) error {
	if binding == nil || !validIPTablesBackend(binding.Backend) || len(binding.Files) != 7 || len(binding.Versions) != 6 || binding.Hash != iptablesToolsHash(binding) {
		return errors.New("iptables 完整工具绑定无效")
	}
	for index, role := range iptablesToolRoles(binding.Backend) {
		if err := ctx.Err(); err != nil {
			return err
		}
		before := binding.Files[index]
		if before.Role != role || index < 6 && binding.Versions[index].Role != role || !before.Executable || len(before.Raw) != 0 || !validUFWFileSnapshot(before.File, true, 16<<20) {
			return errors.New("iptables 工具身份或角色无效")
		}
		path, err := ufwSystemCommand(role)
		if err != nil || path != before.Invoked {
			return errors.New("iptables 系统工具选择已变化")
		}
		after, err := readUFWBoundFile(role, before.Invoked, true, 16<<20)
		if err != nil || after.File != before.File {
			return errors.New("iptables 固定工具文件已变化，请重新生成计划")
		}
	}
	return nil
}

func (binding *iptablesToolBinding) image(ctx context.Context, family string) (iptablesImage, error) {
	var empty iptablesImage
	name := binding.Backend
	if family == "ipv6" {
		name = "ip6tables-" + strings.TrimPrefix(name, "iptables-")
	} else if family != "ipv4" {
		return empty, errors.New("iptables 固定导出的地址族无效")
	}
	tool, err := binding.tool(name + "-save")
	if err != nil {
		return empty, err
	}
	blocker, err := binding.tool("false")
	if err != nil {
		return empty, err
	}
	raw, err := runIPTablesBound(ctx, tool, blocker, "rules", nil)
	if err != nil {
		return empty, err
	}
	return parseIPTablesImage(raw, family)
}

// This closed transport cannot execute a real rule mutation. --test remains
// unconditional for restore; original argv[0] selects the pinned multi-applet.
// A blocker inherited by descriptor prevents explicit modprobe fallback.
func runIPTablesBound(ctx context.Context, tool, blocker ufwBoundFile, action string, input []byte) ([]byte, error) {
	args, limit := []string{"--version"}, 1024
	roles := append(iptablesToolRoles("iptables-nft"), iptablesToolRoles("iptables-legacy")...)
	if !slices.Contains(roles, tool.Role) || tool.Role == "false" || filepath.Base(tool.Invoked) != tool.Role || blocker.Role != "false" {
		return nil, errors.New("iptables 固定操作工具无效")
	}
	switch action {
	case "version":
		if len(input) != 0 {
			return nil, errors.New("iptables 版本读取不能包含执行材料")
		}
	case "rules":
		if !strings.HasSuffix(tool.Role, "-save") || len(input) != 0 {
			return nil, errors.New("iptables 规则读取工具无效")
		}
		args, limit = []string{"--modprobe", "/proc/self/fd/4"}, iptablesExportBytes
	case "test":
		if !strings.HasSuffix(tool.Role, "-restore") || len(input) == 0 || len(input) > 4<<20 || !bytes.HasPrefix(input, []byte("*filter\n")) || !bytes.HasSuffix(input, []byte("COMMIT\n")) {
			return nil, errors.New("iptables 官方预演材料无效或超过 4 MiB")
		}
		args, limit = []string{"--test", "--noflush", "--wait", "1", "--modprobe", "/proc/self/fd/4"}, 8<<10
	default:
		return nil, errors.New("iptables 固定工具不允许该操作")
	}
	binary, err := openUFWRestoreELF(tool)
	if err != nil {
		return nil, errors.New("iptables 当前工具与固定 ELF 不一致")
	}
	defer binary.Close()
	blocked, err := openUFWRestoreELF(blocker)
	if err != nil {
		return nil, errors.New("iptables 模块加载阻断工具已变化")
	}
	defer blocked.Close()
	// Pdeathsig is tied to the thread creating the child, not the Go process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(call, "/proc/self/fd/3", args...)
	command.Args[0] = tool.Invoked
	command.ExtraFiles = []*os.File{binary, blocked}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	command.Stdin = bytes.NewReader(input)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 250 * time.Millisecond
	stdout, stderr := firewallOutput{limit: limit}, firewallOutput{limit: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	if err = command.Run(); err != nil || call.Err() != nil || stdout.exceeded || stderr.exceeded || stderr.data.Len() != 0 || action == "test" && stdout.data.Len() != 0 {
		return nil, errors.New("iptables 固定工具失败、超时、警告或输出超限：" + tool.Role)
	}
	return stdout.data.Bytes(), nil
}
