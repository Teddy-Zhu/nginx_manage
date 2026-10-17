package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

const ufwDryRunCommands = 64

type ufwFileSnapshot struct {
	Path              string
	Present           bool
	Hash              string
	Bytes             int64
	Device, Inode     uint64
	Mode              uint32
	Modified, Changed int64
}
type ufwConfigurationSnapshot struct {
	Files             []ufwFileSnapshot
	Contents          map[string][]byte
	Hash, ToolHash    string
	HasManagedMarkers bool
}

type ufwDryRunProof struct {
	Hash, NativeHash, BatchHash string
	PreservedRules              int
	Warnings                    []string
}

func ufwTool() (string, error) {
	for _, path := range []string{"/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"} {
		if resolved, err := trustedFile(path, true); err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("受信 UFW 程序不可用")
}

type ufwConfigurationSource struct {
	path     string
	required bool
}

func ufwConfigurationSources(binary string, ipv6 bool) []ufwConfigurationSource {
	return []ufwConfigurationSource{
		{binary, true}, {"/etc/ufw/ufw.conf", true}, {"/etc/default/ufw", true},
		{"/etc/ufw/user.rules", true}, {"/etc/ufw/before.rules", true}, {"/etc/ufw/after.rules", true},
		{"/etc/ufw/user6.rules", ipv6}, {"/etc/ufw/before6.rules", ipv6}, {"/etc/ufw/after6.rules", ipv6},
		{"/etc/ufw/sysctl.conf", false}, {"/etc/ufw/before.init", false}, {"/etc/ufw/after.init", false},
	}
}

// Capture fixed source files without interpreting shell settings. These bytes
// supply the private dry-run workspace; they never become portable policy.
// Repeated reads detect drift, not an atomic lock.
func readUFWConfiguration(ctx context.Context, binary string, ipv6 bool) (ufwConfigurationSnapshot, error) {
	out := ufwConfigurationSnapshot{Files: []ufwFileSnapshot{}, Contents: map[string][]byte{}}
	total := 0
	for _, source := range ufwConfigurationSources(binary, ipv6) {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if err := existingRootDirectory(filepath.Dir(source.path)); err != nil {
			return out, err
		}
		file := ufwFileSnapshot{Path: source.path}
		before, err := os.Lstat(source.path)
		if os.IsNotExist(err) && !source.required {
			out.Files = append(out.Files, file)
			continue
		}
		if err != nil {
			return out, err
		}
		raw, err := nginxmodules.ReadTrusted(source.path, firewall.UFWReadBytes)
		if err != nil {
			return out, err
		}
		after, err := os.Lstat(source.path)
		if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
			return out, errors.New("UFW 配置在读取期间变化")
		}
		stat, ok := after.Sys().(*syscall.Stat_t)
		if !ok {
			return out, errors.New("UFW 配置文件身份不可核对")
		}
		total += len(raw)
		if total > 4<<20 {
			return out, errors.New("UFW 固定配置超过 4 MiB")
		}
		file.Present, file.Hash, file.Bytes = true, secure.Hash(raw), int64(len(raw))
		if source.path != binary {
			out.Contents[source.path] = raw
		}
		if source.path != binary && (strings.Contains(string(raw), "nginxpanel:host:") || strings.Contains(strings.ToLower(string(raw)), hex.EncodeToString([]byte("nginxpanel:host:")))) {
			out.HasManagedMarkers = true
		}
		file.Device, file.Inode, file.Mode = uint64(stat.Dev), stat.Ino, uint32(after.Mode())
		file.Modified, file.Changed = after.ModTime().UnixNano(), stat.Ctim.Sec*1e9+stat.Ctim.Nsec
		out.Files = append(out.Files, file)
		if source.path == binary {
			out.ToolHash = file.Hash
		}
	}
	raw, err := json.Marshal(out.Files)
	if err != nil {
		return out, err
	}
	out.Hash = secure.Hash(raw)
	return out, nil
}

// prepend refuses a matching existing selector instead of updating its action
// or comment. Reverse prepend steps accumulate only in the private datadir;
// every candidate and the final per-family order must match the typed program.
// This prepares a file batch, not a kernel transaction or ownership grant.
func checkUFWDryRun(ctx context.Context, binary string, program *firewall.UFWProgram, baseline ufwConfigurationSnapshot, ipv6 bool) (proof ufwDryRunProof, resultErr error) {
	defer func() {
		if resultErr != nil {
			proof = ufwDryRunProof{}
		}
	}()
	if len(program.Rules) > ufwDryRunCommands || len(program.Rules) != len(program.Entries) {
		return proof, errors.New("UFW dry-run 计划最多 64 条包含入口保护的命令")
	}
	before := map[string]*ufwNativeFile{}
	for _, item := range []struct{ family, path string }{{"ipv4", "/etc/ufw/user.rules"}, {"ipv6", "/etc/ufw/user6.rules"}} {
		if item.family == "ipv6" && !ipv6 {
			continue
		}
		raw := baseline.Contents[item.path]
		file, err := parseUFWNative(raw, item.family, true)
		if err != nil {
			return proof, err
		}
		before[item.family] = file
		proof.PreservedRules += len(file.Rules)
	}
	if proof.PreservedRules+len(program.Rules) > firewall.MaxEntries {
		return proof, errors.New("UFW 既有及生成原生用户规则合计超过 8192 条")
	}
	expected := []ufwNativeRule{}
	for index, rule := range program.Rules {
		entry, err := expectedUFWNative(rule, program.Entries[index])
		if err != nil {
			return proof, err
		}
		if before[entry.Family] == nil {
			return proof, errors.New("UFW 生成规则缺少对应地址族的原生配置基线")
		}
		expected = append(expected, entry)
	}
	native, err := json.Marshal(expected)
	if err != nil {
		return proof, err
	}
	if len(native) > firewall.UFWProgramBytes {
		return proof, errors.New("UFW 生成原生规则超过 480 KiB")
	}
	proof.NativeHash = secure.Hash(append([]byte("ufw:native-host:v1:\x00"), native...))
	proof.Warnings = []string{}
	warned := map[string]bool{}
	const parent = "/run/nginxpanel-host"
	if err := secure.RootDirectory(parent, 0700); err != nil {
		return proof, err
	}
	items, err := os.ReadDir(parent)
	if err != nil {
		return proof, err
	}
	stale := 0
	for _, item := range items {
		if strings.HasPrefix(item.Name(), "ufw-check-") {
			stale++
		}
	}
	if stale >= 16 {
		return proof, errors.New("UFW 私有预演目录达到上限，须本机核对遗留进程与目录")
	}
	temp, err := os.MkdirTemp(parent, "ufw-check-")
	if err != nil {
		return proof, err
	}
	defer func() {
		if err := os.RemoveAll(temp); err != nil {
			resultErr = errors.Join(resultErr, errors.New("UFW 私有预演目录清理失败，须本机核对"))
		}
	}()
	workspace, err := newUFWDryRunWorkspace(ctx, temp, baseline)
	if err != nil {
		return proof, err
	}
	current := map[string]*ufwNativeFile{}
	for family, file := range before {
		current[family] = file
	}
	hashes := []string{}
	total := 0
	for index := len(program.Rules) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return proof, err
		}
		rule := program.Rules[index]
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		args := append([]string{"--datadir=" + temp, "--dry-run", "prepend"}, rule.Arguments...)
		command := exec.CommandContext(call, binary, args...)
		command.Dir = "/"
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1", "TMPDIR=" + filepath.Join(temp, "tmp")}
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
		command.WaitDelay = 250 * time.Millisecond
		stdout, stderr := firewallOutput{limit: 1 << 20}, firewallOutput{limit: 8 << 10}
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		cancel()
		if err != nil || stdout.exceeded || stderr.exceeded || stderr.data.Len() != 0 {
			return proof, errors.New("UFW dry-run 失败、超时或返回警告；未执行规则变更")
		}
		raw := stdout.data.Bytes()
		total += len(raw)
		if total > 8<<20 {
			return proof, errors.New("UFW dry-run 完整输出合计超过 8 MiB")
		}
		candidate, err := parseUFWDryRunCandidate(raw, expected[index], current[expected[index].Family])
		if err != nil {
			return proof, err
		}
		if err = ctx.Err(); err != nil {
			return proof, err
		}
		if err = workspace.replace(expected[index].Family, candidate.Content); err != nil {
			return proof, err
		}
		current[expected[index].Family] = candidate.File
		if candidate.Warning != "" && !warned[candidate.Warning] {
			proof.Warnings = append(proof.Warnings, candidate.Warning)
			warned[candidate.Warning] = true
		}
		hashes = append(hashes, secure.Hash(raw))
	}
	raw, err := json.Marshal(hashes)
	if err != nil {
		return proof, err
	}
	proof.Hash = secure.Hash(append([]byte("ufw:dry-run:v1:\x00"), raw...))
	if err = verifyUFWBatchOrder(before, current, expected); err != nil {
		return proof, err
	}
	if err = workspace.verify(ctx); err != nil {
		return proof, err
	}
	proof.BatchHash, err = workspace.digest(baseline.Hash, proof.NativeHash, proof.Hash)
	if err != nil {
		return proof, err
	}
	return proof, nil
}

type ufwDryRunCandidate struct {
	File    *ufwNativeFile
	Content []byte
	Warning string
}

func parseUFWDryRunCandidate(raw []byte, expected ufwNativeRule, before *ufwNativeFile) (*ufwDryRunCandidate, error) {
	status := "Rules updated\n"
	if expected.Family == "ipv6" {
		status = "Rules updated (v6)\n"
	}
	text, ok := strings.CutSuffix(string(raw), status)
	if !ok {
		return nil, errors.New("UFW dry-run 缺少对应地址族的更新结果，或已有匹配条件冲突")
	}
	if len(text) > firewall.UFWReadBytes {
		return nil, errors.New("UFW 累积候选文件超过 512 KiB")
	}
	candidate, err := parseUFWNative([]byte(text), expected.Family, false)
	if err != nil {
		return nil, err
	}
	warning, err := ufwNativePreserved(before, candidate, expected)
	if err != nil {
		return nil, err
	}
	return &ufwDryRunCandidate{File: candidate, Content: []byte(text), Warning: warning}, nil
}
