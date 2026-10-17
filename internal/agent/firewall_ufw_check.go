package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

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
	Files          []ufwFileSnapshot
	Hash, ToolHash string
}

func ufwTool() (string, error) {
	for _, path := range []string{"/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"} {
		if resolved, err := trustedFile(path, true); err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("受信 UFW 程序不可用")
}

// Capture a fixed set of source files without interpreting shell settings or
// copying them into the policy. Repeated reads detect drift, not an atomic lock.
func readUFWConfiguration(ctx context.Context, binary string, ipv6 bool) (ufwConfigurationSnapshot, error) {
	out := ufwConfigurationSnapshot{Files: []ufwFileSnapshot{}}
	sources := []struct {
		path     string
		required bool
	}{
		{binary, true}, {"/etc/ufw/ufw.conf", true}, {"/etc/default/ufw", true},
		{"/etc/ufw/user.rules", true}, {"/etc/ufw/before.rules", true}, {"/etc/ufw/after.rules", true},
		{"/etc/ufw/user6.rules", ipv6}, {"/etc/ufw/before6.rules", ipv6}, {"/etc/ufw/after6.rules", ipv6},
		{"/etc/ufw/sysctl.conf", false}, {"/etc/ufw/before.init", false}, {"/etc/ufw/after.init", false},
	}
	total := 0
	for _, source := range sources {
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
// or comment. Every invocation still starts from the same live source files;
// this is individual syntax/conflict preparation, not a batch application proof.
func checkUFWDryRun(ctx context.Context, binary string, program *firewall.UFWProgram) (digest string, resultErr error) {
	if len(program.Rules) > ufwDryRunCommands || len(program.Rules) != len(program.Entries) {
		return "", errors.New("UFW dry-run 计划最多 64 条包含入口保护的命令")
	}
	const parent = "/run/nginxpanel-host"
	if err := secure.RootDirectory(parent, 0700); err != nil {
		return "", err
	}
	items, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	stale := 0
	for _, item := range items {
		if strings.HasPrefix(item.Name(), "ufw-check-") {
			stale++
		}
	}
	if stale >= 16 {
		return "", errors.New("UFW 私有预演目录达到上限，须本机核对遗留进程与目录")
	}
	temp, err := os.MkdirTemp(parent, "ufw-check-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(temp); err != nil {
			digest = ""
			resultErr = errors.Join(resultErr, errors.New("UFW 私有预演目录清理失败，须本机核对"))
		}
	}()
	hashes := []string{}
	total := 0
	for index, rule := range program.Rules {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		args := append([]string{"--dry-run", "prepend"}, rule.Arguments...)
		command := exec.CommandContext(call, binary, args...)
		command.Dir = "/"
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1", "TMPDIR=" + temp}
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
		command.WaitDelay = 250 * time.Millisecond
		stdout, stderr := firewallOutput{limit: 1 << 20}, firewallOutput{limit: 8 << 10}
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		cancel()
		if err != nil || stdout.exceeded || stderr.exceeded || stderr.data.Len() != 0 {
			return "", errors.New("UFW dry-run 失败、超时或返回警告；未执行规则变更")
		}
		raw := stdout.data.Bytes()
		total += len(raw)
		if total > 8<<20 || !ufwDryRunMatches(raw, rule, program.Entries[index]) {
			return "", errors.New("UFW dry-run 存在既有规则冲突、未知候选结果或超过预算")
		}
		hashes = append(hashes, secure.Hash(raw))
	}
	raw, err := json.Marshal(hashes)
	if err != nil {
		return "", err
	}
	return secure.Hash(append([]byte("ufw:dry-run:v1:\x00"), raw...)), nil
}

func ufwDryRunMatches(raw []byte, rule firewall.UFWRule, entry firewall.PreviewEntry) bool {
	if len(raw) == 0 || !utf8.Valid(raw) || len(rule.Arguments) < 3 {
		return false
	}
	prefix, status, anywhere := "ufw", "Rules updated", "0.0.0.0/0"
	if entry.Family == "ipv6" {
		prefix, status, anywhere = "ufw6", "Rules updated (v6)", "::/0"
	}
	source, err := netip.ParsePrefix(entry.Source)
	if err != nil {
		return false
	}
	sourceText := source.String()
	if source.Bits() == source.Addr().BitLen() {
		sourceText = source.Addr().String() // UFW removes /32 and /128 host masks.
	}
	ports := strconv.Itoa(entry.Ports.From)
	if entry.Ports.From != entry.Ports.To {
		ports += ":" + strconv.Itoa(entry.Ports.To)
	}
	direction := "in"
	if entry.Interface != "" {
		direction += "_" + entry.Interface
	}
	comment := hex.EncodeToString([]byte(rule.Arguments[len(rule.Arguments)-1]))
	tuple := "### tuple ### " + strings.Join([]string{entry.Action, entry.Protocol, ports, anywhere, "any", sourceText, direction, "comment=" + comment}, " ")
	text := string(raw)
	if !strings.HasPrefix(text, "*filter\n:"+prefix+"-user-input ") || !strings.HasSuffix(text, "COMMIT\n"+status+"\n") {
		return false
	}
	if strings.Count(text, "comment="+comment) != 1 {
		return false
	}
	rules, ok := ufwDryRunSections(strings.TrimSuffix(text, status+"\n"), prefix)
	if !ok {
		return false
	}
	for _, line := range strings.Split(rules, "\n") {
		if line != "" {
			return line == tuple
		}
	}
	return false
}

// This recognizes the official candidate file layout, not the semantics of
// arbitrary iptables expressions or the completeness of existing UFW rules.
func ufwDryRunSections(candidate, prefix string) (string, bool) {
	for _, char := range candidate {
		if char < 0x20 && char != '\n' || char == 0x7f {
			return "", false
		}
	}
	header := "*filter\n"
	for _, suffix := range []string{"user-input", "user-output", "user-forward", "before-logging-input", "before-logging-output", "before-logging-forward", "user-logging-input", "user-logging-output", "user-logging-forward", "after-logging-input", "after-logging-output", "after-logging-forward", "logging-deny", "logging-allow"} {
		header += ":" + prefix + "-" + suffix + " - [0:0]\n"
	}
	rest, ok := strings.CutPrefix(candidate, header)
	if !ok {
		return "", false
	}
	limitHeader := ":" + prefix + "-user-limit - [0:0]\n:" + prefix + "-user-limit-accept - [0:0]\n"
	rest, limiting := strings.CutPrefix(rest, limitHeader)
	rest, ok = strings.CutPrefix(rest, "### RULES ###\n")
	if !ok {
		return "", false
	}
	rules, rest, ok := strings.Cut(rest, "\n### END RULES ###\n")
	if !ok || !ufwCandidateLines(rules, prefix, true) {
		return "", false
	}
	rest, ok = strings.CutPrefix(rest, "\n### LOGGING ###\n")
	if !ok {
		return "", false
	}
	logging, rest, ok := strings.Cut(rest, "### END LOGGING ###\n")
	if !ok || !ufwCandidateLines(logging, prefix, false) {
		return "", false
	}
	if limiting {
		rest, ok = strings.CutPrefix(rest, "\n### RATE LIMITING ###\n")
		if !ok {
			return "", false
		}
		rate, tail, found := strings.Cut(rest, "### END RATE LIMITING ###\n")
		if !found || !ufwCandidateLines(rate, prefix, false) {
			return "", false
		}
		rest = tail
	}
	return rules, rest == "COMMIT\n"
}

func ufwCandidateLines(section, prefix string, tuples bool) bool {
	packetRules := 0
	for _, line := range strings.Split(section, "\n") {
		switch {
		case line == "":
		case tuples && strings.HasPrefix(line, "### tuple ### "):
		case strings.HasPrefix(line, "-A "+prefix+"-"):
			packetRules++
		case !tuples && strings.HasPrefix(line, "-I "+prefix+"-"):
			packetRules++
		default:
			return false
		}
	}
	return !tuples || packetRules > 0
}
