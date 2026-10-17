package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type Fail2banExistingJailInput struct {
	Profile fail2ban.ExistingJailProfile `json:"profile"`
	Policy  fail2ban.ExistingJailPolicy  `json:"policy"`
}

func readFail2banExistingTuning(ctx context.Context, program fail2banProgram, b *fail2banBinding, name string) (fail2ban.ExistingJailPolicy, error) {
	out := fail2ban.ExistingJailPolicy{Enabled: true, IgnoreIPs: []string{}}
	for _, field := range []struct {
		name string
		dest *int64
	}{{"bantime", &out.BanTime}, {"findtime", &out.FindTime}} {
		raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), name, field.name), 1024)
		if err != nil {
			return out, err
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return out, errors.New("已有 jail 时间参数格式未知")
		}
		*field.dest = value
	}
	raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), name, "maxretry"), 1024)
	if err != nil {
		return out, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return out, errors.New("已有 jail 重试阈值格式未知")
	}
	out.MaxRetry = int(value)
	raw, err = program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), name, "ignoreip"), 16384)
	if err != nil {
		return out, err
	}
	if strings.TrimSpace(string(raw)) == "No IP address/network is ignored" {
		return out.Normalize()
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || lines[0] != "These IP addresses/networks are ignored:" {
		return out, errors.New("已有 jail 忽略列表格式未知")
	}
	for i, line := range lines[1:] {
		prefix := "|- "
		if i == len(lines)-2 {
			prefix = "`- "
		}
		value, ok := strings.CutPrefix(line, prefix)
		if !ok {
			return out, errors.New("已有 jail 忽略列表不完整")
		}
		out.IgnoreIPs = append(out.IgnoreIPs, value)
	}
	return out.Normalize()
}

func fail2banExistingServerConfig(live fail2banLiveService) (string, error) {
	raw, err := fail2banReadLimited("/proc/"+strconv.FormatInt(*live.view.MainPID, 10)+"/cmdline", 64<<10)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != 0 {
		return "", errors.New("已有实例启动参数无法完整读取")
	}
	args := strings.Split(string(raw[:len(raw)-1]), "\x00")
	server := false
	for i, arg := range args {
		for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
			if arg == dir+"/fail2ban-server" {
				server = true
			}
		}
		if arg == "-c" || arg == "--conf" {
			if i+1 == len(args) || args[i+1] != fail2banExistingConfig {
				return "", errors.New("已有实例未使用固定 /etc/fail2ban 配置目录")
			}
		} else if strings.HasPrefix(arg, "--conf=") && arg != "--conf="+fail2banExistingConfig || strings.HasPrefix(arg, "-c") && arg != "-c" && arg != "-c"+fail2banExistingConfig {
			return "", errors.New("已有实例配置目录参数未知")
		}
	}
	if !server {
		return "", errors.New("已有实例不是受支持的固定系统 fail2ban-server 入口")
	}
	return secure.Hash(raw), nil
}

func verifyFail2banExistingAction(ctx context.Context, program fail2banProgram, b *fail2banBinding, name string, commands [][]any) error {
	const action = "nftables-multiport"
	properties := map[string]any{}
	for _, command := range commands {
		if len(command) < 3 {
			continue
		}
		if command[0] == "set" && command[2] == "addaction" {
			if len(command) != 4 || command[3] != action {
				return errors.New("已有 jail 不允许其他动作或 Python action")
			}
		}
		if command[0] == "set" && command[2] == "action" {
			if len(command) != 6 || command[3] != action {
				return errors.New("官方 action 属性格式未知")
			}
			key, k := command[4].(string)
			value := command[5]
			if !k {
				return errors.New("官方 action 属性类型未知")
			}
			if _, exists := properties[key]; exists {
				return errors.New("官方 action 属性重复")
			}
			properties[key] = value
		}
		if command[0] == "multi-set" && command[2] == "action" {
			if len(command) != 5 || command[3] != action {
				return errors.New("官方 action 批量属性格式未知")
			}
			pairs, ok := command[4].([]any)
			if !ok {
				return errors.New("官方 action 属性列表未知")
			}
			for _, item := range pairs {
				pair, ok := item.([]any)
				if !ok || len(pair) != 2 {
					return errors.New("官方 action 属性不完整")
				}
				key, k := pair[0].(string)
				value := pair[1]
				if !k {
					return errors.New("官方 action 属性类型未知")
				}
				if _, exists := properties[key]; exists {
					return errors.New("官方 action 属性重复")
				}
				properties[key] = value
			}
		}
	}
	raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), name, "actions"), 4096)
	if err != nil || strings.TrimSpace(string(raw)) != "The jail "+name+" has the following actions:\n"+action {
		return errors.New("实际 jail 的完整动作列表与官方配置不一致")
	}
	for _, key := range []string{"actionstart", "actionstop", "actioncheck", "actionban", "actionunban"} {
		expected, ok := properties[key].(string)
		if !ok {
			return errors.New("官方 action 缺少必要命令属性")
		}
		raw, err := program.run(ctx, append(fail2banReadArgs(b.Socket, "get"), name, "action", action, key), 64<<10)
		if err != nil || strings.TrimSpace(string(raw)) != strings.TrimSpace(expected) {
			return errors.New("实际 jail 的 action 命令与官方固定配置不一致")
		}
	}
	return nil
}

// Preview is local root admission only. It neither publishes ownership nor
// writes /etc/fail2ban, reloads a jail, or grants a public mutation route.
func PreviewFail2banExistingJail(ctx context.Context, data, scope string, input Fail2banExistingJailInput) (out fail2ban.ExistingJailPlan, resultErr error) {
	out = fail2ban.ExistingJailPlan{At: time.Now().Unix(), Profile: input.Profile, Jails: []string{}, Impacts: []string{}}
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if err := input.Profile.Validate(); err != nil {
		return out, err
	}
	after, err := input.Policy.Normalize()
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	unlock, err := fail2banHostSyncLocks(data)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	leave, err := fail2banHostSyncAdmission(data, true)
	if err != nil {
		return out, err
	}
	defer leave()
	b, err := selectFail2banBinding(data)
	if err != nil {
		return out, err
	}
	if b == nil || b.managed != nil || b.State != "bound" || b.ClientVersion != fail2ban.RegexVersion {
		return out, errors.New("已有 jail 预检要求当前已接入的官方 1.1.1 系统实例")
	}
	unit, err := fail2banExistingUnitHash(ctx, b.Service)
	if err != nil {
		return out, err
	}
	live, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return out, err
	}
	server, err := fail2banExistingServerConfig(live)
	if err != nil {
		return out, err
	}
	program, err := selectFail2banClient(b)
	if err != nil {
		return out, err
	}
	program, err = program.authenticate(ctx)
	if err != nil {
		return out, err
	}
	_, _, raw, err := readFail2banBound(ctx, data, b, true, "")
	if err != nil {
		return out, err
	}
	jails, err := parseFail2banJails(raw)
	if err != nil {
		return out, err
	}
	found := false
	for _, jail := range jails {
		out.Jails = append(out.Jails, jail.Name)
		found = found || jail.Name == input.Profile.Name
	}
	if !found {
		return out, errors.New("首次接管预检要求目标 jail 正在原实例的完整列表中运行")
	}
	sort.Strings(out.Jails)
	before, err := readFail2banExistingTuning(ctx, program, b, input.Profile.Name)
	if err != nil {
		return out, err
	}
	snapshot, err := readFail2banExistingConfig()
	if err != nil {
		return out, err
	}
	commands, err := dumpFail2banExisting(ctx, program, b, fail2banExistingConfig, input.Profile.Name)
	if err != nil {
		return out, err
	}
	backend, err := fail2banExistingBackend(commands, input.Profile.Name)
	if err != nil {
		return out, err
	}
	files, err := fail2banExistingReference(input.Profile, before, backend, snapshot.Files)
	if err != nil {
		return out, err
	}
	base := filepath.Join(fail2banBindingDir(data), "existing-jail-previews")
	if err = secure.RootDirectory(base, 0700); err != nil {
		return out, err
	}
	work, err := os.MkdirTemp(base, ".plan-")
	if err != nil {
		return out, err
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			out.Target = ""
			resultErr = errors.Join(resultErr, errors.New("已有 jail 预检材料清理失败，须本机检查"))
		}
	}()
	referenceDir := filepath.Join(work, "reference-before")
	if err = writeFail2banExistingCandidate(referenceDir, files); err != nil {
		return out, err
	}
	reference, err := dumpFail2banExisting(ctx, program, b, referenceDir, input.Profile.Name)
	if err != nil {
		return out, err
	}
	profileCommands, err := fail2banExistingStableDump(commands, true)
	if err != nil {
		return out, err
	}
	profileReference, err := fail2banExistingStableDump(reference, true)
	if err != nil {
		return out, err
	}
	if fail2banDumpHash(profileCommands) != fail2banDumpHash(profileReference) {
		return out, errors.New("目标 jail 的 filter/action、后端或来源与固定 SSH/nftables INPUT 配置不一致，不能自动接管")
	}
	overlay := "jail.d/zzzz-nginxpanel-existing-" + input.Profile.Name + ".local"
	if _, exists := snapshot.Files[overlay]; exists {
		return out, errors.New("目标 jail 已存在同名接管文件，须核对原操作，禁止覆盖")
	}
	candidate := maps.Clone(snapshot.Files)
	candidate[overlay] = []byte(fail2banExistingOverlay(input.Profile, after))
	candidateDir := filepath.Join(work, "candidate")
	if err = writeFail2banExistingCandidate(candidateDir, candidate); err != nil {
		return out, err
	}
	afterCommands, err := dumpFail2banExisting(ctx, program, b, candidateDir, input.Profile.Name)
	if err != nil {
		return out, err
	}
	afterFiles, err := fail2banExistingReference(input.Profile, after, backend, snapshot.Files)
	if err != nil {
		return out, err
	}
	afterDir := filepath.Join(work, "reference-after")
	if err = writeFail2banExistingCandidate(afterDir, afterFiles); err != nil {
		return out, err
	}
	afterReference, err := dumpFail2banExisting(ctx, program, b, afterDir, input.Profile.Name)
	if err != nil {
		return out, err
	}
	if after.Enabled {
		stableBefore, err := fail2banExistingStableDump(commands, false)
		if err != nil {
			return out, err
		}
		stableAfter, err := fail2banExistingStableDump(afterCommands, false)
		if err != nil {
			return out, err
		}
		if fail2banDumpHash(stableBefore) != fail2banDumpHash(stableAfter) {
			return out, errors.New("候选 jail 改变了参数之外的原配置；未接管")
		}
		if err = checkFail2banExistingTuningDump(afterCommands, afterReference); err != nil {
			return out, err
		}
	} else if len(afterCommands) != 0 || len(afterReference) != 0 {
		return out, errors.New("候选 jail 停用期望被其他配置覆盖；未接管")
	}
	if err = verifyFail2banExistingAction(ctx, program, b, input.Profile.Name, commands); err != nil {
		return out, err
	}
	bans, err := readFail2banHostJail(ctx, program, b.Socket, input.Profile.Name)
	if err != nil {
		return out, err
	}
	current, err := readFail2banExistingConfig()
	if err != nil || current.hash() != snapshot.hash() {
		return out, errors.New("已有 Fail2ban 配置在预检期间变化")
	}
	currentUnit, err := fail2banExistingUnitHash(ctx, b.Service)
	if err != nil || currentUnit != unit {
		return out, errors.New("已有 Fail2ban 服务单元在预检期间变化")
	}
	currentTuning, err := readFail2banExistingTuning(ctx, program, b, input.Profile.Name)
	if err != nil {
		return out, err
	}
	beforeRaw, _ := json.Marshal(before)
	currentRaw, _ := json.Marshal(currentTuning)
	if !bytes.Equal(beforeRaw, currentRaw) {
		return out, errors.New("已有 jail 实际参数在预检期间变化")
	}
	raw, err = program.run(ctx, fail2banReadArgs(b.Socket, "status"), 128<<10)
	if err != nil {
		return out, err
	}
	currentJails, err := parseFail2banJails(raw)
	if err != nil {
		return out, err
	}
	names := make([]string, 0, len(currentJails))
	for _, jail := range currentJails {
		names = append(names, jail.Name)
	}
	sort.Strings(names)
	if strings.Join(names, "\x00") != strings.Join(out.Jails, "\x00") {
		return out, errors.New("已有实例完整 jail 列表在预检期间变化")
	}
	currentLive, err := readFail2banLiveService(ctx, b)
	if err != nil || !sameFail2banLive(live, currentLive) {
		return out, errors.New("已有实例在接管预检期间变化")
	}
	if err = program.unchanged(ctx, data); err != nil {
		return out, err
	}
	if err = fail2banCurrentBinding(data, b, true); err != nil {
		return out, err
	}
	out.BindingID, out.Before, out.After = b.ID, before, after
	out.Impacts = []string{"接管将只生成目标 jail 的独立 jail.d 覆盖文件，保留原 filter/action、日志来源及其他 jail", "应用需另行确认并通过官方单 jail reload；可能短暂影响 SSH 保护，须核对原剩余封禁", "本机预检不授予接管权，不修改系统配置或当前保护"}
	raw, _ = json.Marshal(struct {
		Binding                                                         *fail2banBinding
		Unit, Server, Config, Program, AfterProgram, Invocation, Socket string
		Input                                                           Fail2banExistingJailInput
		Before                                                          fail2ban.ExistingJailPolicy
		Jails                                                           []string
		Bans                                                            map[string]fail2banHostBanTime
	}{b, unit, server, snapshot.hash(), fail2banDumpHash(commands), fail2banDumpHash(afterCommands), live.invocation, live.inode, Fail2banExistingJailInput{input.Profile, after}, before, out.Jails, bans})
	out.Target = secure.Hash(raw)
	return out, ctx.Err()
}

func PreviewFail2banExistingJailFile(ctx context.Context, data, scope, path string) (fail2ban.ExistingJailPlan, error) {
	if err := fail2banManagedRoot(data, scope); err != nil {
		return fail2ban.ExistingJailPlan{}, err
	}
	raw, err := secure.ReadRootFile(path, 16<<10)
	if err != nil {
		return fail2ban.ExistingJailPlan{}, err
	}
	var input Fail2banExistingJailInput
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		return fail2ban.ExistingJailPlan{}, errors.New("已有 jail 预检文件须为明确的 profile/policy JSON 对象")
	}
	return PreviewFail2banExistingJail(ctx, data, scope, input)
}
