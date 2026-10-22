package agent

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func compileFail2banExistingPolicyFiles(ctx context.Context, data string, p fail2banProgram, b *fail2banBinding, files map[string][]byte, name string, enabled bool) (commands [][]any, resultErr error) {
	base := filepath.Join(fail2banExistingDir(data), "policy-previews")
	if err := secure.RootDirectory(base, 0700); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(base, ".plan-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			commands = nil
			resultErr = errors.Join(resultErr, errors.New("已有 jail 参数预检材料清理失败"))
		}
	}()
	if err = writeFail2banExistingCandidate(work, files); err != nil {
		return nil, err
	}
	live, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return nil, err
	}
	started, err := fail2banExistingStarted(ctx, b, live)
	if err != nil {
		return nil, err
	}
	python, _, err := fail2banExistingClockProgram(live, started)
	if err != nil {
		return nil, err
	}
	c := &fail2banExistingPolicyCapture{Plan: Fail2banExistingPolicyPlan{Name: name}}
	raw, err := fail2banManagedExec(ctx, python, fail2banExistingPolicyClientArgs(p, c, work, b.Socket, "-d"), 2*time.Second, 2<<20)
	if err != nil {
		return nil, errors.New("官方单 jail 配置编译失败，或 include 超出冻结配置目录")
	}
	return parseFail2banExistingPolicyDump(raw, name, enabled)
}

func existingPolicyJails(names []string, name string, enabled bool) []string {
	out := make([]string, 0, len(names)+1)
	for _, value := range names {
		if value != name {
			out = append(out, value)
		}
	}
	if enabled {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func PlanFail2banExistingPolicyFile(ctx context.Context, data, scope, adoption, inputFile string) (Fail2banExistingPolicyPlan, error) {
	var out Fail2banExistingPolicyPlan
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if !validID(adoption) {
		return out, errors.New("参数计划须指定当前接管 UUID")
	}
	input, err := readFail2banExistingJailInput(inputFile)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
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
	c, err := planFail2banExistingPolicyLocked(ctx, data, adoption, input)
	if err != nil {
		return out, err
	}
	return c.Plan, nil
}

func planFail2banExistingPolicyLocked(ctx context.Context, data, adoption string, input Fail2banExistingJailInput) (*fail2banExistingPolicyCapture, error) {
	after, err := input.Policy.Normalize()
	if err != nil {
		return nil, err
	}
	if err = input.Profile.Validate(); err != nil {
		return nil, err
	}
	var evidence fail2banExistingRuntimeEvidence
	runtime, err := readFail2banExistingRuntimeLocked(ctx, data, adoption, nil, &evidence)
	if err != nil {
		return nil, err
	}
	original, before := evidence.Capture, evidence.Selection
	if !sameFail2banExistingInput(Fail2banExistingJailInput{original.Plan.Profile, after}, Fail2banExistingJailInput{input.Profile, after}) {
		return nil, errors.New("参数变更不能改变原接管 profile、来源或端口")
	}
	if equalFail2banExistingPolicy(before.Policy, after) {
		return nil, errors.New("期望参数与当前已确认参数一致")
	}
	name := original.Plan.Profile.Name
	overlay := fail2banExistingOverlayName(name)
	if string(evidence.Config.Files[overlay]) != fail2banExistingOverlay(original.Plan.Profile, before.Policy) {
		return nil, errors.New("当前参数覆盖文件与已确认选择不同")
	}
	if err = checkFail2banExistingPolicyWritable(); err != nil {
		return nil, err
	}
	// Even while disabled, prove the exact configuration that would be started.
	// An empty disabled dump cannot hide a changed filter/action or backend.
	forcedBefore := before.Policy
	forcedBefore.Enabled = true
	files := maps.Clone(evidence.Config.Files)
	files[overlay] = []byte(fail2banExistingOverlay(original.Plan.Profile, forcedBefore))
	beforeCommands, err := compileFail2banExistingPolicyFiles(ctx, data, evidence.Program, &original.Binding, files, name, true)
	if err != nil {
		return nil, err
	}
	if fail2banDumpHash(beforeCommands) != before.EnabledDumpHash {
		return nil, errors.New("已接管 jail 的启用配置在外部变化")
	}
	backend, err := fail2banExistingBackend(beforeCommands, name)
	if err != nil {
		return nil, err
	}
	forcedAfter := after
	forcedAfter.Enabled = true
	files[overlay] = []byte(fail2banExistingOverlay(original.Plan.Profile, forcedAfter))
	enabledCommands, err := compileFail2banExistingPolicyFiles(ctx, data, evidence.Program, &original.Binding, files, name, true)
	if err != nil {
		return nil, err
	}
	if err = compareFail2banExistingPolicyDump(beforeCommands, enabledCommands); err != nil {
		return nil, err
	}
	reference, err := fail2banExistingReference(original.Plan.Profile, forcedAfter, backend, evidence.Config.Files)
	if err != nil {
		return nil, err
	}
	referenceCommands, err := compileFail2banExistingPolicyFiles(ctx, data, evidence.Program, &original.Binding, reference, name, true)
	if err != nil {
		return nil, err
	}
	if err = checkFail2banExistingTuningDump(enabledCommands, referenceCommands); err != nil {
		return nil, err
	}
	afterCommands := enabledCommands
	if !after.Enabled {
		files[overlay] = []byte(fail2banExistingOverlay(original.Plan.Profile, after))
		afterCommands, err = compileFail2banExistingPolicyFiles(ctx, data, evidence.Program, &original.Binding, files, name, false)
		if err != nil {
			return nil, err
		}
		if len(afterCommands) != 0 {
			return nil, errors.New("停用期望被其他配置覆盖")
		}
	}
	current, err := readFail2banExistingConfig()
	if err != nil || current.hash() != evidence.Config.hash() {
		return nil, errors.New("参数预检期间系统配置变化")
	}
	live, err := readFail2banLiveService(ctx, &original.Binding)
	if err != nil || !sameFail2banLive(live, evidence.Live) {
		return nil, errors.New("参数预检期间服务变化")
	}
	if err = verifyFail2banExistingConfigSource(live, current); err != nil {
		return nil, err
	}
	unit, err := fail2banExistingUnitHash(ctx, original.Binding.Service)
	if err != nil || unit != original.Unit {
		return nil, errors.New("参数预检期间服务单元变化")
	}
	server, err := fail2banExistingServerConfig(live)
	if err != nil {
		return nil, err
	}
	if err = evidence.Program.unchanged(ctx, data); err != nil {
		return nil, err
	}
	if err = fail2banCurrentBinding(data, &original.Binding, true); err != nil {
		return nil, err
	}
	plan := Fail2banExistingPolicyPlan{At: time.Now().Unix(), AdoptionID: adoption, BindingID: original.Binding.ID, BaseID: before.ID, Name: name, Before: before.Policy, After: after, BanCount: len(runtime.Bans), StopConfirmation: before.Policy.Enabled && !after.Enabled, Impacts: []string{"只替换本应用的独立覆盖文件，并通过官方客户端 reload 当前 jail；不重启全局实例", "保留其他 jail；继续启用时核对原未到期封禁及绝对到期时间，不重放封禁"}}
	stopProof := ""
	if plan.StopConfirmation {
		raw, _ := json.Marshal(runtime.Bans)
		stopProof = secure.Hash(raw)
		plan.Impacts = append(plan.Impacts, "停止此 SSH jail 将结束其当前封禁保护，须单独明确确认")
	}
	raw, _ := json.Marshal([]any{runtime.Target, after, fail2banDumpHash(afterCommands), fail2banDumpHash(enabledCommands), stopProof})
	plan.Target = secure.Hash(raw)
	next := fail2banExistingPolicySelection{Schema: 1, AdoptionID: adoption, PreviousID: before.ID, Policy: after, DumpHash: fail2banDumpHash(afterCommands), EnabledDumpHash: fail2banDumpHash(enabledCommands), NativeProof: before.NativeProof}
	if len(existingPolicyJails(runtime.Jails, name, after.Enabled)) > 64 {
		return nil, errors.New("启用后的完整 jail 名单超出限制")
	}
	return &fail2banExistingPolicyCapture{Schema: 1, Plan: plan, BaseTarget: runtime.Target, Unit: unit, Server: server, Invocation: live.invocation, Socket: live.inode, ClockProof: runtime.ClockProof, StopBanProof: stopProof, Snapshot: evidence.Config, BeforeJails: runtime.Jails, AfterJails: existingPolicyJails(runtime.Jails, name, after.Enabled), Before: before, After: next}, ctx.Err()
}

// Inspect the executing process's mount, not the host's view. Root CLI access
// does not prove that the Agent's systemd namespace can replace the overlay.
func checkFail2banExistingPolicyWritable() error {
	dir := filepath.Join(fail2banExistingConfig, "jail.d")
	if err := existingRootDirectory(dir); err != nil {
		return err
	}
	fd, err := secure.OpenReadNoSymlinks(unix.AT_FDCWD, dir, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Flags&unix.ST_RDONLY != 0 {
		return errors.New("已有 Fail2ban jail.d 在当前执行环境只读，须由本机管理员核对 Agent 目录写入授权及挂载状态")
	}
	return nil
}

func sameExistingPolicyJails(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func fail2banExistingMatchLimits(commands [][]any) (retry, matches int64, resultErr error) {
	for _, command := range commands {
		if len(command) != 4 || command[0] != "set" {
			continue
		}
		switch command[2] {
		case "maxretry":
			if retry != 0 {
				return 0, 0, errors.New("maxretry 配置重复")
			}
			retry, _ = command[3].(int64)
		case "maxmatches":
			if matches != 0 {
				return 0, 0, errors.New("maxmatches 配置重复")
			}
			matches, _ = command[3].(int64)
		}
	}
	if retry < 1 || retry > 1000 || matches < 1 || matches > 1000 {
		return 0, 0, errors.New("jail 匹配预算配置不完整")
	}
	return retry, matches, nil
}

func compareFail2banExistingPolicyDump(before, after [][]any) error {
	br, bm, err := fail2banExistingMatchLimits(before)
	if err != nil {
		return err
	}
	ar, am, err := fail2banExistingMatchLimits(after)
	if err != nil {
		return err
	}
	if bm != am && (bm != br || am != ar) {
		return errors.New("参数候选改变了独立 maxmatches 配置")
	}
	withoutMatches := func(commands [][]any) [][]any {
		out := [][]any{}
		for _, command := range commands {
			if len(command) >= 3 && command[0] == "set" && command[2] == "maxmatches" {
				continue
			}
			out = append(out, command)
		}
		return out
	}
	b, err := fail2banExistingStableDump(withoutMatches(before), false)
	if err != nil {
		return err
	}
	a, err := fail2banExistingStableDump(withoutMatches(after), false)
	if err != nil {
		return err
	}
	if fail2banDumpHash(a) != fail2banDumpHash(b) {
		return errors.New("参数候选改变了原 filter/action、来源或其他非调整配置")
	}
	return nil
}
