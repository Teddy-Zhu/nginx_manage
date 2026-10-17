package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

func ManageFail2banExistingPolicy(ctx context.Context, data, scope, action, operation, adoption, target, inputFile string, confirmStop bool) (Fail2banExistingPolicyOperation, error) {
	var out Fail2banExistingPolicyOperation
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if !validID(operation) || action != "apply" && action != "status" && action != "cancel" {
		return out, errors.New("须指定有效的已有 jail 参数操作和 UUID")
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	if action == "status" {
		if adoption != "" || target != "" || inputFile != "" || confirmStop {
			return out, errors.New("参数操作查询只接收原操作 UUID")
		}
		r, err := j.Get(operation)
		if err != nil {
			return out, err
		}
		if _, err = validFail2banExistingPolicyRecord(data, r); err != nil {
			return out, err
		}
		return fail2banExistingPolicyOperation(r), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	unlock, err := fail2banHostSyncLocks(data)
	if err != nil {
		return out, err
	}
	defer unlock()
	leave, err := fail2banHostSyncAdmission(data, false)
	if err != nil {
		return out, err
	}
	defer leave()
	if err = prepareFail2banExistingPolicy(data); err != nil {
		return out, err
	}
	var input Fail2banExistingJailInput
	if action == "apply" {
		if !validID(adoption) || !fail2banDigest.MatchString(target) || inputFile == "" {
			return out, errors.New("应用须明确当前接管 UUID、参数计划摘要和参数文件")
		}
		input, err = readFail2banExistingJailInput(inputFile)
		if err != nil {
			return out, err
		}
		input.Policy, err = input.Policy.Normalize()
		if err != nil {
			return out, err
		}
	} else if adoption != "" || target != "" || inputFile != "" || confirmStop {
		return out, errors.New("取消只接收原参数操作 UUID")
	}
	if old, readErr := j.Get(operation); readErr == nil {
		c, err := validFail2banExistingPolicyRecord(data, old)
		if err != nil {
			return out, err
		}
		if action == "apply" {
			original, err := existingPolicyAdoption(data, c.Plan.AdoptionID)
			if err != nil {
				return out, err
			}
			if adoption != c.Plan.AdoptionID || target != c.Plan.Target || !sameFail2banExistingInput(input, Fail2banExistingJailInput{original.Plan.Profile, c.Plan.After}) || confirmStop != c.Plan.StopConfirmation {
				return out, errors.New("操作 UUID 已用于其他已有 jail 参数请求")
			}
		}
		if old.State == "succeeded" || old.State == "failed" {
			if action == "cancel" && old.State == "succeeded" {
				return out, errors.New("参数操作已完成，恢复参数须新建独立计划")
			}
			return fail2banExistingPolicyOperation(old), nil
		}
		if err = fail2banManagedIdle(data, operation); err != nil {
			return out, err
		}
		if action == "cancel" {
			original, err := existingPolicyAdoption(data, c.Plan.AdoptionID)
			if err != nil {
				return out, err
			}
			selected, err := loadFail2banExistingPolicy(data, original, c.Plan.AdoptionID)
			if err != nil {
				return out, err
			}
			if selected.ID == operation {
				return out, errors.New("参数选择已经发布，须查询原结果并新建恢复计划")
			}
			if old.Fail2banExistingPolicy.Sent {
				if _, _, err = observeFail2banExistingPolicy(ctx, data, old, c, false); err != nil {
					return out, errors.Join(errors.New("已提交的请求须原进程退出且原运行状态完整核对后才能取消"), err)
				}
			}
			old.Fail2banExistingPolicy.CancelRequested = true
			if err = j.Put(old); err != nil {
				return out, err
			}
		}
		err = advanceFail2banExistingPolicy(ctx, data, j, old, c)
		current, readErr := j.Get(operation)
		if readErr != nil {
			return out, errors.Join(err, readErr)
		}
		return fail2banExistingPolicyOperation(current), err
	} else if !os.IsNotExist(readErr) {
		return out, readErr
	}
	if action == "cancel" {
		return out, os.ErrNotExist
	}
	if err = fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	c, err := planFail2banExistingPolicyLocked(ctx, data, adoption, input)
	if err != nil {
		return out, err
	}
	if c.Plan.Target != target {
		return out, errors.New("参数计划基准变化，须重新生成计划")
	}
	if confirmStop != c.Plan.StopConfirmation {
		return out, errors.New("只有明确停止 SSH jail 时须提供独立停用确认")
	}
	c.After.ID = operation
	if err = c.valid(); err != nil {
		return out, err
	}
	path := fail2banExistingPolicyPath(data, "policy-captures", operation)
	if raw, readErr := listenerRead(path, fail2banExistingCaptureLimit); readErr == nil {
		var saved fail2banExistingPolicyCapture
		if json.Unmarshal(raw, &saved) != nil || saved.valid() != nil || saved.Plan.Target != c.Plan.Target || saved.After.ID != operation {
			return out, errors.New("操作 UUID 已保存其他参数准备材料")
		}
		c = &saved
	} else if !os.IsNotExist(readErr) {
		return out, readErr
	}
	for _, kind := range []string{"policy-captures", "policy-events"} {
		entries, err := os.ReadDir(filepath.Join(fail2banExistingDir(data), kind))
		if err != nil {
			return out, err
		}
		if len(entries) >= 2048 {
			if _, err = os.Lstat(fail2banExistingPolicyPath(data, kind, operation)); err != nil {
				return out, errors.New("已有 jail 参数历史容量已满")
			}
		}
	}
	raw, _ := json.Marshal(c)
	if err = writeFail2banJailImmutable(path, raw, fail2banExistingCaptureLimit); err != nil {
		return out, err
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return out, err
	}
	i := &fail2banExistingPolicyIntent{AdoptionID: adoption, CaptureHash: secure.Hash(raw), Target: target, Bans: map[string]fail2banBanTime{}}
	r := Record{OperationID: operation, Kind: fail2banExistingPolicyKind, RequestHash: fail2banExistingPolicyRequestHash(*i), State: "running", Stage: "prepared", Fail2banExistingPolicy: i}
	if err = j.Put(r); err != nil {
		return out, err
	}
	err = advanceFail2banExistingPolicy(ctx, data, j, r, c)
	current, readErr := j.Get(operation)
	if readErr != nil {
		return out, errors.Join(err, readErr)
	}
	return fail2banExistingPolicyOperation(current), err
}

func existingPolicyAdoption(data, adoption string) (*fail2banExistingCapture, error) {
	r, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(adoption)
	if err != nil {
		return nil, err
	}
	c, err := validFail2banExistingRecord(data, r)
	if err != nil {
		return nil, err
	}
	if r.State != "succeeded" || r.Fail2banExisting.Action != "adopt" {
		return nil, errors.New("原 jail 接管尚未确认")
	}
	g, err := loadFail2banExistingGrant(data, c.Plan.Profile.Name)
	if err != nil {
		return nil, err
	}
	if g == nil || g.Action != "adopt" || g.ID != adoption {
		return nil, errors.New("原 jail 接管授权已不再有效")
	}
	return c, nil
}

// Only the owned overlay is exchanged. Both the expected bytes and the full
// surrounding snapshot are checked by the caller; foreign files stay intact.
func replaceFail2banExistingPolicyOverlay(c *fail2banExistingPolicyCapture, forward bool) error {
	before, after := c.Plan.Before, c.Plan.After
	if !forward {
		before, after = after, before
	}
	profile := fail2ban.ExistingJailProfile{Name: c.Plan.Name}
	path := filepath.Join(fail2banExistingConfig, fail2banExistingOverlayName(c.Plan.Name))
	actual, err := listenerRead(path, 16384)
	if err != nil {
		return err
	}
	next := []byte(fail2banExistingOverlay(profile, after))
	if bytes.Equal(actual, next) {
		return syncDir(filepath.Dir(path))
	}
	if string(actual) != fail2banExistingOverlay(profile, before) {
		return ErrExternalChange
	}
	if err = existingRootDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + "." + secure.ID() + ".tmp"
	defer os.Remove(tmp)
	if err = durableFile(tmp, next, 0600, 0); err != nil {
		return err
	}
	// Recheck after creating the durable candidate, immediately before rename.
	latest, err := listenerRead(path, 16384)
	if err != nil || !bytes.Equal(latest, actual) {
		return ErrExternalChange
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func existingPolicyRecovery(j *Journal, r Record, err error) error {
	r.State, r.Stage, r.Error = "recovery_required", "policy_unconfirmed", err.Error()
	return errors.Join(err, j.Put(r))
}

func observeFail2banExistingPolicy(ctx context.Context, data string, r Record, c *fail2banExistingPolicyCapture, after bool) (Fail2banExistingRuntime, fail2banExistingRuntimeEvidence, error) {
	var out Fail2banExistingRuntime
	var evidence fail2banExistingRuntimeEvidence
	i := r.Fail2banExistingPolicy
	if i.Sent && (i.Submission != "confirmed" || !after) && !networkdCallEnded(*i.Pending) {
		return out, evidence, errors.New("原 reload 进程仍可能执行，不能重发或补偿")
	}
	current, err := readFail2banExistingConfig()
	if err != nil {
		return out, evidence, err
	}
	basis := c.Before
	if after {
		basis = c.After
	}
	switch current.hash() {
	case c.Snapshot.hash():
		basis.DumpHash = c.Before.DumpHash
	case c.afterSnapshot().hash():
		basis.DumpHash = c.After.DumpHash
	default:
		return out, evidence, errors.New("参数操作的配置树出现外部变化")
	}
	out, err = readFail2banExistingRuntimeLocked(ctx, data, c.Plan.AdoptionID, &basis, &evidence)
	if err != nil {
		return out, evidence, err
	}
	if evidence.Config.hash() != current.hash() {
		return out, evidence, errors.New("参数操作观察期间配置变化")
	}
	server, err := fail2banExistingServerConfig(evidence.Live)
	if err != nil || server != c.Server {
		return out, evidence, errors.New("参数操作的服务启动配置变化")
	}
	if evidence.Live.invocation != c.Invocation || evidence.Live.inode != c.Socket {
		if !i.Sent || !networkdCallEnded(*i.Pending) {
			return out, evidence, errors.New("参数操作期间原实例代次变化")
		}
	}
	want := c.BeforeJails
	if after {
		want = c.AfterJails
	}
	if !sameExistingPolicyJails(out.Jails, want) {
		return out, evidence, errors.New("参数操作期间其他 jail 名单变化")
	}
	if !after && i.Sent && c.Plan.Before.Enabled {
		if err = checkFail2banExistingPolicyBans(i.Bans, out.Bans); err != nil {
			return out, evidence, err
		}
	}
	return out, evidence, nil
}

func checkFail2banExistingPolicyBans(before, after map[string]fail2banBanTime) error {
	now := time.Now().Unix()
	for ip, old := range before {
		if old.Duration != -1 && old.Expires <= now {
			continue
		}
		current, ok := after[ip]
		if !ok || current != old {
			return errors.New("原未到期封禁或到期时间变化，未重放封禁")
		}
	}
	return nil
}

func advanceFail2banExistingPolicy(ctx context.Context, data string, j *Journal, r Record, c *fail2banExistingPolicyCapture) error {
	fail := func(err error) error { return existingPolicyRecovery(j, r, err) }
	i := r.Fail2banExistingPolicy
	original, err := existingPolicyAdoption(data, c.Plan.AdoptionID)
	if err != nil {
		return fail(err)
	}
	if original.Binding.ID != c.Plan.BindingID || original.Unit != c.Unit || original.Plan.NativeProof != c.Before.NativeProof {
		return fail(errors.New("参数操作的原接管依据变化"))
	}
	selected, err := loadFail2banExistingPolicy(data, original, c.Plan.AdoptionID)
	if err != nil {
		return fail(err)
	}
	if selected.ID == r.OperationID {
		if err = syncDir(filepath.Join(fail2banExistingDir(data), "policy-current")); err != nil {
			return fail(err)
		}
		r.State, r.Stage, r.Error = "succeeded", "policy_confirmed", ""
		return j.Put(r)
	}
	if selected.ID != c.Before.ID {
		return fail(ErrExternalChange)
	}
	if i.CancelRequested {
		if i.Sent {
			if _, _, err = observeFail2banExistingPolicy(ctx, data, r, c, false); err != nil {
				return fail(err)
			}
		}
		if err = replaceFail2banExistingPolicyOverlay(c, false); err != nil {
			return fail(err)
		}
		r.State, r.Stage, r.Error = "failed", "cancelled", ""
		return j.Put(r)
	}
	if !i.Sent {
		if time.Now().Unix()-c.Plan.At > 300 || time.Now().Unix() < c.Plan.At {
			return fail(errors.New("参数操作尚未发送且计划已过期，须取消后重新预检"))
		}
		view, evidence, err := observeFail2banExistingPolicy(ctx, data, r, c, false)
		if err != nil {
			return fail(err)
		}
		if c.Plan.Before.Enabled && view.ClockProof != c.ClockProof {
			return fail(errors.New("发送前时钟材料变化，须重新预检"))
		}
		if c.Plan.StopConfirmation {
			raw, _ := json.Marshal(view.Bans)
			if secure.Hash(raw) != c.StopBanProof {
				return fail(errors.New("停止前封禁集合变化，须取消后重新确认影响"))
			}
		}
		python, configDir, err := prepareFail2banExistingPolicyClient(ctx, data, c, evidence)
		if err != nil {
			return fail(err)
		}
		if err = replaceFail2banExistingPolicyOverlay(c, true); err != nil {
			return fail(err)
		}
		view, evidence, err = observeFail2banExistingPolicy(ctx, data, r, c, false)
		if err != nil {
			return fail(err)
		}
		if evidence.Config.hash() != c.afterSnapshot().hash() {
			return fail(errors.New("发送前参数候选配置不完整"))
		}
		if c.Plan.Before.Enabled && view.ClockProof != c.ClockProof {
			return fail(errors.New("发送前时钟材料变化"))
		}
		if c.Plan.StopConfirmation {
			raw, _ := json.Marshal(view.Bans)
			if secure.Hash(raw) != c.StopBanProof {
				return fail(errors.New("停止前封禁集合变化，未发送 reload"))
			}
		}
		process, err := networkProcess(uint32(*evidence.Live.view.MainPID))
		if err != nil {
			return fail(err)
		}
		current, err := readFail2banLiveService(ctx, &original.Binding)
		if err != nil || !sameFail2banLive(current, evidence.Live) || networkdCallEnded(process) {
			return fail(errors.New("发送前原服务进程变化"))
		}
		if err = evidence.Program.unchanged(ctx, data); err != nil {
			return fail(err)
		}
		config, err := readFail2banExistingConfig()
		if err != nil || config.hash() != c.afterSnapshot().hash() {
			return fail(errors.New("发送前系统候选变化"))
		}
		i.Bans, i.Pending, i.Sent, i.Submission = view.Bans, &process, true, "pending"
		r.Stage, r.Error = "reload_pending", ""
		if err = j.Put(r); err != nil {
			return err
		}
		// One named jail only. No --all, --restart, --unban, or global stop.
		raw, callErr := fail2banManagedExec(ctx, python, fail2banExistingPolicyClientArgs(evidence.Program, c, configDir, original.Binding.Socket, "reload"), 15*time.Second, 16384)
		i.Submission = "confirmed"
		if callErr != nil || strings.TrimSpace(string(raw)) != "OK" {
			i.Submission = "unknown"
		}
		r.Stage = "reload_observing"
		if err = j.Put(r); err != nil {
			return err
		}
		if i.Submission != "confirmed" {
			return fail(errors.New("单 jail reload 回包未确认；仅观察原请求，不重复发送"))
		}
	}
	view, evidence, err := observeFail2banExistingPolicy(ctx, data, r, c, true)
	if err != nil {
		return fail(err)
	}
	if evidence.Config.hash() != c.afterSnapshot().hash() {
		return fail(errors.New("运行参数已变化但磁盘候选不一致，须本机核对"))
	}
	if c.Plan.After.Enabled {
		if err = checkFail2banExistingPolicyBans(i.Bans, view.Bans); err != nil {
			return fail(err)
		}
	}
	private, err := readFail2banExistingConfigAt(filepath.Join(fail2banExistingDir(data), "policy-configs", r.OperationID))
	if err != nil || private.hash() != c.afterSnapshot().hash() {
		return fail(errors.New("原 reload 独立候选配置发生变化"))
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = publishFail2banExistingPolicy(data, c); err != nil {
		return fail(err)
	}
	r.State, r.Stage, r.Error = "succeeded", "policy_confirmed", ""
	return j.Put(r)
}

func (f *fail2banJailsExecutor) advanceExistingPolicy(ctx context.Context) error {
	leave, err := f.lock(true)
	if err != nil {
		return err
	}
	defer leave()
	records, err := f.journal().List()
	if err != nil {
		return err
	}
	var pending *Record
	other := false
	for _, r := range records {
		if !pendingNginxRecord(r) {
			continue
		}
		if r.Kind != fail2banExistingPolicyKind {
			other = true
			continue
		}
		if pending != nil {
			return errors.New("存在多个未完成的已有 jail 参数操作")
		}
		copy := r
		pending = &copy
	}
	if pending == nil {
		return nil
	}
	if other {
		return ErrBusy
	}
	c, err := validFail2banExistingPolicyRecord(f.server.DataDir, *pending)
	if err != nil {
		return existingPolicyRecovery(f.journal(), *pending, err)
	}
	return advanceFail2banExistingPolicy(ctx, f.server.DataDir, f.journal(), *pending, c)
}
