package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/secure"
)

// Initial ownership only persists an equivalent overlay. Parameter changes and
// jail shutdown need a separate, explicitly authorized runtime operation.
func ManageFail2banExistingOwnership(ctx context.Context, data, scope, action, operation, target, inputFile, base string) (Fail2banExistingOwnershipOperation, error) {
	var out Fail2banExistingOwnershipOperation
	if err := fail2banManagedRoot(data, scope); err != nil {
		return out, err
	}
	if !validID(operation) || action != "adopt" && action != "release" && action != "status" && action != "cancel" {
		return out, errors.New("须指定有效已有 jail 所有权操作和 UUID")
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	if action == "status" {
		if target != "" || inputFile != "" || base != "" {
			return out, errors.New("所有权查询只接受原操作 UUID")
		}
		r, err := j.Get(operation)
		if err != nil {
			return out, err
		}
		if _, err = validFail2banExistingRecord(data, r); err != nil {
			return out, err
		}
		return fail2banExistingOperation(r), nil
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
	if err = prepareFail2banExistingOwnership(data); err != nil {
		return out, err
	}
	if action == "cancel" {
		if target != "" || inputFile != "" || base != "" {
			return out, errors.New("取消只接受原所有权操作 UUID")
		}
		r, e := j.Get(operation)
		if e != nil {
			return out, e
		}
		capture, e := validFail2banExistingRecord(data, r)
		if e != nil {
			return out, e
		}
		if r.State == "failed" && r.Stage == "cancelled" {
			return fail2banExistingOperation(r), nil
		}
		if r.State == "succeeded" {
			return out, errors.New("原所有权操作已经完成，不能取消；接管后须显式释放")
		}
		g, e := loadFail2banExistingGrant(data, r.Fail2banExisting.Name)
		if e != nil {
			return out, e
		}
		if g != nil && g.ID == operation {
			return out, errors.New("所有权已经发布，须先查询原结果，再显式释放")
		}
		if e = fail2banManagedIdle(data, operation); e != nil {
			return out, e
		}
		r.Fail2banExisting.CancelRequested = true
		if e = j.Put(r); e != nil {
			return out, e
		}
		if e = advanceFail2banExistingOwnership(ctx, data, j, r, capture); e != nil {
			current, readErr := j.Get(operation)
			if readErr != nil {
				return out, errors.Join(e, readErr)
			}
			return fail2banExistingOperation(current), e
		}
		r, e = j.Get(operation)
		if e != nil {
			return out, e
		}
		return fail2banExistingOperation(r), nil
	}
	var input Fail2banExistingJailInput
	if action == "adopt" {
		if !fail2banDigest.MatchString(target) || inputFile == "" || base != "" {
			return out, errors.New("首次接管须明确预检摘要和原参数文件")
		}
		input, err = readFail2banExistingJailInput(inputFile)
		if err != nil {
			return out, err
		}
		input.Policy, err = input.Policy.Normalize()
		if err != nil {
			return out, err
		}
		if err = input.Profile.Validate(); err != nil {
			return out, err
		}
	} else if !validID(base) || target != "" || inputFile != "" {
		return out, errors.New("释放须指定原接管 UUID，不接收参数修改")
	}
	if old, e := j.Get(operation); e == nil {
		capture, e := validFail2banExistingRecord(data, old)
		if e != nil {
			return out, e
		}
		i := old.Fail2banExisting
		if i.Action != action || action == "adopt" && (i.Target != target || !sameFail2banExistingInput(input, Fail2banExistingJailInput{capture.Plan.Profile, capture.Plan.Before})) || action == "release" && i.AdoptionID != base {
			return out, errors.New("操作 UUID 已用于其他已有 jail 所有权请求")
		}
		if pendingNginxRecord(old) {
			if e = fail2banManagedIdle(data, operation); e != nil {
				return out, e
			}
			e = advanceFail2banExistingOwnership(ctx, data, j, old, capture)
			current, readErr := j.Get(operation)
			if readErr != nil {
				return out, errors.Join(e, readErr)
			}
			return fail2banExistingOperation(current), e
		}
		return fail2banExistingOperation(old), nil
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if err = fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	var capture *fail2banExistingCapture
	i := fail2banExistingIntent{Action: action, AdoptionID: base}
	if action == "adopt" {
		g, e := loadFail2banExistingGrant(data, input.Profile.Name)
		if e != nil {
			return out, e
		}
		if g != nil && g.Action == "adopt" {
			return out, errors.New("目标 jail 已接管，不能重新授予所有权")
		}
		var frozen fail2banExistingCapture
		plan, e := previewFail2banExistingJailLocked(ctx, data, input, &frozen)
		if e != nil {
			return out, e
		}
		if plan.Target != target {
			return out, errors.New("已有 jail 预检基准变化，须重新预检")
		}
		if !equalFail2banExistingPolicy(plan.Before, plan.After) {
			return out, errors.New("首次接管仅允许固定当前启用状态和参数；不能同时调整或停用 jail")
		}
		if err = frozen.valid(); err != nil {
			return out, err
		}
		capture = &frozen
		i.Name, i.BindingID, i.AdoptionID, i.Target = input.Profile.Name, plan.BindingID, operation, plan.Target
		path := fail2banExistingCapturePath(data, operation)
		if err = secure.RootDirectory(filepath.Dir(path), 0700); err != nil {
			return out, err
		}
		entries, e := os.ReadDir(filepath.Dir(path))
		if e != nil {
			return out, e
		}
		existing, e := listenerRead(path, fail2banExistingCaptureLimit)
		if e == nil {
			original, e := loadFail2banExistingCapture(data, operation, secure.Hash(existing))
			if e != nil {
				return out, e
			}
			if original.Plan.Target != frozen.Plan.Target || original.Binding.ID != frozen.Binding.ID || original.Unit != frozen.Unit || original.Server != frozen.Server || original.Invocation != frozen.Invocation || original.Socket != frozen.Socket || original.Snapshot.hash() != frozen.Snapshot.hash() || original.CandidateHash != frozen.CandidateHash || original.DumpHash != frozen.DumpHash {
				return out, errors.New("操作 UUID 已保存其他接管准备材料")
			}
			capture = original
		} else if !os.IsNotExist(e) {
			return out, e
		} else if len(entries) >= 2048 {
			return out, errors.New("已有 jail 接管快照容量已满，须本机维护")
		}
		pointerDir := filepath.Join(fail2banExistingDir(data), "current")
		if err = secure.RootDirectory(pointerDir, 0700); err != nil {
			return out, err
		}
		pointers, e := os.ReadDir(pointerDir)
		if e != nil {
			return out, e
		}
		if len(pointers) >= 64 && g == nil {
			return out, errors.New("已有 jail 接管登记最多保留 64 个名称")
		}
		raw, e := json.Marshal(capture)
		if e != nil {
			return out, e
		}
		if err = writeFail2banJailImmutable(path, raw, fail2banExistingCaptureLimit); err != nil {
			return out, err
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return out, err
		}
		i.CaptureHash = secure.Hash(raw)
	} else {
		original, e := j.Get(base)
		if e != nil {
			return out, e
		}
		capture, err = validFail2banExistingRecord(data, original)
		if err != nil {
			return out, err
		}
		if original.Fail2banExisting.Action != "adopt" || original.State != "succeeded" {
			return out, errors.New("原接管尚未成功，须先核对原操作")
		}
		i.Name, i.BindingID, i.Target, i.CaptureHash = original.Fail2banExisting.Name, original.Fail2banExisting.BindingID, original.Fail2banExisting.Target, original.Fail2banExisting.CaptureHash
		g, e := loadFail2banExistingGrant(data, i.Name)
		if e != nil {
			return out, e
		}
		if g == nil || g.Action != "adopt" || g.ID != base {
			return out, errors.New("当前 jail 接管身份已变化或已释放")
		}
	}
	r := Record{OperationID: operation, Kind: fail2banExistingKind, RequestHash: fail2banExistingRequestHash(i), State: "running", Stage: "prepared", Fail2banExisting: &i}
	if err = j.Put(r); err != nil {
		return out, err
	}
	if err = advanceFail2banExistingOwnership(ctx, data, j, r, capture); err != nil {
		current, readErr := j.Get(operation)
		if readErr != nil {
			return out, errors.Join(err, readErr)
		}
		return fail2banExistingOperation(current), err
	}
	r, err = j.Get(operation)
	if err != nil {
		return out, err
	}
	return fail2banExistingOperation(r), nil
}

func sameFail2banExistingInput(a, b Fail2banExistingJailInput) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func fail2banExistingNeedsRecovery(j *Journal, r Record, err error) error {
	r.State, r.Stage, r.Error = "recovery_required", "ownership_unconfirmed", err.Error()
	return errors.Join(err, j.Put(r))
}

func advanceFail2banExistingOwnership(ctx context.Context, data string, j *Journal, r Record, c *fail2banExistingCapture) error {
	i := r.Fail2banExisting
	fail := func(err error) error { return fail2banExistingNeedsRecovery(j, r, err) }
	g, err := loadFail2banExistingGrant(data, i.Name)
	if err != nil {
		return fail(err)
	}
	if g != nil && g.ID == r.OperationID {
		if err = syncDir(filepath.Dir(fail2banExistingPointerPath(data, i.Name))); err != nil {
			return fail(err)
		}
		r.State, r.Stage, r.Error = "succeeded", i.Action+"_confirmed", ""
		return j.Put(r)
	}
	if i.CancelRequested {
		return cancelFail2banExistingOwnership(data, j, r, c, g)
	}
	if i.Action == "adopt" && g != nil && g.Action == "adopt" || i.Action == "release" && (g == nil || g.ID != i.AdoptionID || g.Action != "adopt") {
		return fail(ErrExternalChange)
	}
	current, err := readFail2banExistingConfig()
	if err != nil {
		return fail(err)
	}
	beforeHash := c.Snapshot.hash()
	actual := current.hash()
	overlay := filepath.Join(fail2banExistingConfig, fail2banExistingOverlayName(i.Name))
	if i.Action == "release" {
		expected := beforeHash
		if actual != beforeHash && actual != c.CandidateHash {
			expected, err = previewFail2banExistingRelease(ctx, data, c, current)
			if err != nil {
				return fail(err)
			}
		}
		if _, exists := current.Files[fail2banExistingOverlayName(i.Name)]; exists {
			if err = removeFail2banExistingOverlay(overlay, []byte(fail2banExistingOverlay(c.Plan.Profile, c.Plan.Before))); err != nil {
				return fail(err)
			}
		}
		current, err = readFail2banExistingConfig()
		if err != nil || current.hash() != expected {
			return fail(errors.New("释放后原配置无法完整核对"))
		}
	} else {
		if actual != beforeHash && actual != c.CandidateHash {
			return fail(errors.New("原 Fail2ban 配置出现外部变化，未覆盖现场"))
		}
		if err = checkFail2banExistingIdentity(ctx, data, c); err != nil {
			return fail(err)
		}
		if actual == beforeHash {
			if err = secure.RootDirectory(filepath.Dir(overlay), 0755); err != nil {
				return fail(err)
			}
			if err = syncDir(fail2banExistingConfig); err != nil {
				return fail(err)
			}
			if err = writeFail2banJailImmutable(overlay, []byte(fail2banExistingOverlay(c.Plan.Profile, c.Plan.Before)), 16384); err != nil {
				return fail(err)
			}
		}
		// The real include tree must compile to the exact previously checked
		// candidate. No reload is sent during an equivalent initial takeover.
		program, err := selectFail2banClient(&c.Binding)
		if err != nil {
			return fail(err)
		}
		program, err = program.authenticate(ctx)
		if err != nil {
			return fail(err)
		}
		commands, err := dumpFail2banExisting(ctx, program, &c.Binding, fail2banExistingConfig, i.Name)
		if err != nil || fail2banDumpHash(commands) != c.DumpHash {
			return fail(errors.New("实际接管配置与预检候选不一致"))
		}
		policy, err := readFail2banExistingTuning(ctx, program, &c.Binding, i.Name)
		if err != nil || !equalFail2banExistingPolicy(policy, c.Plan.Before) {
			return fail(errors.New("接管期间原 jail 的实际参数变化"))
		}
		native, err := readFail2banExistingNativeProfile(ctx, program, &c.Binding, c.Plan.Profile, c.Plan.Before, commands)
		if err != nil || native != c.Plan.NativeProof {
			return fail(errors.New("接管期间实际过滤器或动作属性变化"))
		}
		if _, err = readFail2banHostJail(ctx, program, c.Binding.Socket, i.Name); err != nil {
			return fail(err)
		}
		raw, err := program.run(ctx, fail2banReadArgs(c.Binding.Socket, "status"), 128<<10)
		if err != nil {
			return fail(err)
		}
		jails, err := parseFail2banJails(raw)
		if err != nil {
			return fail(err)
		}
		names := make([]string, 0, len(jails))
		for _, jail := range jails {
			names = append(names, jail.Name)
		}
		sort.Strings(names)
		if strings.Join(names, "\x00") != strings.Join(c.Plan.Jails, "\x00") {
			return fail(errors.New("接管期间原完整 jail 名单变化"))
		}
		current, err = readFail2banExistingConfig()
		if err != nil || current.hash() != c.CandidateHash {
			return fail(errors.New("接管期间系统配置变化"))
		}
		live, err := readFail2banLiveService(ctx, &c.Binding)
		if err != nil {
			return fail(err)
		}
		if err = verifyFail2banExistingConfigSource(live, current); err != nil {
			return fail(err)
		}
		if err = program.unchanged(ctx, data); err != nil {
			return fail(err)
		}
		if err = checkFail2banExistingIdentity(ctx, data, c); err != nil {
			return fail(err)
		}
	}
	if err = syncDir(filepath.Dir(overlay)); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = publishFail2banExistingGrant(data, r); err != nil {
		return fail(err)
	}
	r.State, r.Stage, r.Error = "succeeded", i.Action+"_confirmed", ""
	return j.Put(r)
}

func removeFail2banExistingOverlay(path string, expected []byte) error {
	raw, err := listenerRead(path, 16384)
	if os.IsNotExist(err) {
		if e := syncDir(filepath.Dir(path)); e != nil && !os.IsNotExist(e) {
			return e
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, expected) {
		return ErrExternalChange
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Other jails may have been taken over since this capture. Prove removal of
// this overlay against the current include tree, preserving unrelated changes.
func previewFail2banExistingRelease(ctx context.Context, data string, c *fail2banExistingCapture, current fail2banExistingConfigSnapshot) (expected string, resultErr error) {
	if err := fail2banCurrentBinding(data, &c.Binding, true); err != nil {
		return "", err
	}
	program, err := selectFail2banClient(&c.Binding)
	if err != nil {
		return "", err
	}
	program, err = program.authenticate(ctx)
	if err != nil {
		return "", err
	}
	commands, err := dumpFail2banExisting(ctx, program, &c.Binding, fail2banExistingConfig, c.Plan.Profile.Name)
	if err != nil || fail2banDumpHash(commands) != c.DumpHash {
		return "", errors.New("当前 jail 配置已变化，不能自动移除接管覆盖")
	}
	files := maps.Clone(current.Files)
	name := fail2banExistingOverlayName(c.Plan.Profile.Name)
	if raw, exists := files[name]; exists {
		if !bytes.Equal(raw, []byte(fail2banExistingOverlay(c.Plan.Profile, c.Plan.Before))) {
			return "", ErrExternalChange
		}
		delete(files, name)
		base := filepath.Join(fail2banBindingDir(data), "existing-jail-previews")
		if err = secure.RootDirectory(base, 0700); err != nil {
			return "", err
		}
		work, err := os.MkdirTemp(base, ".release-")
		if err != nil {
			return "", err
		}
		defer func() {
			if err := os.RemoveAll(work); err != nil {
				expected = ""
				resultErr = errors.Join(resultErr, errors.New("释放预检材料清理失败，须本机检查"))
			}
		}()
		if err = writeFail2banExistingCandidate(work, files); err != nil {
			return "", err
		}
		commands, err = dumpFail2banExisting(ctx, program, &c.Binding, work, c.Plan.Profile.Name)
		if err != nil || fail2banDumpHash(commands) != c.DumpHash {
			return "", errors.New("移除接管覆盖会改变 jail 参数或配置，未释放")
		}
	}
	latest, err := readFail2banExistingConfig()
	if err != nil || latest.hash() != current.hash() {
		return "", ErrExternalChange
	}
	if err = program.unchanged(ctx, data); err != nil {
		return "", err
	}
	if err = fail2banCurrentBinding(data, &c.Binding, true); err != nil {
		return "", err
	}
	return (fail2banExistingConfigSnapshot{Files: files}).hash(), ctx.Err()
}

func cancelFail2banExistingOwnership(data string, j *Journal, r Record, c *fail2banExistingCapture, g *fail2banExistingGrant) error {
	i := r.Fail2banExisting
	fail := func(err error) error { return fail2banExistingNeedsRecovery(j, r, err) }
	path := filepath.Join(fail2banExistingConfig, fail2banExistingOverlayName(i.Name))
	raw := []byte(fail2banExistingOverlay(c.Plan.Profile, c.Plan.Before))
	if i.Action == "adopt" {
		if g != nil && g.Action != "release" {
			return fail(ErrExternalChange)
		}
		// Only our unpublished, byte-identical overlay is removed. Unrelated
		// external configuration is left intact; no runtime command was sent.
		if err := removeFail2banExistingOverlay(path, raw); err != nil {
			return fail(err)
		}
	} else {
		if g == nil || g.Action != "adopt" || g.ID != i.AdoptionID {
			return fail(ErrExternalChange)
		}
		existing, err := listenerRead(path, 16384)
		if err == nil && !bytes.Equal(existing, raw) {
			return fail(ErrExternalChange)
		}
		if err != nil && !os.IsNotExist(err) {
			return fail(err)
		}
		if os.IsNotExist(err) {
			current, err := readFail2banExistingConfig()
			if err != nil {
				return fail(err)
			}
			if current.hash() != c.Snapshot.hash() {
				return fail(ErrExternalChange)
			}
			if err = secure.RootDirectory(filepath.Dir(path), 0755); err != nil {
				return fail(err)
			}
			if err = writeFail2banJailImmutable(path, raw, 16384); err != nil {
				return fail(err)
			}
		}
	}
	r.State, r.Stage, r.Error = "failed", "cancelled", "本机 root 已取消未发布的所有权操作；未向 Fail2ban 发送运行修改"
	return j.Put(r)
}

func checkFail2banExistingIdentity(ctx context.Context, data string, c *fail2banExistingCapture) error {
	if err := fail2banCurrentBinding(data, &c.Binding, true); err != nil {
		return err
	}
	unit, err := fail2banExistingUnitHash(ctx, c.Binding.Service)
	if err != nil || unit != c.Unit {
		return errors.New("已有 jail 服务单元变化")
	}
	live, err := readFail2banLiveService(ctx, &c.Binding)
	if err != nil || live.invocation != c.Invocation || live.inode != c.Socket {
		return errors.New("已有 jail 实例代次变化，须本机核对后恢复")
	}
	server, err := fail2banExistingServerConfig(live)
	if err != nil || server != c.Server {
		return errors.New("已有 jail 服务启动配置变化")
	}
	return nil
}

func (f *fail2banJailsExecutor) advanceExistingOwnership(ctx context.Context) error {
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
		if r.Kind != fail2banExistingKind {
			other = true
			continue
		}
		if pending != nil {
			return errors.New("存在多个未完成的已有 jail 所有权操作")
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
	capture, err := validFail2banExistingRecord(f.server.DataDir, *pending)
	if err != nil {
		return fail2banExistingNeedsRecovery(f.journal(), *pending, err)
	}
	return advanceFail2banExistingOwnership(ctx, f.server.DataDir, f.journal(), *pending, capture)
}
