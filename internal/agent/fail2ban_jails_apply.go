package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

var errFail2banJailsRecovery = errors.New("受管 jail 恢复尚未确认")

func validFail2banJailRecord(record Record, r *fail2banManagedRecord) (*fail2banJailBundle, *fail2banJailBundle, error) {
	i := record.Fail2banJails
	if record.Kind != fail2banJailsKind || i == nil || !i.Basis.valid() || !validID(record.OperationID) || i.AfterID != record.OperationID || i.InstallationID != r.OperationID || i.EngineKey != fail2banNginxEngineKey(r.binding()) || !fail2banInvocation.MatchString(i.Invocation) || i.SocketInode == "" || i.BeforeID != "" && !validID(i.BeforeID) {
		return nil, nil, errors.New("受管 jail 恢复身份无效")
	}
	after, err := loadFail2banJailBundle(r, i.AfterID)
	if err != nil {
		return nil, nil, err
	}
	before, err := loadFail2banJailBundle(r, i.BeforeID)
	if err != nil {
		return nil, nil, err
	}
	target := fail2ban.JailTarget(i.EngineKey, i.BeforeID, i.Basis.NginxDir, i.Basis.NginxHash, i.Basis.RegistryID, i.Invocation, i.Basis.HostHash)
	request := Fail2banJailsRequest{Protocol: Protocol, OperationID: record.OperationID, BaseID: i.BeforeID, Target: target, Policy: after.Policy}
	if target != i.Target || request.Hash() != record.RequestHash || after.EngineKey != i.EngineKey || i.Nginx != (fail2banJailNeedsNginx(before) || fail2banJailNeedsNginx(after)) || fail2banJailNeedsHost(after) && !fail2banDigest.MatchString(i.Basis.HostHash) || record.BeforeDir != record.AfterDir || record.BeforeDir != after.NginxDir || i.BansHash != "" && !fail2banDigest.MatchString(i.BansHash) || i.EffectsPossible && !fail2banDigest.MatchString(i.BansHash) {
		return nil, nil, errors.New("受管 jail 恢复合同无法核对")
	}
	if !i.Nginx {
		actual, _ := json.Marshal([]fail2banNginxRegistry{i.BeforeRegistry, i.AfterRegistry, i.RollbackRegistry})
		empty, _ := json.Marshal([]fail2banNginxRegistry{{}, {}, {}})
		if after.NginxDir != "" || after.NginxHash != "" || record.BeforeRevision != "" || record.AfterRevision != "" || string(actual) != string(empty) {
			return nil, nil, errors.New("宿主机 jail 不接受 Nginx 事务材料")
		}
		return before, after, nil
	}
	if after.NginxDir != i.Basis.NginxDir || after.NginxHash != i.Basis.NginxHash || after.NginxDir == "" || i.BeforeRegistry.ID != i.Basis.RegistryID || i.AfterRegistry.ID != record.OperationID || i.AfterRegistry.PreviousID != i.BeforeRegistry.ID || i.AfterRegistry.RequestHash != record.RequestHash || !validID(i.RollbackRegistry.ID) || i.RollbackRegistry.PreviousID != i.AfterRegistry.ID {
		return nil, nil, errors.New("jail 的 Nginx 恢复基准不匹配")
	}
	if err = validFail2banNginxRegistry(i.BeforeRegistry, true); err != nil {
		return nil, nil, err
	}
	if err = validFail2banNginxRegistry(i.AfterRegistry, false); err != nil {
		return nil, nil, err
	}
	if err = validFail2banNginxRegistry(i.RollbackRegistry, false); err != nil {
		return nil, nil, err
	}
	if i.RollbackRegistry.RequestHash != secure.Hash([]byte("fail2ban.jails.rollback:"+record.RequestHash)) {
		return nil, nil, errors.New("jail 回滚批准摘要无效")
	}
	grants, err := fail2banJailGrants(i.BeforeRegistry, before, after)
	if err != nil {
		return nil, nil, err
	}
	actual, _ := json.Marshal(i.AfterRegistry.Grants)
	expected, _ := json.Marshal(grants)
	rollback, _ := json.Marshal(i.RollbackRegistry.Grants)
	previous, _ := json.Marshal(i.BeforeRegistry.Grants)
	if string(actual) != string(expected) || string(rollback) != string(previous) {
		return nil, nil, errors.New("jail 恢复动作批准不匹配")
	}
	return before, after, nil
}

func checkFail2banJailRegistry(data string, i *fail2banJailIntent, ids ...string) error {
	if !i.Nginx {
		return nil
	}
	current, err := loadFail2banNginxRegistry(data)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if current.ID == id {
			return nil
		}
	}
	return ErrExternalChange
}

// A single host worker advances jail operations. Its shared journal excludes
// concurrent engine changes and, when present, Nginx publication writers.
func (f *fail2banJailsExecutor) advanceJails(ctx context.Context) error {
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
	otherPending := false
	for _, record := range records {
		if !pendingNginxRecord(record) {
			continue
		}
		if record.Kind != fail2banJailsKind {
			otherPending = true
			continue
		}
		if pending != nil {
			return errors.New("存在多个未完成的受管 jail 操作")
		}
		copy := record
		pending = &copy
	}
	if pending == nil {
		return nil
	}
	if otherPending {
		return ErrBusy
	}
	r, err := loadFail2banManaged(f.server.DataDir)
	if err != nil || r == nil || r.State != "installed" {
		return f.jailsRecoveryRequired(*pending, errors.New("受管引擎安装身份不可用，不能覆盖或重建其他实例"))
	}
	before, after, err := validFail2banJailRecord(*pending, r)
	if err != nil {
		return f.jailsRecoveryRequired(*pending, err)
	}
	if pending.Stage == "queued" && pending.State == "running" {
		return f.executeJails(ctx, *pending, r, before, after)
	}
	if !pending.Fail2banJails.EffectsPossible {
		if err = verifyFail2banManaged(ctx, r, true); err != nil {
			return f.jailsRecoveryRequired(*pending, err)
		}
		selected, _, err := selectedFail2banJails(r)
		if err != nil || selected != pending.Fail2banJails.BeforeID {
			return f.jailsRecoveryRequired(*pending, ErrExternalChange)
		}
		if err = checkFail2banJailRegistry(f.server.DataDir, pending.Fail2banJails, pending.Fail2banJails.BeforeRegistry.ID); err != nil {
			return f.jailsRecoveryRequired(*pending, err)
		}
		pending.State, pending.Stage, pending.Error = "failed", "interrupted_before_switch", "Agent 在准备期间重启，受管运行配置未切换"
		return f.persist(*pending)
	}
	return f.recoverJails(*pending, r, before, after)
}

func (f *fail2banJailsExecutor) executeJails(ctx context.Context, record Record, r *fail2banManagedRecord, before, after *fail2banJailBundle) error {
	i := record.Fail2banJails
	failBefore := func(err error) error {
		record.State, record.Stage, record.Error = "failed", "prepare_failed", err.Error()
		return errors.Join(err, f.persist(record))
	}
	record.Stage = "preparing"
	if err := f.persist(record); err != nil {
		return err
	}
	if err := verifyFail2banManaged(ctx, r, true); err != nil {
		return failBefore(err)
	}
	selected, _, err := selectedFail2banJails(r)
	if err != nil || selected != i.BeforeID {
		return failBefore(ErrExternalChange)
	}
	live, err := readFail2banLiveService(ctx, r.binding())
	if err != nil || live.invocation != i.Invocation || live.inode != i.SocketInode {
		return failBefore(errors.New("受管 jail 排队期间实例变化，请重新提交"))
	}
	if err = f.verifyNginx(ctx, after); err != nil {
		return failBefore(err)
	}
	if err = f.verifyHost(ctx, r, after, i.Basis); err != nil {
		return failBefore(err)
	}
	if err = checkFail2banJailRegistry(f.server.DataDir, i, i.BeforeRegistry.ID); err != nil {
		return failBefore(err)
	}
	if err = prepareFail2banJailConfig(r, after); err != nil {
		return failBefore(err)
	}
	templateIDs := []string{}
	for _, j := range after.Policy.Jails {
		if !j.Enabled {
			continue
		}
		seen := false
		for _, id := range templateIDs {
			seen = seen || id == j.Template
		}
		if !seen {
			templateIDs = append(templateIDs, j.Template)
		}
	}
	if len(templateIDs) > 0 {
		program := fail2banProgram{kind: "fail2ban-regex", managed: r}
		reader := &fail2banTemplateReader{data: f.server.DataDir, scope: "host"}
		checks := reader.collect(ctx, fail2ban.TemplateCheckInput{Templates: templateIDs}, program)
		if len(checks) != len(templateIDs) {
			return failBefore(errors.New("官方过滤器检查结果不完整"))
		}
		for _, check := range checks {
			if !check.Available || !check.Passed || check.Engine != r.engine() {
				return failBefore(errors.New("官方过滤器样例检查未通过：" + check.Template))
			}
		}
	}
	if _, err = fail2banManagedExec(ctx, r.python(), r.args(true, "-c", r.jailCandidate(after.ID), "-s", fail2banManagedSocket, "-t"), 8*time.Second, 16384); err != nil {
		return failBefore(errors.New("官方客户端未通过候选 jail 配置校验"))
	}
	proof, err := readFail2banJailRuntime(ctx, r, before)
	if err != nil {
		return failBefore(err)
	}
	i.BansHash, err = saveFail2banBanProof(r, record.OperationID, proof)
	if err != nil {
		return failBefore(err)
	}
	selected, _, err = selectedFail2banJails(r)
	if err != nil || selected != i.BeforeID {
		return failBefore(ErrExternalChange)
	}
	if err = checkFail2banJailRegistry(f.server.DataDir, i, i.BeforeRegistry.ID); err != nil {
		return failBefore(err)
	}
	if err = f.verifyHost(ctx, r, after, i.Basis); err != nil {
		return failBefore(err)
	}
	// All later stages can have changed both configuration and authorization.
	record.Stage = "switch_pending"
	i.EffectsPossible = true
	if err = f.persist(record); err != nil {
		return err
	}
	err = func() error {
		if i.Nginx {
			if err := saveFail2banNginxRegistry(f.server.DataDir, i.AfterRegistry); err != nil {
				return err
			}
		}
		if err := selectFail2banJails(r, i.AfterID); err != nil {
			return err
		}
		if err := exchangeFail2banJailConfig(r, record.OperationID, before, after); err != nil {
			return err
		}
		record.Stage = "reload_pending"
		if err := f.persist(record); err != nil {
			return err
		}
		if err := reloadFail2banJails(ctx, r); err != nil {
			return err
		}
		actual, err := readFail2banJailRuntime(ctx, r, after)
		if err != nil {
			return err
		}
		if err = checkFail2banBanPreservation(proof, actual); err != nil {
			return err
		}
		if err = f.verifyNginx(ctx, after); err != nil {
			return err
		}
		if err = f.verifyHost(ctx, r, after, i.Basis); err != nil {
			return err
		}
		selected, _, err := selectedFail2banJails(r)
		if err != nil || selected != i.AfterID {
			return ErrExternalChange
		}
		if err = checkFail2banJailRegistry(f.server.DataDir, i, i.AfterRegistry.ID); err != nil {
			return err
		}
		record.State, record.Stage, record.Error = "succeeded", "jails_confirmed", ""
		return f.persist(record)
	}()
	if err != nil {
		record.Error = err.Error()
		return errors.Join(err, f.recoverJails(record, r, before, after))
	}
	return nil
}

func reloadFail2banJails(ctx context.Context, r *fail2banManagedRecord) error {
	// No --restart or --unban: official reload owns ticket/database lifecycle.
	raw, err := fail2banManagedExec(ctx, r.python(), r.args(true, "-c", filepath.Join(r.work(), "config"), "-s", fail2banManagedSocket, "--timeout", "10", "reload", "--all"), 15*time.Second, 16384)
	if err != nil || strings.TrimSpace(string(raw)) != "OK" {
		return errors.New("官方受管 jail reload 未确认完成")
	}
	return nil
}

func (f *fail2banJailsExecutor) jailsRecoveryRequired(record Record, err error) error {
	record.State, record.Stage, record.Error = "recovery_required", "jails_unconfirmed", err.Error()
	return errors.Join(errFail2banJailsRecovery, err, f.persist(record))
}

func (f *fail2banJailsExecutor) recoverJails(record Record, r *fail2banManagedRecord, before, after *fail2banJailBundle) error {
	i := record.Fail2banJails
	record.State, record.Stage = "compensating", "jails_rollback_pending"
	if err := f.persist(record); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err := func() error {
		if err := verifyFail2banManaged(ctx, r, false); err != nil {
			return err
		}
		if err := fail2banManagedFile(fail2banManagedUnit, r.unit()); err != nil {
			return err
		}
		selected, _, err := selectedFail2banJails(r)
		if err != nil || selected != i.BeforeID && selected != i.AfterID {
			return ErrExternalChange
		}
		active := filepath.Join(r.work(), "config")
		if err = verifyFail2banJailConfig(r, active, before); err != nil {
			if err = verifyFail2banJailConfig(r, active, after); err != nil {
				return ErrExternalChange
			}
			if err = selectFail2banJails(r, i.BeforeID); err != nil {
				return err
			}
			if err = exchangeFail2banJailConfig(r, record.OperationID, after, before); err != nil {
				return err
			}
		} else if err = selectFail2banJails(r, i.BeforeID); err != nil {
			return err
		}
		if i.Nginx {
			registry, err := loadFail2banNginxRegistry(f.server.DataDir)
			if err != nil {
				return err
			}
			if registry.ID == i.AfterRegistry.ID {
				if err = saveFail2banNginxRegistry(f.server.DataDir, i.RollbackRegistry); err != nil {
					return err
				}
			} else if registry.ID != i.BeforeRegistry.ID && registry.ID != i.RollbackRegistry.ID {
				return ErrExternalChange
			}
		}
		if err = verifyFail2banManaged(ctx, r, true); err != nil {
			return err
		}
		if _, err = readFail2banLiveService(ctx, r.binding()); err != nil {
			if err = fail2banManagedStopped(ctx); err != nil {
				return err
			}
			if err = fail2banManagedNoOther(ctx, f.server.DataDir, false); err != nil {
				return err
			}
			if err = fail2banManagedEffective(ctx); err != nil {
				return err
			}
			if err = fail2banManagedSystemctl(ctx, "start", fail2banManagedService); err != nil {
				return err
			}
		}
		if err = reloadFail2banJails(ctx, r); err != nil {
			return err
		}
		actual, err := readFail2banJailRuntime(ctx, r, before)
		if err != nil {
			return err
		}
		var proof fail2banBanProof
		raw, err := listenerRead(fail2banJailBansPath(r, record.OperationID), fail2banBanProofLimit)
		if err != nil || i.BansHash == "" || secure.Hash(raw) != i.BansHash {
			return errors.New("原官方封禁时间快照无法核对，不重放缓存封禁")
		}
		if err = decodeFail2banNginxJSON(raw, &proof); err != nil {
			return err
		}
		if err = checkFail2banBanPreservation(proof, actual); err != nil {
			return err
		}
		selected, _, err = selectedFail2banJails(r)
		if err != nil || selected != i.BeforeID {
			return ErrExternalChange
		}
		if err = checkFail2banJailRegistry(f.server.DataDir, i, i.BeforeRegistry.ID, i.RollbackRegistry.ID); err != nil {
			return err
		}
		if err = f.verifyNginx(ctx, after); err != nil {
			return err
		}
		return verifyFail2banJailConfig(r, active, before)
	}()
	if err != nil {
		return f.jailsRecoveryRequired(record, err)
	}
	if record.Error == "" {
		record.Error = "jail 应用中断"
	}
	record.State, record.Stage, record.Error = "failed", "jails_rolled_back", record.Error+"；原受管 jail 配置及官方未过期记录已核对；动作执行另看对应状态"
	return f.persist(record)
}

func (f *fail2banJailsExecutor) jailOperation(id string) (Fail2banJailsOperation, error) {
	if !validID(id) {
		return Fail2banJailsOperation{}, errors.New("受管 jail 操作 ID 无效")
	}
	r, err := f.journal().Get(id)
	if err != nil {
		if os.IsNotExist(err) {
			return Fail2banJailsOperation{}, fault.New(404, "FAIL2BAN_JAIL_OPERATION_MISSING", "受管 jail 操作记录不存在")
		}
		return Fail2banJailsOperation{}, err
	}
	if r.Kind != fail2banJailsKind || r.Fail2banJails == nil {
		return Fail2banJailsOperation{}, fault.Conflict("操作 UUID 已用于其他任务")
	}
	return fail2banJailsView(r), nil
}
