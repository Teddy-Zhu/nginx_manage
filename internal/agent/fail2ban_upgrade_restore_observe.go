package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/nginxmodules"
)

func fail2banUpgradeRestoreCandidateBasis(s fail2banUpgradeSwitch) fail2banUpgradeBasis {
	b := s.Prepared.Basis
	b.Current, b.Bundle = s.After, s.Prepared.Material.Bundle
	b.Registry, b.HostSources, b.HostSync = fail2banUpgradeVerificationGrants(s)
	return b
}

func (i fail2banUpgradeRestoreIntent) program(s fail2banUpgradeSwitch) fail2banHostProgram {
	p := s.Prepared
	p.Recovery = i.Recovery
	program, _ := fail2banUpgradeOriginalHostProgram(p)
	return program
}

// This proof concerns retaining the last confirmed actions during a stopped
// restore. It never declares the original engine's live protection recovered.
func (i fail2banUpgradeRestoreIntent) validateActions(s fail2banUpgradeSwitch) error {
	b := fail2banUpgradeRestoreCandidateBasis(s)
	if root := b.HostRegistration; root != nil && root.State == "registered" {
		if !fail2banUpgradeOneOf(i.Recovery.RegistrationReceipt, s.Prepared.Recovery.RegistrationReceipt) {
			return errors.New("升级恢复的原宿主机登记审计变化")
		}
		if runtime := i.Recovery.Runtime; runtime != nil {
			if runtime.State != "succeeded" && runtime.State != "failed" || !fail2banHostRuntimeMatches(runtime, root) || i.Recovery.Receipt == nil {
				return errors.New("升级恢复须保留已终结的原宿主机运行检查点")
			}
		}
		program := i.program(s)
		if !fail2banHostProgramShape(program, i.Kernel) || !i.Kernel.TableExists || i.Kernel.NamespaceID != root.Confirmed.NamespaceID {
			return errors.New("升级恢复未完整冻结当前宿主机动作规则")
		}
	} else if i.Kernel != (firewall.KernelView{}) || i.Recovery.Runtime != nil {
		return errors.New("升级恢复包含范围外宿主机运行材料")
	}
	if sync := b.HostSync; sync != nil {
		session, err := loadFail2banHostSyncEvent(i.Request.DataDir, sync.SessionID)
		if err != nil {
			return err
		}
		if session.Action != "enable" || i.Recovery.Parent == nil || !fail2banHostSyncParentMatches(*i.Recovery.Parent, session) {
			return errors.New("升级恢复缺少候选持续会话的原审计")
		}
	} else if i.Recovery.Parent != nil {
		return errors.New("升级恢复包含范围外持续会话审计")
	}
	h := i.Nginx
	if !fail2banJailNeedsNginx(b.Bundle) {
		if h != nil {
			return errors.New("升级恢复包含范围外 Nginx 动作材料")
		}
		return nil
	}
	if h == nil || h.Directory != b.Bundle.NginxDir || h.ManifestSHA256 != b.Bundle.NginxHash {
		return errors.New("升级恢复须保留原活动 Nginx 配置与拒绝集合")
	}
	checkpoint, err := clientDenyCheckpoint([]Record{h.Checkpoint})
	if err != nil {
		return err
	}
	if checkpoint == nil || checkpoint.BeforeDir != h.Directory || checkpoint.AfterDir != h.Directory || checkpoint.BeforeRevision != h.RevisionID || checkpoint.AfterRevision != h.RevisionID || checkpoint.ClientDeny.ManifestHash != h.ManifestSHA256 {
		return errors.New("升级恢复的 Nginx 动作检查点不完整")
	}
	expected := checkpoint.ClientDeny.After
	switch {
	case checkpoint.State == "succeeded" && checkpoint.Stage == "runtime_confirmed" && checkpoint.ObservedRevision == h.RevisionID:
	case checkpoint.State == "failed" && checkpoint.Stage == "rolled_back":
		expected = checkpoint.ClientDeny.Before
	default:
		return errors.New("升级恢复前须完成原 Nginx 动作事务或其补偿")
	}
	if !fail2banUpgradeOneOf(expected, h.Snapshot) {
		return errors.New("升级恢复的 Nginx 拒绝集合偏离原确认检查点")
	}
	return nil
}

func (i fail2banUpgradeRestoreIntent) transferredParent() *Record {
	if i.Undo.Sync == nil {
		return nil
	}
	r := *i.Recovery.Parent
	r.State, r.Stage, r.Fail2banUpgradeID = "succeeded", "transferred", i.Request.OperationID
	return &r
}

func (i fail2banUpgradeRestoreIntent) observeAudits(j *Journal) error {
	for _, expected := range []*Record{i.Recovery.RegistrationReceipt, i.Recovery.Receipt, i.Recovery.Parent} {
		if expected == nil {
			continue
		}
		actual, err := j.Get(expected.OperationID)
		if err != nil {
			return err
		}
		if sameFail2banUpgradePreparationRecord(actual, *expected) {
			continue
		}
		after := i.transferredParent()
		if after == nil || expected.OperationID != after.OperationID || !sameFail2banUpgradePreparationRecord(actual, *after) {
			return errors.New("升级恢复期间原宿主机审计被其他操作修改")
		}
	}
	if i.Undo.Sync != nil {
		actual, err := j.Get(i.Undo.Sync.ID)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameFail2banUpgradePreparationRecord(actual, fail2banHostSyncParent(i.Undo.Sync)) {
			return errors.New("升级恢复的新持续会话审计偏离批准范围")
		}
	}
	return nil
}

func (i fail2banUpgradeRestoreIntent) observe(ctx context.Context, s fail2banUpgradeSwitch) error {
	data, u := i.Request.DataDir, i.Undo
	current, err := loadFail2banManaged(data)
	if err != nil {
		return err
	}
	if current == nil || !fail2banUpgradeOneOf(current, s.After, u.Managed) {
		return errors.New("升级恢复不得覆盖其他安装选择")
	}
	registry, sources, sync := fail2banUpgradeVerificationGrants(s)
	actualRegistry, err := loadFail2banNginxRegistry(data)
	if err != nil {
		return err
	}
	actualSources, err := loadFail2banHostSources(data)
	if err != nil {
		return err
	}
	actualSync, err := loadFail2banHostSync(data)
	if err != nil {
		return err
	}
	nginxChoices, sourceChoices, syncChoices := []any{registry}, []any{sources}, []any{sync}
	if u.Nginx != nil {
		nginxChoices = append(nginxChoices, u.Nginx)
	}
	if u.Sources != nil {
		sourceChoices = append(sourceChoices, u.Sources)
	}
	if u.Sync != nil {
		syncChoices = append(syncChoices, u.Sync)
	}
	root, err := loadFail2banHostRegistration(data)
	if err != nil {
		return err
	}
	protection, err := loadFail2banHostProtection(data)
	if err != nil {
		return err
	}
	runtime, err := loadFail2banHostRuntime(data)
	if err != nil {
		return err
	}
	if !fail2banUpgradeOneOf(actualRegistry, nginxChoices...) || !fail2banUpgradeOneOf(actualSources, sourceChoices...) || !fail2banUpgradeOneOf(actualSync, syncChoices...) || !fail2banUpgradeOneOf(root, s.Prepared.Basis.HostRegistration) || !fail2banUpgradeOneOf(protection, s.Prepared.Basis.HostProtection) || !fail2banUpgradeOneOf(runtime, i.Recovery.Runtime) {
		return errors.New("升级恢复期间动作批准、登记或运行检查点漂移")
	}
	if stopping, e := loadFail2banHostSyncStop(data, actualSync); e != nil || stopping != nil {
		return errors.Join(errors.New("升级恢复期间出现持续停用意图"), e)
	}
	if err = i.observeAudits(&Journal{Dir: filepath.Join(data, "agent", "operations")}); err != nil {
		return err
	}
	for _, record := range []*fail2banManagedRecord{&s.After, &u.Managed} {
		if err = verifyFail2banManaged(ctx, record, false); err != nil {
			return err
		}
		_, bundle, e := selectedFail2banJails(record)
		if e != nil {
			return e
		}
		if e = verifyFail2banJailConfig(record, filepath.Join(record.work(), "config"), bundle); e != nil {
			return e
		}
	}
	raw, err := nginxmodules.ReadTrusted(fail2banManagedUnit, 64<<10)
	if err != nil {
		return err
	}
	if string(raw) != s.After.unit() && string(raw) != u.Managed.unit() {
		return ErrExternalChange
	}
	if err = fail2banManagedFile(fail2banManagedUnit, string(raw)); err != nil {
		return err
	}
	if err = fail2banManagedNoOther(ctx, data, false); err != nil {
		return err
	}
	service, invocation, err := lifecycleService(ctx)
	if err != nil {
		return err
	}
	if service.Load != "loaded" || service.UnitFile != i.Before.Service.UnitFile || invocation != i.Before.Invocation {
		return errors.New("升级恢复期间停止服务观察或启用偏好变化")
	}
	if err = fail2banExistingStopped(current.binding(), service); err != nil {
		return err
	}
	machine, boot, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return err
	}
	if machine != i.Before.MachineID || boot != i.Before.BootID {
		return errors.New("升级恢复已超出原机器或启动代次")
	}
	state := i.stateRestore()
	ready, err := state.ready()
	if err != nil {
		return err
	}
	swapped, err := state.observe(ctx, ready)
	if err != nil {
		return err
	}
	stateReceipt, err := state.receipt()
	if err != nil {
		return err
	}
	if stateReceipt != nil && !swapped {
		return errors.New("升级恢复完成证明与实际数据库目录不一致")
	}
	if root != nil && root.State == "registered" {
		program := i.program(s)
		kernel, e := program.snapshot(ctx)
		if e != nil {
			return e
		}
		if !fail2banHostProgramShape(program, kernel) || kernel.NamespaceID != i.Kernel.NamespaceID || kernel.Fingerprint != i.Kernel.Fingerprint {
			return errors.New("升级恢复期间原宿主机规则漂移，不重建或接管")
		}
	}
	p := s.Prepared
	p.Basis = fail2banUpgradeRestoreCandidateBasis(s)
	nginx, err := readFail2banUpgradeQuiesceNginx(data, p)
	if err != nil {
		return err
	}
	if !fail2banUpgradeOneOf(nginx, i.Nginx) {
		return errors.New("升级恢复期间原 Nginx 动作集合或检查点变化")
	}
	return ctx.Err()
}

func (i fail2banUpgradeRestoreIntent) selected(ctx context.Context) error {
	basis, err := readFail2banStateBasis(ctx, i.Request.DataDir)
	if err != nil {
		return err
	}
	if !sameFail2banStateRestoreControl(basis, i.State.Input.Basis) {
		return errors.New("升级恢复未完整选择原代码、完整 jail 配置及停止服务")
	}
	registry, err := loadFail2banNginxRegistry(i.Request.DataDir)
	if err != nil {
		return err
	}
	sources, err := loadFail2banHostSources(i.Request.DataDir)
	if err != nil {
		return err
	}
	sync, err := loadFail2banHostSync(i.Request.DataDir)
	if err != nil {
		return err
	}
	u := i.Undo
	if u.Nginx != nil && !fail2banUpgradeOneOf(registry, u.Nginx) || u.Sources != nil && !fail2banUpgradeOneOf(sources, u.Sources) || u.Sync != nil && !fail2banUpgradeOneOf(sync, u.Sync) {
		return errors.New("升级恢复的新动作批准尚未全部发布")
	}
	return nil
}

func (i fail2banUpgradeRestoreIntent) applyGrants(j *Journal) error {
	if after := i.transferredParent(); after != nil {
		actual, err := j.Get(after.OperationID)
		if err != nil {
			return err
		}
		if !sameFail2banUpgradePreparationRecord(actual, *after) {
			if !sameFail2banUpgradePreparationRecord(actual, *i.Recovery.Parent) {
				return ErrExternalChange
			}
			if err = j.Put(*after); err != nil {
				return err
			}
		}
	}
	u := i.Undo
	return publishFail2banUpgradeGrants(i.Request.DataDir, u.Nginx, u.Sources, u.Sync)
}
