package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Called under the independent worker's host/binding locks. Each selected
// recovery freezes other writers until publication or explicit cancellation.
func (f *fail2banHostSyncExecutor) bootRecovery(ctx context.Context, event *fail2banHostSyncEvent) (bool, error) {
	dataDir := f.server.DataDir
	current, err := loadFail2banHostBootRecovery(dataDir)
	if err != nil {
		return true, err
	}
	if current != nil {
		if err = ensureFail2banHostBootRecoveryRecord(dataDir, current); err != nil {
			return true, err
		}
		record, e := current.record(dataDir)
		if e != nil {
			return true, e
		}
		if record.State == "running" {
			err = f.advanceBootRecovery(ctx, current)
			if err != nil {
				err = fail2banHostBootRecoveryFailure(dataDir, current, err)
			}
			if err == nil {
				latest, e := current.record(dataDir)
				if e != nil {
					return true, e
				}
				if latest.State == "running" && latest.Error != "" {
					latest.Error = ""
					err = (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Put(latest)
				}
			}
			return true, err
		}
		if record.State == "cancelled" {
			old, e := current.retirement(dataDir)
			if e != nil {
				return true, e
			}
			if event != nil && (event.ID == old.Sync.ID || event.ID == old.StopID || event.ID == current.SyncID) {
				return true, nil
			}
		}
	}
	if event == nil || event.Action != "enable" || !event.RecoverOnBoot {
		return false, nil
	}
	if err = fail2banHostBootSyncAuthority(dataDir, event); err != nil {
		return true, err
	}
	machine, boot, err := fail2banHostBootIdentity()
	if err != nil {
		return true, err
	}
	if machine != event.MachineIDHash {
		return true, errors.New("主机身份与启动恢复批准不一致，须本机重新核对")
	}
	if boot == event.BootID {
		return false, nil
	}
	if stopping, e := loadFail2banHostSyncStop(dataDir, event); e != nil || stopping != nil {
		return false, e
	}
	if f.gate.closing() {
		return true, ErrBusy
	}
	admit, err := fail2banHostSyncAdmission(dataDir, true)
	if err != nil {
		return true, err
	}
	defer admit()
	protection, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return true, err
	}
	sources, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return true, err
	}
	if protection == nil || sources == nil || protection.ID != event.ProtectionID || sources.ID != event.SourcesID || protection.Action != "approve" || sources.Action != "approve" || protection.Owner != event.Owner || protection.RegistrationID != event.RegistrationID || protection.NamespaceID != event.NamespaceID || sources.Owner != event.Owner || sources.RegistrationID != event.RegistrationID || sources.NamespaceID != event.NamespaceID || sources.EngineKey != event.EngineKey {
		return true, errors.New("原保护或官方来源批准已变化，禁止启动恢复")
	}
	protected, err := fail2banHostProtectedSources(ctx, protection.Policy)
	if err != nil {
		return true, err
	}
	sample, err := collectFail2banHost(ctx, dataDir, sources, protected)
	if err != nil {
		return true, err
	}
	if err = checkFail2banBootManagers(ctx, dataDir); err != nil {
		return true, err
	}
	dir := filepath.Join(fail2banHostBootRecoveryDir(dataDir), "events")
	if err = secure.RootDirectory(dir, 0700); err != nil {
		return true, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	r, err := loadFail2banHostBootRecoveryEvent(dataDir, fail2banHostBootOperationID("recovery", event.ID, boot))
	if err != nil && (!os.IsNotExist(err) || r != nil) {
		return true, err
	}
	retirementID := fail2banHostBootOperationID("retirement", event.ID, boot)
	old, err := loadFail2banHostRetirementEvent(dataDir, retirementID)
	if os.IsNotExist(err) {
		if len(entries) >= 2048 {
			return true, errors.New("启动恢复记录容量已满，须本机维护")
		}
		old, err = prepareFail2banHostRetirement(ctx, dataDir, retirementID, event.RegistrationID)
	}
	if err != nil {
		return true, err
	}
	if old.Sync == nil || old.Sync.ID != event.ID || old.Stopping != nil {
		return true, errors.New("启动恢复的原会话已变化或已明确停止")
	}
	if r == nil {
		r = newFail2banHostBootRecovery(current, old, boot, protection, sources)
	}
	if err = r.valid(dataDir); err != nil {
		return true, err
	}
	if err = checkFail2banBootScope(r, old.Sync); err != nil {
		return true, err
	}
	if err = sample.unchanged(ctx, dataDir); err != nil {
		return true, err
	}
	if err = checkFail2banHostBootRecoveryBase(dataDir, r); err != nil {
		return true, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return true, err
	}
	if err = writeFail2banJailImmutable(filepath.Join(dir, r.ID+".json"), raw, fail2banHostBootRecoveryBytes); err != nil {
		return true, err
	}
	if err = rootJSONWrite(filepath.Join(fail2banHostBootRecoveryDir(dataDir), "current.json"), struct {
		ID string `json:"id"`
	}{r.ID}, 1024); err != nil {
		return true, err
	}
	return true, ensureFail2banHostBootRecoveryRecord(dataDir, r)
}

func checkFail2banBootManagers(ctx context.Context, dataDir string) error {
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	observer := firewallObserver{scope: "host", ctx: ctx, dataDir: dataDir}
	return checkFirewallManagers(observer.collect(call))
}

func checkFail2banBootScope(r *fail2banHostBootRecovery, original *fail2banHostSyncEvent) error {
	machine, boot, err := fail2banHostBootIdentity()
	if err != nil {
		return err
	}
	namespace, err := nftNamespace()
	if err != nil {
		return err
	}
	if machine != original.MachineIDHash || boot != r.BootID || namespace != r.NamespaceID {
		return errors.New("启动恢复期间主机、启动或命名空间身份变化；暂停新提交，须本机取消后重新核对")
	}
	return nil
}

func fail2banHostBootSyncAuthority(dataDir string, event *fail2banHostSyncEvent) error {
	if event.RecoveryID == "" {
		return nil
	}
	r, err := loadFail2banHostBootRecoveryEvent(dataDir, event.RecoveryID)
	if err != nil {
		return err
	}
	old, err := r.retirement(dataDir)
	if err != nil {
		return err
	}
	record, err := r.record(dataDir)
	if err != nil {
		return err
	}
	if record.State != "succeeded" || event.RequestHash != r.sync(old).RequestHash {
		return errors.New("派生持续会话的启动恢复尚未完成或已取消")
	}
	return nil
}

func (f *fail2banHostSyncExecutor) advanceBootRecovery(ctx context.Context, r *fail2banHostBootRecovery) error {
	dataDir := f.server.DataDir
	old, err := r.retirement(dataDir)
	if err != nil {
		return err
	}
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return err
	}
	// Recovery of a durable create is observation-only, including during a later
	// boot or maintenance closing. It must never be submitted for a second time.
	if root != nil && root.OperationID == r.RegistrationID && (root.State == "creating" || root.State == "removing" || !fail2banHostRegistrationReceipt(dataDir, root)) {
		if root.Owner != r.Owner || root.Action != "init" || root.BaseOperationID != old.RegistrationID || root.Baseline.NamespaceID != r.NamespaceID {
			return errors.New("启动恢复的待定创建不属于原意图")
		}
		_, err = recoverFail2banHostRegistration(dataDir, root)
		return err
	}
	if err = checkFail2banBootScope(r, old.Sync); err != nil {
		return err
	}
	selected, err := loadFail2banHostRetirement(dataDir)
	if err != nil {
		return err
	}
	if selected == nil || selected.ID != old.ID {
		if selected == nil && old.PreviousID != "" || selected != nil && selected.ID != old.PreviousID {
			return errors.New("启动恢复的原退役选择发生变化")
		}
		admit, e := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).maintenanceLock()
		if e != nil {
			return e
		}
		defer admit()
		if e = checkFail2banHostRetirementBase(dataDir, old); e != nil {
			return e
		}
		if e = rootJSONWrite(filepath.Join(fail2banHostRetirementDir(dataDir), "current.json"), struct {
			ID string `json:"id"`
		}{old.ID}, 1024); e != nil {
			return e
		}
		if e = ensureFail2banHostRetirementRecord(dataDir, old); e != nil {
			return e
		}
		return finishFail2banHostRetirement(ctx, dataDir, old)
	}
	retired, err := old.record(dataDir)
	if err != nil {
		return err
	}
	if retired.State != "succeeded" {
		return errors.New("启动恢复须先完成原范围退役")
	}
	if f.gate.closing() {
		return ErrBusy
	}
	admit, err := fail2banHostSyncAdmission(dataDir, true)
	if err != nil {
		return err
	}
	defer admit()
	if root == nil {
		return errors.New("启动恢复的登记丢失")
	}
	if root.OperationID == old.RegistrationID {
		expected := old.released()
		actual := *root
		actual.UpdatedAt = 0
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(expected)
		if string(a) != string(b) || !fail2banHostRegistrationReceipt(dataDir, root) {
			return errors.New("启动恢复的原释放登记不匹配")
		}
		if err = checkFail2banBootManagers(ctx, dataDir); err != nil {
			return err
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		kernel, e := snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
		cancel()
		if e != nil || !validFail2banHostAbsence(kernel) || kernel.NamespaceID != r.NamespaceID {
			return errors.Join(errors.New("新启动目标未证明缺失，禁止创建或接管同名表"), e)
		}
		if err = checkFail2banBootScope(r, old.Sync); err != nil {
			return err
		}
		if f.gate.closing() {
			return ErrBusy
		}
		v := &fail2banHostRegistration{Schema: 1, Owner: r.Owner, OperationID: r.RegistrationID, BaseOperationID: old.RegistrationID, Action: "init", State: "creating", OperationState: "running", RequestHash: fail2banHostRegistrationRequest("init", r.RegistrationID, old.RegistrationID), Baseline: kernel}
		_, err = submitFail2banHostRegistration(ctx, dataDir, v)
		return err
	}
	if root.OperationID != r.RegistrationID || root.Owner != r.Owner || root.Action != "init" || root.BaseOperationID != old.RegistrationID || root.State != "registered" || root.Confirmed.NamespaceID != r.NamespaceID || !fail2banHostRegistrationReceipt(dataDir, root) {
		return errors.New("新启动登记未确认；不重试创建，须本机核对或取消")
	}
	if err = proveFail2banBootEmpty(ctx, root); err != nil {
		return err
	}
	currentProtection, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return err
	}
	p := r.protection()
	if currentProtection == nil {
		return errors.New("启动恢复的保护批准指针丢失")
	}
	if currentProtection.ID == r.Protection.ID && currentProtection.RequestHash == r.Protection.RequestHash {
		return saveFail2banHostProtection(dataDir, p)
	}
	if currentProtection.ID != p.ID || currentProtection.RequestHash != p.RequestHash {
		return errors.New("启动恢复的保护批准变化，禁止覆盖")
	}
	currentSources, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return err
	}
	s := r.sources()
	if currentSources == nil {
		return errors.New("启动恢复的官方来源指针丢失")
	}
	if currentSources.ID != r.Sources.ID && currentSources.ID != s.ID || currentSources.ID == r.Sources.ID && currentSources.RequestHash != r.Sources.RequestHash || currentSources.ID == s.ID && currentSources.RequestHash != s.RequestHash {
		return errors.New("启动恢复的官方来源批准变化，禁止覆盖")
	}
	protected, err := fail2banHostProtectedSources(ctx, p.Policy)
	if err != nil {
		return err
	}
	sample, err := collectFail2banHost(ctx, dataDir, s, protected)
	if err != nil {
		return err
	}
	if err = checkFail2banBootScope(r, old.Sync); err != nil {
		return err
	}
	if currentSources.ID == r.Sources.ID {
		return saveFail2banHostSources(dataDir, s)
	}
	if err = checkFail2banBootManagers(ctx, dataDir); err != nil {
		return err
	}
	currentSync, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return err
	}
	event := r.sync(old)
	if currentSync == nil || currentSync.ID != old.StopID && currentSync.ID != event.ID {
		return errors.New("启动恢复的持续会话基础变化")
	}
	if currentSync.ID == old.StopID && currentSync.RequestHash != old.stopped().RequestHash || currentSync.ID == event.ID && currentSync.RequestHash != event.RequestHash {
		return errors.New("启动恢复的完整持续批准不匹配")
	}
	if err = sample.unchanged(ctx, dataDir); err != nil {
		return err
	}
	if err = writeFail2banHostSyncEvent(dataDir, event); err != nil {
		return err
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	parent, err := j.Get(event.ID)
	if os.IsNotExist(err) {
		if err = j.Put(fail2banHostSyncParent(event)); err != nil {
			return err
		}
	} else if err != nil || !sameFail2banRetirementRecord(parent, fail2banHostSyncParent(event)) {
		return errors.Join(errors.New("启动恢复的新会话父回执冲突"), err)
	}
	if currentSync.ID != event.ID {
		if err = publishFail2banHostSync(dataDir, event); err != nil {
			return err
		}
	}
	if err = proveFail2banBootEmpty(ctx, root); err != nil {
		return err
	}
	if err = checkFail2banBootScope(r, old.Sync); err != nil {
		return err
	}
	return finishFail2banHostBootRecovery(dataDir, r)
}

func proveFail2banBootEmpty(ctx context.Context, root *fail2banHostRegistration) error {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	kernel, err := snapshotFail2banHostRegistration(call, root.Owner)
	if err != nil || !kernel.Available || !kernel.TableExists || kernel.Chains != 0 || kernel.Rules != 0 || kernel.NamespaceID != root.Confirmed.NamespaceID || kernel.Fingerprint != root.Confirmed.Fingerprint {
		return errors.Join(errors.New("新启动的所属空表无法证明，禁止批准持续执行"), err)
	}
	return nil
}
