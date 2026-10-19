package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

func fail2banUpgradeOneOf(value any, candidates ...any) bool {
	hash := fail2banUpgradeGrantHash("switch-value", value)
	for _, candidate := range candidates {
		if hash == fail2banUpgradeGrantHash("switch-value", candidate) {
			return true
		}
	}
	return false
}

// Every live pointer must be either the frozen before-image or an exact event
// authored by this transaction. Matching an ID alone cannot authorize a write.
func (i fail2banUpgradeSwitch) observe(ctx context.Context, u *fail2banUpgradeSwitchUndo) error {
	data, p := i.Request.DataDir, i.Prepared
	r, err := loadFail2banManaged(data)
	if err != nil {
		return err
	}
	registry, err := loadFail2banNginxRegistry(data)
	if err != nil {
		return err
	}
	sources, err := loadFail2banHostSources(data)
	if err != nil {
		return err
	}
	sync, err := loadFail2banHostSync(data)
	if err != nil {
		return err
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
	managedChoices := []any{p.Basis.Current, i.After}
	nginxChoices, sourceChoices, syncChoices := []any{p.Basis.Registry}, []any{p.Basis.HostSources}, []any{p.Basis.HostSync}
	if p.Material.Nginx != nil {
		nginxChoices = append(nginxChoices, p.Material.Nginx)
	}
	if p.Material.Sources != nil {
		sourceChoices = append(sourceChoices, p.Material.Sources)
	}
	if p.Material.Sync != nil {
		syncChoices = append(syncChoices, p.Material.Sync)
	}
	if u != nil {
		managedChoices = append(managedChoices, u.Managed)
		if u.Nginx != nil {
			nginxChoices = append(nginxChoices, u.Nginx)
		}
		if u.Sources != nil {
			sourceChoices = append(sourceChoices, u.Sources)
		}
		if u.Sync != nil {
			syncChoices = append(syncChoices, u.Sync)
		}
	}
	if r == nil || !fail2banUpgradeOneOf(r, managedChoices...) || !fail2banUpgradeOneOf(registry, nginxChoices...) || !fail2banUpgradeOneOf(sources, sourceChoices...) || !fail2banUpgradeOneOf(sync, syncChoices...) || !fail2banUpgradeOneOf(root, p.Basis.HostRegistration) || !fail2banUpgradeOneOf(protection, p.Basis.HostProtection) || !fail2banUpgradeOneOf(runtime, p.Recovery.Runtime) {
		return errors.New("切换范围出现其他安装、批准、登记或运行检查点，保留隔离")
	}
	_, bundle, err := selectedFail2banJails(r)
	if err != nil {
		return err
	}
	if err = verifyFail2banJailConfig(r, filepath.Join(r.work(), "config"), bundle); err != nil {
		return err
	}
	unit, err := nginxmodules.ReadTrusted(fail2banManagedUnit, 64<<10)
	if err != nil {
		return err
	}
	if string(unit) != p.Basis.Current.unit() && string(unit) != i.After.unit() {
		return errors.New("受管单元出现切换范围外的内容")
	}
	if err = fail2banManagedFile(fail2banManagedUnit, string(unit)); err != nil {
		return err
	}
	if stopping, err := loadFail2banHostSyncStop(data, sync); err != nil || stopping != nil {
		return errors.Join(errors.New("切换期间出现未完成的持续停用意图"), err)
	}
	if err = fail2banManagedNoOther(ctx, data, false); err != nil {
		return err
	}
	service, _, err := lifecycleService(ctx)
	if err != nil {
		return err
	}
	if err = fail2banExistingStopped(r.binding(), service); err != nil {
		return err
	}
	machine, boot, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil || machine != i.Manifest.Basis.MachineID || boot != i.Manifest.Basis.BootID {
		return errors.Join(errors.New("切换期间主机或启动代次变化，不能沿用原内核及状态证明"), err)
	}
	directory, files, err := observeFail2banStateDirectory(ctx, filepath.Join(r.work(), "state"))
	if err != nil || directory != i.Directory || fail2banStateFilesHash(files) != fail2banStateFilesHash(i.Manifest.Files) {
		return errors.Join(errors.New("切换期间原状态目录变化，不覆盖未知 SQLite 状态"), err)
	}
	if root != nil && root.State == "registered" {
		if !fail2banHostRegistrationReceipt(data, root) {
			return errors.New("原宿主机登记审计无法核对")
		}
		if runtime != nil && !fail2banHostRuntimeReceipt(data, runtime) {
			return errors.New("原宿主机运行审计无法核对")
		}
		program, _ := fail2banUpgradeOriginalHostProgram(p)
		kernel, err := program.snapshot(ctx)
		if err != nil || !kernel.TableExists || kernel.NamespaceID != i.Kernel.NamespaceID || kernel.Fingerprint != i.Kernel.Fingerprint {
			return errors.Join(errors.New("切换期间原宿主机规则缺失或漂移，禁止重建或接管"), err)
		}
	}
	return ctx.Err()
}

func (i fail2banUpgradeSwitch) transferParent(id string) error {
	j := &Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}
	before, err := i.parentBefore(id)
	if err != nil {
		return err
	}
	after, err := i.transferredParent(id)
	if err != nil {
		return err
	}
	actual, err := j.Get(id)
	if err != nil {
		return err
	}
	if sameFail2banUpgradePreparationRecord(actual, after) {
		return nil
	}
	if !sameFail2banUpgradePreparationRecord(actual, *before) {
		return errors.New("原持续会话审计已变化，不移交未知检查点")
	}
	return j.Put(after)
}

func (i fail2banUpgradeSwitch) applyGrants(u *fail2banUpgradeSwitchUndo) error {
	p, data := i.Prepared, i.Request.DataDir
	nginx, sources, sync := p.Material.Nginx, p.Material.Sources, p.Material.Sync
	if u != nil {
		nginx, sources, sync = u.Nginx, u.Sources, u.Sync
	}
	if err := writeFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "handover.json"), i.marker()); err != nil {
		return err
	}
	if p.Material.Sync != nil {
		if err := i.transferParent(p.Basis.HostSync.ID); err != nil {
			return err
		}
		if u != nil {
			j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
			if _, err := j.Get(p.Material.Sync.ID); err == nil {
				if err = i.transferParent(p.Material.Sync.ID); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	if nginx != nil {
		actual, err := loadFail2banNginxRegistry(data)
		if err != nil {
			return err
		}
		if actual.ID != nginx.ID {
			if actual.ID != nginx.PreviousID {
				return errors.New("Nginx 批准基础变化")
			}
			if err = saveFail2banNginxRegistry(data, *nginx); err != nil {
				return err
			}
		} else if !fail2banUpgradeOneOf(actual, nginx) {
			return ErrExternalChange
		}
	}
	if sources != nil {
		actual, err := loadFail2banHostSources(data)
		if err != nil {
			return err
		}
		if actual == nil {
			return errors.New("原来源批准丢失")
		}
		if actual.ID != sources.ID {
			if actual.ID != sources.PreviousID {
				return errors.New("宿主机来源批准基础变化")
			}
			event := *sources
			if err = saveFail2banHostSources(data, &event); err != nil {
				return err
			}
		} else if !fail2banUpgradeOneOf(actual, sources) {
			return ErrExternalChange
		}
	}
	if sync != nil {
		actual, err := loadFail2banHostSync(data)
		if err != nil {
			return err
		}
		if actual == nil || actual.ID != sync.ID && actual.ID != sync.PreviousID {
			return errors.New("持续同步批准基础变化")
		}
		event := *sync
		if err = writeFail2banHostSyncEvent(data, &event); err != nil {
			return err
		}
		j, expected := &Journal{Dir: filepath.Join(data, "agent", "operations")}, fail2banHostSyncParent(sync)
		if r, e := j.Get(sync.ID); os.IsNotExist(e) {
			if err = j.Put(expected); err != nil {
				return err
			}
		} else if e != nil {
			return e
		} else if !sameFail2banUpgradePreparationRecord(r, expected) {
			return errors.New("候选持续会话的父操作已变化")
		}
		if actual.ID != sync.ID {
			return publishFail2banHostSync(data, sync)
		}
		if !fail2banUpgradeOneOf(actual, sync) {
			return ErrExternalChange
		}
	}
	return nil
}

// Inspect unpublished immutable events too, and reserve one compensating
// event per affected store before consuming the forward event's last slot.
func (i fail2banUpgradeSwitch) grantEvents(u *fail2banUpgradeSwitchUndo) error {
	p, data := i.Prepared, i.Request.DataDir
	nginx, sources, sync := p.Material.Nginx, p.Material.Sources, p.Material.Sync
	if u != nil {
		nginx, sources, sync = u.Nginx, u.Sources, u.Sync
	}
	type eventFile struct {
		path     string
		expected any
		limit    int64
	}
	var files []eventFile
	if nginx != nil {
		files = append(files, eventFile{filepath.Join(fail2banNginxDir(data), "grants", nginx.ID+".json"), nginx, 32 << 10})
	}
	if sources != nil {
		files = append(files, eventFile{filepath.Join(fail2banHostSourcesDir(data), "events", sources.ID+".json"), sources, fail2banHostProtectionBytes})
	}
	if sync != nil {
		files = append(files, eventFile{filepath.Join(fail2banHostSyncDir(data), "events", sync.ID+".json"), sync, fail2banHostProtectionBytes})
	}
	for _, file := range files {
		want, err := json.Marshal(file.expected)
		if err != nil {
			return err
		}
		if int64(len(want)) > file.limit {
			return errors.New("升级批准超出原事件预算")
		}
		raw, err := listenerRead(file.path, file.limit)
		extra := 0
		if os.IsNotExist(err) {
			extra = 1
		} else if err != nil {
			return err
		} else if !bytes.Equal(raw, want) {
			return ErrExternalChange
		}
		if u == nil {
			extra++
		}
		entries, err := os.ReadDir(filepath.Dir(file.path))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if len(entries)+extra > 2048 {
			return errors.New("升级批准存储无法同时保留候选和新补偿事件，须本机维护")
		}
	}
	return nil
}

func (i fail2banUpgradeSwitch) replaceUnit(target fail2banManagedRecord) error {
	before, after := i.Prepared.Basis.Current.unit(), i.After.unit()
	raw, err := nginxmodules.ReadTrusted(fail2banManagedUnit, 64<<10)
	if err != nil {
		return err
	}
	if string(raw) == target.unit() {
		return fail2banManagedFile(fail2banManagedUnit, target.unit())
	}
	if string(raw) != before && string(raw) != after {
		return errors.New("受管单元出现切换范围外的内容")
	}
	if err = fail2banManagedFile(fail2banManagedUnit, string(raw)); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(fail2banManagedUnit), ".nginxpanel-fail2ban-"+i.Request.OperationID+"-"+target.EventID+".tmp")
	if _, err = os.Lstat(tmp); os.IsNotExist(err) {
		if err = durableFile(tmp, []byte(target.unit()), 0644, 0); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	f, info, err := secure.OpenRootFile(tmp, 64<<10)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	staged, err := nginxmodules.ReadTrusted(tmp, 64<<10)
	if err != nil || info.Mode().Perm() != 0644 || string(staged) != target.unit() {
		return errors.Join(ErrExternalChange, err)
	}
	if err = os.Rename(tmp, fail2banManagedUnit); err != nil {
		return err
	}
	return syncDir(filepath.Dir(fail2banManagedUnit))
}

func (i fail2banUpgradeSwitch) execute(ctx context.Context, u *fail2banUpgradeSwitchUndo) error {
	target := i.After
	if u != nil {
		target = u.Managed
	}
	if err := i.observe(ctx, u); err != nil {
		return err
	}
	if err := i.grantEvents(u); err != nil {
		return err
	}
	if err := writeFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "execution.json"), i.marker()); err != nil {
		return err
	}
	if err := verifyFail2banManaged(ctx, &target, false); err != nil {
		return err
	}
	if u == nil && i.Prepared.Material.Bundle != nil {
		if err := saveFail2banJailBundle(&target, *i.Prepared.Material.Bundle); err != nil {
			return err
		}
	}
	if err := i.replaceUnit(target); err != nil {
		return err
	}
	r, err := loadFail2banManaged(i.Request.DataDir)
	if err != nil {
		return err
	}
	if r.EventID != target.EventID {
		if err = publishFail2banManagedRecord(i.Request.DataDir, target.PreviousEvent, target); err != nil {
			return err
		}
	} else if !fail2banUpgradeOneOf(r, target) {
		return ErrExternalChange
	}
	if err = i.applyGrants(u); err != nil {
		return err
	}
	// daemon-reload is a convergent load of the exact owned file, never a
	// start/restart or a replay of an unknown service-control operation.
	if err = fail2banManagedSystemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return err
	}
	if err = verifyFail2banManaged(ctx, &target, true); err != nil {
		return err
	}
	if err = i.observe(ctx, u); err != nil {
		return err
	}
	outcome := "selected"
	if u != nil {
		outcome = "reverted"
	}
	receipt := fail2banUpgradeSwitchReceipt{fail2banUpgradeSwitchMarker: i.marker(), Outcome: outcome, CompletedAt: time.Now().Unix(), ManagedEvent: target.EventID, ManagedSHA256: fail2banUpgradeGrantHash("managed", target)}
	if err = writeFail2banUpgradeSwitchJSON(filepath.Join(i.dir(), "receipt.json"), receipt); err != nil {
		return err
	}
	return (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Put(i.record(&receipt, u))
}
