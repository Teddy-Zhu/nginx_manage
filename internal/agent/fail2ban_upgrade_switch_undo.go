package agent

import (
	"errors"
	"time"

	"nginxpanel/internal/secure"
)

type fail2banUpgradeUndoIDs struct{ Managed, Nginx, Sources, Sync string }

func (i fail2banUpgradeSwitch) makeUndo(previous, nginxPrevious, sourcesPrevious, syncPrevious string, ids fail2banUpgradeUndoIDs, at int64) (u fail2banUpgradeSwitchUndo, err error) {
	p := i.Prepared
	u.fail2banUpgradeSwitchMarker, u.CreatedAt = i.marker(), at
	if previous != p.Basis.Current.EventID && previous != i.After.EventID {
		return u, errors.New("撤回不能覆盖其他安装选择")
	}
	seen := map[string]bool{}
	checks := []struct {
		id       string
		required bool
	}{{ids.Managed, true}, {ids.Nginx, p.Material.Nginx != nil}, {ids.Sources, p.Material.Sources != nil}, {ids.Sync, p.Material.Sync != nil}}
	for _, check := range checks {
		if check.required != (check.id != "") || check.id != "" && (!validID(check.id) || seen[check.id]) {
			return u, errors.New("切换补偿事件标识无效")
		}
		if check.id != "" {
			seen[check.id] = true
		}
	}
	old := append(fail2banUpgradeOriginalIDs(p.Basis, p.Recovery), i.Request.OperationID, i.Request.PreparationID, i.Request.SnapshotID, i.After.EventID, p.Material.IDs.Jails, p.Material.IDs.Nginx, p.Material.IDs.Sources, p.Material.IDs.Sync)
	for _, id := range old {
		if id != "" && seen[id] {
			return u, errors.New("补偿须使用新事件，不得复用原批准或资源标识")
		}
	}
	u.Managed = fail2banUpgradeManagedEvent(p.Basis.Current, ids.Managed, previous, p.Basis.Current.JailSelection, "upgrade-revert", at)
	if err = validateFail2banManagedRecord(u.Managed, i.Request.DataDir); err != nil {
		return u, err
	}
	if p.Material.Nginx != nil {
		if nginxPrevious != p.Basis.Registry.ID && nginxPrevious != p.Material.Nginx.ID {
			return u, errors.New("撤回不能覆盖其他 Nginx 批准")
		}
		r := p.Basis.Registry
		r.ID, r.PreviousID, r.ApprovedAt = ids.Nginx, nginxPrevious, at
		r.RequestHash = fail2banUpgradeGrantHash("undo-nginx", struct {
			Intent, ID, Previous string
			Grants               []fail2banNginxGrant
		}{i.hash(), r.ID, r.PreviousID, r.Grants})
		if err = validFail2banNginxRegistry(r, false); err != nil {
			return u, err
		}
		u.Nginx = &r
	}
	if p.Material.Sources != nil {
		if sourcesPrevious != p.Basis.HostSources.ID && sourcesPrevious != p.Material.Sources.ID {
			return u, errors.New("撤回不能覆盖其他宿主机来源批准")
		}
		e := *p.Basis.HostSources
		e.ID, e.PreviousID, e.ApprovedAt = ids.Sources, sourcesPrevious, at
		e.RequestHash = e.requestHash()
		if !e.valid() {
			return u, errors.New("宿主机来源补偿材料无效")
		}
		u.Sources = &e
	}
	if p.Material.Sync != nil {
		if syncPrevious != p.Basis.HostSync.ID && syncPrevious != p.Material.Sync.ID {
			return u, errors.New("撤回不能覆盖其他持续同步批准")
		}
		e := *p.Basis.HostSync
		e.ID, e.PreviousID, e.SessionID, e.SourcesID, e.RecoveryID, e.ApprovedAt = ids.Sync, syncPrevious, ids.Sync, ids.Sources, "", at
		e.RuntimeBaseID = ""
		if p.Recovery.Runtime != nil {
			e.RuntimeBaseID = p.Recovery.Runtime.Intent.OperationID
		}
		e.RequestHash = e.requestHash()
		if !e.valid() {
			return u, errors.New("持续同步补偿材料无效")
		}
		u.Sync = &e
	}
	return u, nil
}

func (i fail2banUpgradeSwitch) validateUndo(u fail2banUpgradeSwitchUndo) error {
	if u.fail2banUpgradeSwitchMarker != i.marker() || u.CreatedAt < i.CreatedAt || u.CreatedAt > time.Now().Unix()+300 {
		return errors.New("切换补偿意图身份无效")
	}
	ids := fail2banUpgradeUndoIDs{Managed: u.Managed.EventID}
	var np, sp, cp string
	if u.Nginx != nil {
		ids.Nginx, np = u.Nginx.ID, u.Nginx.PreviousID
	}
	if u.Sources != nil {
		ids.Sources, sp = u.Sources.ID, u.Sources.PreviousID
	}
	if u.Sync != nil {
		ids.Sync, cp = u.Sync.ID, u.Sync.PreviousID
	}
	expected, err := i.makeUndo(u.Managed.PreviousEvent, np, sp, cp, ids, u.CreatedAt)
	if err != nil {
		return err
	}
	if fail2banUpgradeGrantHash("switch-undo", expected) != fail2banUpgradeGrantHash("switch-undo", u) {
		return errors.New("切换补偿改变了原代码或批准范围")
	}
	return nil
}

func (i fail2banUpgradeSwitch) newUndo() (fail2banUpgradeSwitchUndo, error) {
	data := i.Request.DataDir
	managed, err := loadFail2banManaged(data)
	if err != nil || managed == nil {
		return fail2banUpgradeSwitchUndo{}, errors.Join(errors.New("撤回须保留当前安装选择"), err)
	}
	nginx, err := loadFail2banNginxRegistry(data)
	if err != nil {
		return fail2banUpgradeSwitchUndo{}, err
	}
	sources, err := loadFail2banHostSources(data)
	if err != nil {
		return fail2banUpgradeSwitchUndo{}, err
	}
	sync, err := loadFail2banHostSync(data)
	if err != nil {
		return fail2banUpgradeSwitchUndo{}, err
	}
	ids := fail2banUpgradeUndoIDs{Managed: secure.ID()}
	var sp, cp string
	if sources != nil {
		sp = sources.ID
	}
	if sync != nil {
		cp = sync.ID
	}
	if i.Prepared.Material.Nginx != nil {
		ids.Nginx = secure.ID()
	}
	if i.Prepared.Material.Sources != nil {
		ids.Sources = secure.ID()
	}
	if i.Prepared.Material.Sync != nil {
		ids.Sync = secure.ID()
	}
	return i.makeUndo(managed.EventID, nginx.ID, sp, cp, ids, time.Now().Unix())
}
