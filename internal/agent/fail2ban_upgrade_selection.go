package agent

import (
	"context"
	"errors"
	"path/filepath"
)

// A selection keeps its real authorizing transaction. A completed recovery is
// not a reverse switch, and never receives the original switch's old grant.
type fail2banUpgradeSelection struct {
	DataDir, SwitchID, RestoreID string
	SHA256, ReceiptSHA256        string
	CompletedAt                  int64
	Managed                      fail2banManagedRecord
	Bundle                       *fail2banJailBundle
	Snapshot                     fail2banStateReceipt
	Manifest                     fail2banStateManifest
	Registry                     fail2banNginxRegistry
	Sources                      *fail2banHostSourcesEvent
	Sync                         *fail2banHostSyncEvent
	Registration                 *fail2banHostRegistration
	Protection                   *fail2banHostProtectionEvent
	Original                     fail2banUpgradeSwitch
	Reserved                     []string
}

func fail2banUpgradeSelectionRef(switchID, restoreID string) bool {
	return validID(switchID) && restoreID == "" || switchID == "" && validID(restoreID)
}

func fail2banUpgradeSelectionSourceID(switchID, restoreID string) string {
	if restoreID != "" {
		return restoreID
	}
	return switchID
}

func (s fail2banUpgradeSelection) matches(switchID, restoreID string) bool {
	return fail2banUpgradeSelectionRef(switchID, restoreID) && s.SwitchID == switchID && s.RestoreID == restoreID
}

func selectionFromFail2banUpgradeSwitch(i fail2banUpgradeSwitch, r fail2banUpgradeSwitchReceipt) fail2banUpgradeSelection {
	registry, sources, sync := fail2banUpgradeVerificationGrants(i)
	return fail2banUpgradeSelection{DataDir: i.Request.DataDir, SwitchID: i.Request.OperationID, SHA256: i.hash(), ReceiptSHA256: fail2banUpgradeGrantHash("switch-receipt", r), CompletedAt: r.CompletedAt, Managed: i.After, Bundle: i.Prepared.Material.Bundle, Snapshot: i.Snapshot, Manifest: i.Manifest, Registry: registry, Sources: sources, Sync: sync, Registration: i.Prepared.Basis.HostRegistration, Protection: i.Prepared.Basis.HostProtection, Original: i}
}

// Reading an acknowledged source is historical authentication only. Before
// any start, beforeStart separately checks the live stopped before-image.
func readFail2banUpgradeSelection(data, switchID, restoreID string) (fail2banUpgradeSelection, error) {
	var out fail2banUpgradeSelection
	if !fail2banUpgradeSelectionRef(switchID, restoreID) {
		return out, errors.New("须且只能指定一个已完成的升级切换或停止态恢复 UUID")
	}
	if switchID != "" {
		i, r, err := readFail2banUpgradeVerificationSwitch(data, switchID)
		if err != nil {
			return out, err
		}
		return selectionFromFail2banUpgradeSwitch(i, r), nil
	}
	i, original, err := readFail2banUpgradeRestore(data, restoreID)
	if err != nil {
		return out, err
	}
	f, err := i.facts()
	if err != nil {
		return out, err
	}
	if f.Receipt == nil || f.Receipt.Outcome != "restored" {
		return out, errors.New("恢复启动及保护核对须引用已完成的原版本停止态恢复")
	}
	audit, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(restoreID)
	if err != nil || !sameFail2banUpgradePreparationRecord(audit, i.record(f.Receipt)) {
		return out, errors.Join(errors.New("恢复启动前须完成原停止态恢复审计"), err)
	}
	u, basis := i.Undo, original.Prepared.Basis
	out = fail2banUpgradeSelection{DataDir: data, RestoreID: restoreID, SHA256: i.hash(), ReceiptSHA256: fail2banUpgradeGrantHash("upgrade-restore-receipt", f.Receipt), CompletedAt: f.Receipt.CompletedAt, Managed: u.Managed, Bundle: basis.Bundle, Snapshot: original.Snapshot, Manifest: original.Manifest, Registry: basis.Registry, Sources: basis.HostSources, Sync: basis.HostSync, Registration: basis.HostRegistration, Protection: basis.HostProtection, Original: original, Reserved: []string{restoreID, i.Request.ActivationID, u.Managed.EventID}}
	if u.Nginx != nil {
		out.Registry = *u.Nginx
		out.Reserved = append(out.Reserved, u.Nginx.ID)
	}
	if u.Sources != nil {
		out.Sources = u.Sources
		out.Reserved = append(out.Reserved, u.Sources.ID)
	}
	if u.Sync != nil {
		out.Sync = u.Sync
		out.Reserved = append(out.Reserved, u.Sync.ID)
	}
	a, err := readFail2banUpgradeActivationIntent(data, i.Request.ActivationID)
	if err != nil {
		return out, err
	}
	out.Reserved = append(out.Reserved, a.VerificationID)
	return out, nil
}

func (s fail2banUpgradeSelection) independentID(id string) error {
	if !validID(id) {
		return errors.New("升级启动或保护证明须使用独立 UUID")
	}
	if err := fail2banUpgradeVerificationID(id, s.Original); err != nil {
		return err
	}
	reservedIDs := append(fail2banUpgradeOriginalIDs(s.Original.Prepared.Basis, s.Original.Prepared.Recovery), s.Reserved...)
	for _, reserved := range reservedIDs {
		if id == reserved {
			return errors.New("升级启动或保护证明不能复用恢复、选择或批准标识")
		}
	}
	return nil
}

func (s fail2banUpgradeSelection) beforeStart(ctx context.Context) error {
	if s.RestoreID == "" {
		if err := s.Original.snapshot(ctx); err != nil {
			return err
		}
		return s.Original.observe(ctx, nil)
	}
	i, original, err := readFail2banUpgradeRestore(s.DataDir, s.RestoreID)
	if err != nil {
		return err
	}
	if i.hash() != s.SHA256 {
		return ErrExternalChange
	}
	if err = i.snapshot(ctx, original); err != nil {
		return err
	}
	if err = i.observe(ctx, original); err != nil {
		return err
	}
	return i.selected(ctx)
}
