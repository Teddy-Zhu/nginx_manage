package agent

import (
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

// Check the compensation path before stopping the original service. The parent
// fence prevents another upgrade from consuming these slots between children;
// each executor still rechecks its actual publication and disk requirements.
func (i fail2banUpgradeRunIntent) reserveChildren(p fail2banUpgradePreparation) error {
	data := i.Request.DataDir
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return err
	}
	if len(records)+9 > 2048 {
		return errors.New("整体升级缺少父子操作及补偿证明的审计容量")
	}
	for _, store := range []string{fail2banUpgradeQuiescences(data), fail2banUpgradeSwitches(data), fail2banUpgradeRestores(data)} {
		if err = fail2banStatePrivateDir(store, true); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(store)); err != nil {
			return err
		}
		if err = fail2banUpgradeSwitchQuota(store, true); err != nil {
			return err
		}
	}
	store := fail2banUpgradeActivations(data)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err = fail2banUpgradeActivationQuota(store, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		return err
	}
	count := 0
	for _, e := range entries {
		if e.Name() != "current.json" {
			count++
		}
	}
	if count > 6 {
		return errors.New("整体升级须为候选和原版本恢复各保留一个启动材料位置")
	}
	if err = reserveFail2banUpgradeVerification(data); err != nil {
		return err
	}
	entries, err = os.ReadDir(fail2banUpgradeVerifications(data))
	if err != nil {
		return err
	}
	if len(entries) > 6 {
		return errors.New("整体升级须为候选和原版本恢复各保留一个保护证明位置")
	}
	var proofBytes int64
	for _, entry := range entries {
		f, info, e := secure.OpenRootFile(filepath.Join(fail2banUpgradeVerifications(data), entry.Name()), fail2banUpgradeVerificationLimit)
		if e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		proofBytes += info.Size()
	}
	if proofBytes > (128<<20)-3*fail2banUpgradeVerificationLimit {
		return errors.New("整体升级缺少候选、恢复及原子发布保护证明空间")
	}
	store = fail2banUpgradeRestoreStates(data)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	var size int64
	for n, resource := range fail2banStateResources {
		f, info, e := secure.OpenRootFile(filepath.Join(p.Basis.Current.work(), "state", resource.name), resource.limit)
		if os.IsNotExist(e) && n != 0 {
			continue
		}
		if e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		size += info.Size()
	}
	return fail2banStateQuota(store, size+(128<<20)+(2<<20), true)
}
