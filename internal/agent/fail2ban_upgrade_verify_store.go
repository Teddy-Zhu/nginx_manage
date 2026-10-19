package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

var errFail2banUpgradeVerificationAbsent = errors.New("原升级保护证明不存在")

func readFail2banUpgradeVerification(data, id string) (fail2banUpgradeVerification, fail2banUpgradeSwitch, error) {
	var v fail2banUpgradeVerification
	var i fail2banUpgradeSwitch
	if !validID(id) {
		return v, i, errors.New("升级保护核对 UUID 无效")
	}
	store := fail2banUpgradeVerifications(data)
	if err := fail2banStatePrivateDir(store, false); err != nil {
		if os.IsNotExist(err) {
			return v, i, errFail2banUpgradeVerificationAbsent
		}
		return v, i, err
	}
	raw, err := listenerRead(filepath.Join(store, id+".json"), fail2banUpgradeVerificationLimit)
	if err != nil {
		if os.IsNotExist(err) {
			return v, i, errFail2banUpgradeVerificationAbsent
		}
		return v, i, err
	}
	if err = decodeFail2banNginxJSON(raw, &v); err != nil {
		return v, i, err
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return v, i, errors.New("升级保护证明字段或规范格式变化")
	}
	i, receipt, err := readFail2banUpgradeVerificationSwitch(data, v.Request.SwitchID)
	if err != nil {
		return v, i, err
	}
	if err = v.validate(data, id, i, receipt); err != nil {
		return v, i, err
	}
	if err = checkFail2banUpgradeCandidateLineage(i, v.Managed); err != nil {
		return v, i, err
	}
	return v, i, nil
}

func reserveFail2banUpgradeVerification(data string) error {
	store := fail2banUpgradeVerifications(data)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		return err
	}
	if len(entries) >= 8 {
		return errors.New("升级保护证明含临时材料已达 8 项容量上限，须本机维护")
	}
	var total int64
	for _, entry := range entries {
		f, info, err := secure.OpenRootFile(filepath.Join(store, entry.Name()), fail2banUpgradeVerificationLimit)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("升级保护证明须为 root 专用 0600 文件")
		}
		total += info.Size()
	}
	if total > 104<<20 {
		return errors.New("升级保护证明无法在 128 MiB 预算内发布完整原子记录")
	}
	return nil
}

func writeFail2banUpgradeVerification(v fail2banUpgradeVerification) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(v.path(), raw, fail2banUpgradeVerificationLimit)
}

func acknowledgeFail2banUpgradeVerification(v fail2banUpgradeVerification, j *Journal) error {
	r, err := j.Get(v.Request.OperationID)
	if err == nil {
		if !sameFail2banUpgradePreparationRecord(r, v.record()) {
			return errors.New("升级保护核对审计与原证明不匹配")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return j.Put(v.record())
}

func ReadFail2banUpgradeVerification(parent context.Context, data, scope, id string) (Fail2banUpgradeVerification, error) {
	var out Fail2banUpgradeVerification
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = parent.Err(); err != nil {
		return out, err
	}
	v, i, err := readFail2banUpgradeVerification(data, id)
	if err != nil {
		return out, err
	}
	out, err = v.result(i)
	if err != nil {
		return out, err
	}
	r, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !sameFail2banUpgradePreparationRecord(r, v.record()) {
		return out, errors.New("升级保护核对原审计无法匹配")
	}
	out.State = "verified"
	return out, nil
}
