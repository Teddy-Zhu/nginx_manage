package agent

import (
	"encoding/json"
	"errors"
	"time"
)

// Freeze only this installation's grants before admitting a withdrawal. The
// existing Nginx reconciler, rather than service control, owns runtime sets.
func (l *fail2banLifecycle) withdrawal(id, hash string) (*fail2banNginxRegistry, *fail2banNginxRegistry, error) {
	r, err := loadFail2banManaged(l.server.DataDir)
	if err != nil || r == nil {
		return nil, nil, errors.New("撤回安装来源无法核对")
	}
	before, err := loadFail2banNginxRegistry(l.server.DataDir)
	if err != nil {
		return nil, nil, err
	}
	key := fail2banNginxEngineKey(r.binding())
	after := before
	after.Grants = []fail2banNginxGrant{}
	for _, grant := range before.Grants {
		if grant.EngineKey != key {
			after.Grants = append(after.Grants, grant)
		}
	}
	if len(after.Grants) == len(before.Grants) {
		return nil, nil, nil
	}
	after.ID, after.PreviousID, after.RequestHash, after.ApprovedAt = id, before.ID, hash, time.Now().Unix()
	if err = validFail2banNginxRegistry(after, false); err != nil {
		return nil, nil, err
	}
	return &before, &after, nil
}
func (l *fail2banLifecycle) completeWithdrawal(record *Record) error {
	i := record.Fail2banLifecycle
	if i.BeforeRegistry == nil && i.AfterRegistry == nil {
		return nil
	}
	if i.BeforeRegistry == nil || i.AfterRegistry == nil {
		return errors.New("撤回动作授权快照不完整")
	}
	before, after := *i.BeforeRegistry, *i.AfterRegistry
	if validFail2banNginxRegistry(before, true) != nil || validFail2banNginxRegistry(after, false) != nil || after.ID != record.OperationID || after.PreviousID != before.ID || after.RequestHash != record.RequestHash {
		return errors.New("撤回动作授权合同无效")
	}
	r, err := loadFail2banManaged(l.server.DataDir)
	if err != nil || r == nil || r.OperationID != i.Request.Input.BaseID || r.State != "rolled-back" {
		return errors.New("撤回实例身份无法核对")
	}
	key := fail2banNginxEngineKey(r.binding())
	expected := []fail2banNginxGrant{}
	for _, grant := range before.Grants {
		if grant.EngineKey != key {
			expected = append(expected, grant)
		}
	}
	actualRaw, _ := json.Marshal(after.Grants)
	expectedRaw, _ := json.Marshal(expected)
	if string(actualRaw) != string(expectedRaw) {
		return errors.New("撤回动作授权超出该安装的作用域")
	}
	current, err := loadFail2banNginxRegistry(l.server.DataDir)
	if err != nil {
		return err
	}
	currentRaw, _ := json.Marshal(current)
	beforeRaw, _ := json.Marshal(before)
	afterRaw, _ := json.Marshal(after)
	if string(currentRaw) == string(afterRaw) {
		return nil
	}
	if string(currentRaw) != string(beforeRaw) {
		return errors.New("动作授权已发生外部变化，未覆盖当前登记")
	}
	if err = saveFail2banNginxRegistry(l.server.DataDir, after); err != nil {
		return err
	}
	if f := l.server.fail2banNginx; f != nil {
		f.mu.Lock()
		f.value.Registry = after
		f.registryVersion++
		f.mu.Unlock()
	}
	return nil
}
