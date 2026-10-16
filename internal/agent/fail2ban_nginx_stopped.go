package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// An unreadable/crashed engine is never evidence that its bans disappeared.
// Only a completed root stop/withdrawal plus a fresh inactive-service proof
// authorizes an empty snapshot for that installation's exact action grants.
func stoppedFail2banNginxSource(ctx context.Context, data string, grants []fail2banNginxGrant) (string, error) {
	r, err := loadFail2banManaged(data)
	if err != nil || r == nil {
		return "", err
	}
	key := fail2banNginxEngineKey(r.binding())
	for _, grant := range grants {
		if grant.EngineKey != key {
			return "", nil
		}
	}
	stopped, err := fail2banExplicitStop(r)
	if err != nil || !stopped {
		return "", err
	}
	if err = fail2banManagedStopped(ctx); err != nil {
		// An administrator may have started the same owned unit since the stop.
		// A complete live proof returns collection to the official live reader.
		if r.State == "installed" {
			if _, liveErr := readFail2banLiveService(ctx, r.binding()); liveErr == nil {
				return "", nil
			}
		}
		return "", errors.New("管理员停用登记存在，但实际服务停止状态无法核对")
	}
	if r.State == "rolled-back" {
		if _, err = os.Lstat(fail2banManagedUnit); !os.IsNotExist(err) {
			return "", errors.New("已撤回实例仍存在服务文件或无法完整核对")
		}
	} else if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return "", err
	}
	return r.EventID, nil
}

func fail2banExplicitStop(current *fail2banManagedRecord) (bool, error) {
	r := *current
	for depth := 0; depth < 256; depth++ {
		if r.ActionState != "completed" {
			return false, nil
		}
		switch r.Action {
		case "stop":
			return r.State == "installed", nil
		case "rollback":
			return r.State == "rolled-back", nil
		case "enable", "disable":
		default:
			return false, nil
		}
		if r.PreviousEvent == "" {
			return false, nil
		}
		if !validID(r.PreviousEvent) {
			return false, errors.New("受管服务停用历史指针无效")
		}
		var before fail2banManagedRecord
		if err := readFail2banNginxJSON(filepath.Join(fail2banManagedDir(r.DataDir), "history", r.PreviousEvent+".json"), &before, 16384); err != nil {
			return false, err
		}
		if before.Schema != 1 || before.EventID != r.PreviousEvent || before.OperationID != current.OperationID || before.DataDir != current.DataDir || fail2banNginxEngineKey(before.binding()) != fail2banNginxEngineKey(current.binding()) {
			return false, errors.New("受管服务停用历史身份无法核对")
		}
		r = before
	}
	return false, errors.New("受管服务停用历史超过核对预算，请重新明确停止服务")
}
