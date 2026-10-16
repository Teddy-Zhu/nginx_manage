package agent

import (
	"context"
	"errors"
	"path/filepath"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/storage"
)

// AuthorizeDisasterRuntime is a local root action, separate from IPC. The
// unprivileged peer can continue only the action explicitly approved here.
func AuthorizeDisasterRuntime(ctx context.Context, data, id, epoch string, rollback bool) error {
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".disaster-restore.lock")
	if err != nil {
		return err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer access()
	if err = installGrant(j, i.Stop.MaintenanceID, epoch, true); err != nil {
		return err
	}
	if err = checkDisasterRuntime(data, i); err != nil {
		return err
	}
	r, err := readDisasterRestore(data, id)
	if err != nil {
		return err
	}
	if disasterActivationCommitted(r) {
		return errors.New("原恢复已提交激活，禁止运行补偿或重新应用")
	}
	if r.Stage == "files_compensated" || r.Stage == "compensating" && !rollback {
		return errors.New("原恢复已进入文件补偿")
	}
	if !rollback {
		switch r.Stage {
		case "files_installed", "runtime_preparing", "runtime_applying", "runtime_confirmed":
		default:
			return errors.New("原文件安装尚未完成或已选择补偿，不能批准运行应用")
		}
	}
	fence, err := storage.ReadWriterFence(data)
	if err != nil || fence != i.Fence() {
		return errors.Join(err, errors.New("恢复运行批准缺少原写入屏障"))
	}
	return panelrecovery.ApproveDisasterRuntime(i, epoch, rollback)
}
