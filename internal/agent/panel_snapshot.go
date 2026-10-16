package agent

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
)

// CapturePanelSnapshot holds the same root admission lock used by maintenance
// release. The caller cannot authorize a new snapshot with a stale Agent epoch.
// A snapshot alone never authorizes a later restore after maintenance is released.
func CapturePanelSnapshot(ctx context.Context, data, id, maintenanceID, epoch string) (panelrecovery.Result, error) {
	var out panelrecovery.Result
	if os.Geteuid() != 0 || !validID(id) || !validID(maintenanceID) || !validID(epoch) {
		return out, errors.New("快照捕获须由 root 提供原维护会话和 epoch")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = installGrant(j, maintenanceID, epoch, false); err != nil {
		return out, err
	}
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		if r.Kind == "maintenance.lock" {
			continue
		}
		switch r.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return out, errors.New("仍有独立副作用任务执行中或待恢复，不能捕获面板快照")
		}
	}
	uid, gid, err := panelSnapshotIdentity(data)
	if err != nil {
		return out, err
	}
	return panelrecovery.Capture(ctx, panelrecovery.Input{DataDir: data, OperationID: id, MaintenanceID: maintenanceID, Epoch: epoch, UID: uid, GID: gid})
}

func panelSnapshotIdentity(data string) (int, int, error) {
	identity, err := user.Lookup("nginxpanel")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(identity.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(identity.Gid)
	if err != nil {
		return 0, 0, err
	}
	if binding, err := panelruntime.ReadDeployment(data); err == nil {
		if binding.UID != uid || binding.GID != gid {
			return 0, 0, errors.New("面板运行绑定与本机专用账户不匹配")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	return uid, gid, nil
}
