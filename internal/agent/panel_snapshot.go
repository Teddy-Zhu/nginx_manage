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
	return accessPanelSnapshot(ctx, data, id, maintenanceID, epoch, false, nil)
}

// WithCheckedPanelSnapshot retains independent maintenance admission while a
// local root recovery coordinator consumes the authenticated rollback receipt.
// The callback is a Go-only entry point, never an IPC-supplied action.
func WithCheckedPanelSnapshot(ctx context.Context, data, id, maintenanceID, epoch string, visit func(panelrecovery.Result) error) error {
	if visit == nil {
		return errors.New("恢复快照协调缺少本机处理入口")
	}
	_, err := accessPanelSnapshot(ctx, data, id, maintenanceID, epoch, true, visit)
	return err
}

func accessPanelSnapshot(ctx context.Context, data, id, maintenanceID, epoch string, inspect bool, visit func(panelrecovery.Result) error) (panelrecovery.Result, error) {
	var out panelrecovery.Result
	if os.Geteuid() != 0 || !validID(id) || !validID(maintenanceID) || !validID(epoch) {
		return out, errors.New("恢复快照操作须由 root 提供原维护会话和 epoch")
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
	if err = installGrant(j, maintenanceID, epoch, inspect); err != nil {
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
		settled, e := settledPanelUpdate(r, maintenanceID)
		if e != nil {
			return out, e
		}
		if settled {
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
	if inspect {
		out, err = panelrecovery.Inspect(ctx, data, id)
		if err != nil {
			return out, err
		}
		if out.State != "verified" {
			return panelrecovery.Result{}, errors.New("原快照已提交退役，不能用于恢复协调")
		}
		m := out.Receipt.Manifest
		if m.MaintenanceID != maintenanceID || m.UID != uid || m.GID != gid {
			return panelrecovery.Result{}, errors.New("本机快照与原维护会话或当前面板账户不一致")
		}
		if visit != nil {
			err = visit(out)
		}
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
	binding, err := panelruntime.ReadDeployment(data)
	if err != nil {
		return 0, 0, err
	}
	if binding.UID != uid || binding.GID != gid {
		return 0, 0, errors.New("面板运行绑定与本机专用账户不匹配")
	}
	return uid, gid, nil
}
