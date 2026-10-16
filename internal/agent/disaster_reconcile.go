package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/storage"
)

// ReconcileDisaster keeps root admission and writer exclusion around the
// unprivileged preparation/verifier and the fixed-file replacement. It never
// parses SQL, releases maintenance or activates serve.
func ReconcileDisaster(ctx context.Context, data, id, epoch string, prepare func(context.Context, panelrecovery.DisasterIntent) error) (out Record, err error) {
	if os.Geteuid() != 0 || !validID(id) || !validID(epoch) || prepare == nil {
		return out, errors.New("恢复对账需要本机 root、原操作和当前维护授权")
	}
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".disaster-restore.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	if err = installGrant(j, i.Stop.MaintenanceID, epoch, true); err != nil {
		return out, err
	}
	if err = checkDisasterRuntime(data, i); err != nil {
		return out, err
	}
	if err = checkDisasterRecords(j, i, true); err != nil {
		return out, err
	}
	if _, e := panelrecovery.ReadDisasterRuntimeApproval(i, true); e == nil {
		return out, errors.New("原恢复已批准补偿，禁止继续数据对账")
	} else if !os.IsNotExist(e) {
		return out, e
	}
	status, err := DisasterRuntime(data, id)
	if err != nil {
		return out, err
	}
	out = status.Restore
	if out.Stage != "runtime_confirmed" && out.Stage != "data_reconciling" && out.Stage != "data_reconciled" {
		return out, errors.New("恢复对账须先确认原 Nginx 应用，且不能已进入补偿")
	}
	if status.Nginx == nil || status.Nginx.State != "succeeded" {
		return out, errors.New("恢复对账缺少原 Nginx 成功记录")
	}
	writer, err := storage.LockWriterForRecovery(data, i.Rollback.Manifest.GID)
	if err != nil {
		return out, err
	}
	defer writer()
	fence, err := storage.ReadWriterFence(data)
	if err != nil || fence != i.Fence() {
		return out, errors.Join(err, errors.New("恢复对账缺少原写入屏障"))
	}
	if out.Stage == "runtime_confirmed" {
		// Once a fixed postimage is approved, a replay may find either side
		// of its atomic rename. InstallDisasterReconciled checks both hashes.
		if _, e := panelrecovery.ReadDisasterReconciliation(i); os.IsNotExist(e) {
			if err = panelrecovery.CheckDisasterTarget(ctx, i, true); err != nil {
				return out, err
			}
		} else if e != nil {
			return out, e
		}
	}
	if err = prepare(ctx, i); err != nil {
		return out, err
	}
	r, err := panelrecovery.ReadDisasterReconciliation(i)
	if err != nil {
		return out, err
	}
	if _, err = panelrecovery.ReadDisasterReconciliationProof(i, r); err != nil {
		return out, err
	}
	if err = checkDisasterRuntime(data, i); err != nil {
		return out, err
	}
	if out.Stage == "data_reconciled" {
		return out, panelrecovery.CheckDisasterTarget(ctx, i, true)
	}
	out.State, out.Stage, out.Error, out.MaintenanceEpoch = "recovery_required", "data_reconciling", "", epoch
	if _, err = validDisasterRestore(data, out); err != nil {
		return out, err
	}
	if err = j.Put(out); err != nil {
		return out, err
	}
	if err = panelrecovery.InstallDisasterReconciled(ctx, i); err != nil {
		out.Error = panelRestoreError(err)
		return out, errors.Join(err, j.Put(out))
	}
	out.Stage = "data_reconciled"
	return out, j.Put(out)
}
