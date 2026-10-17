package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

const disasterRestoreKind = "backup.restore"

func validDisasterRestore(data string, r Record) (panelrecovery.DisasterIntent, error) {
	i, err := panelrecovery.ReadDisasterIntent(data, r.OperationID)
	if os.IsNotExist(err) {
		return i, errors.New("独立灾备执行记录引用的原安装意图已缺失")
	}
	if err != nil {
		return i, err
	}
	if r.DisasterRestoreID != "" || r.Kind != disasterRestoreKind || !validID(r.MaintenanceEpoch) || r.RequestHash != i.SHA256() || r.CandidateHash != i.AdoptionSHA256 || r.RestoreSnapshot != i.Rollback.Manifest.OperationID || r.Deadline != i.ExpiresAt || r.PanelRestore != nil || r.PanelUpdate != nil || r.PanelSelection != nil || r.PanelService != nil || r.NginxInstall != nil || r.NginxSwitch != nil || r.NginxSwitchJob != nil || r.RemoteListener != nil || r.LogPolicy != nil {
		return i, errors.New("独立灾备恢复记录与原批准不一致")
	}
	if r.DisasterActivation != nil || strings.HasPrefix(r.Stage, "activation_") || r.Stage == "committed" {
		return i, validDisasterActivation(i, r)
	}
	switch r.Stage {
	case "preparing", "installing", "compensating":
		if r.State != "running" && r.State != "recovery_required" {
			return i, errors.New("独立灾备恢复执行状态无效")
		}
	case "files_installed", "runtime_preparing", "runtime_applying", "runtime_confirmed", "data_reconciling", "data_reconciled", "runtime_compensating", "runtime_compensated":
		if r.State != "recovery_required" {
			return i, errors.New("灾备文件安装不能宣告完整恢复成功")
		}
		if strings.HasPrefix(r.Stage, "data_") {
			reconciled, e := panelrecovery.ReadDisasterReconciliation(i)
			if e != nil {
				return i, e
			}
			if _, e = panelrecovery.ReadDisasterReconciliationProof(i, reconciled); e != nil {
				return i, e
			}
		}
	case "files_compensated":
		if r.State != "rolled_back" {
			return i, errors.New("独立灾备恢复补偿状态无效")
		}
	default:
		return i, errors.New("独立灾备恢复阶段无效")
	}
	return i, nil
}

func readDisasterRestore(data, id string) (Record, error) {
	var r Record
	if os.Geteuid() != 0 || !validID(id) {
		return r, errors.New("独立灾备恢复查询需要 root 和原操作标识")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return r, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), 64<<10)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || string(raw) != string(canonical) || r.OperationID != id {
		return r, errors.New("独立灾备恢复记录不是原始规范记录")
	}
	_, err = validDisasterRestore(data, r)
	return r, err
}

// DisasterRestoreStatus reports durable transaction evidence, not a fresh
// observation of the application. The business database is not opened here.
func DisasterRestoreStatus(data, id string) (Record, error) { return readDisasterRestore(data, id) }

func sameDisasterApproval(a, b panelrecovery.DisasterIntent) bool {
	a.CreatedAt, b.CreatedAt = 0, 0
	a.ApprovalEpoch, b.ApprovalEpoch = "", ""
	return a.SHA256() == b.SHA256()
}

func checkDisasterRuntime(data string, i panelrecovery.DisasterIntent) error {
	if err := checkDisasterProgram(data, i); err != nil {
		return err
	}
	hold, err := storage.ReadServiceHold(data)
	if err != nil {
		return err
	}
	if hold != i.Stop {
		return errors.New("原恢复停机标记已变化")
	}
	return nil
}

func checkDisasterProgram(data string, i panelrecovery.DisasterIntent) error {
	running, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	live, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	expected, err := os.Stat(filepath.Join(running.Directory, "nginxpanel"))
	if err != nil {
		return err
	}
	if !os.SameFile(live, expected) {
		return errors.New("独立灾备恢复须使用当前批准的面板执行文件")
	}
	binding, err := json.Marshal(running.Deployment)
	if err != nil {
		return err
	}
	if i.Stop.BindingSHA256 != secure.Hash(binding) || running.Release.ID != i.ReleaseID || running.Release.BinarySHA256 != i.BinarySHA256 || running.Deployment.UID != i.Rollback.Manifest.UID || running.Deployment.GID != i.Rollback.Manifest.GID {
		return errors.New("独立灾备恢复与原停机、批准程序或目标账户不一致")
	}
	uid, gid, err := panelSnapshotIdentity(data)
	if err != nil {
		return err
	}
	if uid != i.Rollback.Manifest.UID || gid != i.Rollback.Manifest.GID {
		return errors.New("独立灾备恢复目标账户已变化")
	}
	return nil
}

// RestoreDisaster is a local root coordinator only. It retains maintenance
// admission and a startup fence across file installation and compensation; it
// never starts serve, changes the selected program or clears a restore barrier.
func RestoreDisaster(ctx context.Context, data, id, epoch string, input panelrecovery.DisasterIntent, rollback bool) (out Record, err error) {
	if os.Geteuid() != 0 || !validID(id) || !validID(epoch) || input.OperationID != id || input.DataDir != data {
		return out, errors.New("独立灾备恢复须提供原操作和当前维护授权")
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	if _, err = panelruntime.Root(data); err != nil {
		return out, err
	}
	unlock, err := j.waitRootLock(call, ".disaster-restore.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	access, err := j.waitRootLock(call, ".maintenance-access.lock")
	if err != nil {
		return out, err
	}
	defer access()
	if err = installGrant(j, input.Stop.MaintenanceID, epoch, true); err != nil {
		return out, err
	}
	out, err = readDisasterRestore(data, id)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return out, err
	}
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err == nil {
		if !sameDisasterApproval(i, input) {
			return out, errors.New("原灾备恢复标识已有不同材料或目标依据")
		}
	} else if !os.IsNotExist(err) {
		return out, err
	} else {
		if !fresh || rollback {
			return out, errors.New("独立灾备恢复缺少原安装意图，不能重建批准")
		}
		i = input
		i.CreatedAt = time.Now().Unix()
		i.ApprovalEpoch = epoch
	}
	if err = i.Validate(); err != nil {
		return out, err
	}
	if _, e := panelrecovery.ReadDisasterRuntimeApproval(i, true); e == nil {
		if !rollback {
			return out, errors.New("原恢复已持久批准补偿，禁止继续安装")
		}
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if disasterActivationCommitted(out) {
		return out, errors.New("恢复已提交激活，只能续办原激活，不能重新安装或补偿")
	}
	if err = checkDisasterRuntime(data, i); err != nil {
		return out, err
	}
	if err = checkDisasterRecords(j, i, !fresh); err != nil {
		return out, err
	}
	unlockWriter, err := storage.LockWriterForRecovery(data, i.Rollback.Manifest.GID)
	if err != nil {
		return out, err
	}
	defer unlockWriter()
	if err = checkDisasterRuntime(data, i); err != nil {
		return out, err
	}
	if fresh {
		fenced, e := storage.WriterFenced(data)
		if e != nil {
			return out, e
		}
		if fenced {
			return out, errors.New("恢复屏障存在但独立执行记录缺失，禁止重建事务")
		}
		if !rollback && i.ExpiresAt <= time.Now().Unix() {
			return out, errors.New("原接入批准已到期，不能新建安装事务")
		}
		if err = panelrecovery.CheckDisasterTarget(call, i, false); err != nil {
			return out, err
		}
		if !rollback {
			if err = panelrecovery.CheckDisasterMaterial(call, i); err != nil {
				return out, err
			}
			snapshot, e := panelrecovery.Inspect(call, data, i.Rollback.Manifest.OperationID)
			if e != nil {
				return out, e
			}
			a, _ := json.Marshal(snapshot.Receipt)
			b, _ := json.Marshal(i.Rollback)
			if snapshot.Expired || string(a) != string(b) {
				return out, errors.New("目标回退快照与原接入批准不一致或已到期")
			}
		}
		if err = panelrecovery.SaveDisasterIntent(i); err != nil {
			return out, err
		}
		out = Record{OperationID: id, Kind: disasterRestoreKind, State: "running", Stage: "preparing", MaintenanceEpoch: epoch, RequestHash: i.SHA256(), CandidateHash: i.AdoptionSHA256, RestoreSnapshot: i.Rollback.Manifest.OperationID, Deadline: i.ExpiresAt}
		if err = j.Put(out); err != nil {
			return out, err
		}
	}
	if out.Stage == "files_compensated" {
		// A terminal replay may finish unlinking its own fence, but cannot
		// reinstall after the original data has become writable again.
		fenced, e := storage.WriterFenced(data)
		if e != nil {
			return out, e
		}
		if fenced {
			if e = panelrecovery.CheckDisasterTarget(call, i, false); e != nil {
				return out, e
			}
		}
		return out, storage.ClearWriterFence(data, i.Fence())
	}
	if (out.Stage == "compensating" || strings.HasPrefix(out.Stage, "runtime_compensat")) && !rollback {
		return out, errors.New("原恢复已进入补偿，只能继续原补偿")
	}
	if rollback && (strings.HasPrefix(out.Stage, "runtime_") || strings.HasPrefix(out.Stage, "data_")) && out.Stage != "runtime_compensated" {
		return out, errors.New("须先完成原 Nginx 运行补偿，再恢复目标原文件")
	}
	if rollback {
		child, e := readDisasterNginx(data, i)
		if e == nil && child.State != "rolled_back" {
			return out, errors.New("Nginx 子操作尚未确认补偿，不能恢复原文件")
		}
		if e != nil && !os.IsNotExist(e) {
			return out, e
		}
	}
	if err = storage.BindWriterFence(data, i.Fence()); err != nil {
		return out, err
	}
	save := func() error {
		if _, e := validDisasterRestore(data, out); e != nil {
			return e
		}
		return j.Put(out)
	}
	out.MaintenanceEpoch = epoch
	if err = runDisasterFiles(call, i, &out, rollback, save); err != nil {
		out.State, out.Error = "recovery_required", panelRestoreError(err)
		return out, errors.Join(err, save())
	}
	if out.Stage == "files_compensated" {
		return out, storage.ClearWriterFence(data, i.Fence())
	}
	return out, nil
}

func runDisasterFiles(ctx context.Context, i panelrecovery.DisasterIntent, r *Record, rollback bool, save func() error) error {
	if rollback && r.Stage == "preparing" {
		if err := panelrecovery.CheckDisasterTarget(ctx, i, false); err != nil {
			return err
		}
		return finishDisasterCompensation(r, save)
	}
	if rollback {
		r.State, r.Stage, r.Error = "running", "compensating", ""
		if err := save(); err != nil {
			return err
		}
		if err := panelrecovery.InstallDisaster(ctx, i, true); err != nil {
			return err
		}
		return finishDisasterCompensation(r, save)
	}
	if r.Stage == "files_installed" || strings.HasPrefix(r.Stage, "runtime_") || strings.HasPrefix(r.Stage, "data_") {
		return panelrecovery.CheckDisasterTarget(ctx, i, true)
	}
	if i.ExpiresAt <= time.Now().Unix() {
		return errors.New("灾备安装批准已到期，材料和屏障保留，可继续原补偿")
	}
	r.State, r.Error = "running", ""
	if err := save(); err != nil {
		return err
	}
	if r.Stage == "preparing" {
		if err := panelrecovery.CheckDisasterMaterial(ctx, i); err != nil {
			return err
		}
		if err := panelrecovery.PreserveDisasterOriginals(ctx, i); err != nil {
			return err
		}
		r.Stage = "installing"
		if err := save(); err != nil {
			return err
		}
	}
	if err := panelrecovery.InstallDisaster(ctx, i, false); err != nil {
		return err
	}
	r.State, r.Stage, r.Error = "recovery_required", "files_installed", ""
	return save()
}

func finishDisasterCompensation(r *Record, save func() error) error {
	stage := r.Stage
	r.State, r.Stage, r.Error = "rolled_back", "files_compensated", ""
	if err := save(); err != nil {
		r.Stage = stage
		return err
	}
	return nil
}
