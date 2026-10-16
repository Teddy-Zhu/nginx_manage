package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

// AdoptPreparation binds a fixed root copy to an operator-supplied preparation
// digest, the original stop and an authenticated target rollback snapshot. It
// retains independent maintenance admission but never installs business files.
func AdoptPreparation(ctx context.Context, data, id string, in AdoptInput) (out AdoptionStatus, err error) {
	if err = in.validate(id); err != nil {
		return out, err
	}
	unlock, root, err := lockAdoptionStore(data, true)
	if err != nil {
		return out, err
	}
	defer unlock()
	call, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	if _, e := os.Lstat(filepath.Join(root, ".cleaning-"+id)); e == nil {
		return out, errors.New("原恢复接入尚在清理，须继续原清理操作")
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if _, e := os.Lstat(filepath.Join(root, ".cleaned-"+id)); e == nil {
		return out, errors.New("原恢复材料已清理且历史回执保留，须使用新的恢复准备标识")
	} else if !os.IsNotExist(e) {
		return out, e
	}
	err = agent.WithCheckedPanelSnapshot(call, data, in.SnapshotID, in.MaintenanceID, in.Epoch, func(snapshot panelrecovery.Result) error {
		running, e := panelruntime.Read(data)
		if e != nil {
			return e
		}
		hold, e := storage.ReadServiceHold(data)
		if e != nil {
			return e
		}
		binding, e := json.Marshal(running.Deployment)
		if e != nil {
			return e
		}
		if hold.MaintenanceID != in.MaintenanceID || hold.ReleaseID != running.Release.ID || hold.BindingSHA256 != secure.Hash(binding) {
			return errors.New("恢复接入与当前原停机事务不一致")
		}
		unlockWriter, e := storage.LockWriterForMaintenance(data, running.Deployment.GID)
		if e != nil {
			return e
		}
		defer unlockWriter()
		final, _ := adoptionDirectory(data, id, false)
		work, _ := adoptionDirectory(data, id, true)
		if _, e = os.Lstat(final); e == nil {
			if _, e = os.Lstat(work); !os.IsNotExist(e) {
				return errors.New("恢复接入同时存在已批准和未结束目录")
			}
			result, e := readFinalAdoption(call, data, id, final)
			if e != nil {
				return e
			}
			i := result.Adoption.Intent
			if e = matchAdoptionInput(i, in, hold, running, snapshot.Receipt); e != nil {
				return e
			}
			actual, e := panelrecovery.ObserveTarget(call, i.Rollback)
			if e != nil {
				return e
			}
			if !sameAdoptionValue(actual, i.Before) {
				return errors.New("目标已偏离原接入前资源，禁止重用为安装授权")
			}
			out = result
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		var intent AdoptionIntent
		if _, e = os.Lstat(work); e == nil {
			if e = checkAdoptionWork(work); e != nil {
				return e
			}
			if e = readAdoptionJSON(filepath.Join(work, "intent.json"), &intent); e != nil {
				return e
			}
			if e = intent.Validate(data, id); e != nil {
				return e
			}
			if e = matchAdoptionInput(intent, in, hold, running, snapshot.Receipt); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		} else {
			if snapshot.Expired {
				return errors.New("目标回退快照已到期，禁止新接入")
			}
			result, e := QueryPreparation(call, data, id)
			if e != nil {
				return e
			}
			if result.Expired || result.SHA256 != in.PreparationSHA256 {
				return errors.New("恢复准备已过期或摘要与本次明确指定值不一致")
			}
			p := result.Preparation
			before, e := panelrecovery.ObserveTarget(call, snapshot.Receipt)
			if e != nil {
				return e
			}
			now := time.Now().Unix()
			intent = AdoptionIntent{Schema: 1, DataDir: data, PreparationSHA256: result.SHA256, Preparation: p, Stop: hold, Rollback: snapshot.Receipt, Before: before, UID: running.Deployment.UID, GID: running.Deployment.GID, BinarySHA256: running.Release.BinarySHA256, ApprovalEpoch: in.Epoch, CreatedAt: now, ExpiresAt: min(now+AdoptionLifetime, snapshot.Receipt.Manifest.ExpiresAt)}
			if e = intent.Validate(data, id); e != nil {
				return e
			}
			if e = matchAdoptionInput(intent, in, hold, running, snapshot.Receipt); e != nil {
				return e
			}
			if e = adoptionBudget(root); e != nil {
				return e
			}
			if e = os.Mkdir(work, 0700); e != nil {
				return e
			}
			if e = syncDir(root); e != nil {
				return e
			}
			if e = writeAdoptionJSON(filepath.Join(work, "intent.json"), intent); e != nil {
				return e
			}
		}
		if intent.ExpiresAt <= time.Now().Unix() {
			return errors.New("恢复接入意图已到期，材料保留供查询或原事务清理")
		}
		before, e := panelrecovery.ObserveTarget(call, intent.Rollback)
		if e != nil {
			return e
		}
		if !sameAdoptionValue(before, intent.Before) {
			return errors.New("当前目标已偏离原接入前资源，拒绝继续")
		}
		for index := range resources {
			if e = copyAdoptionFile(call, data, work, intent, index); e != nil {
				return e
			}
		}
		for _, name := range []string{".copy", ".json-copy"} {
			if e = os.Remove(filepath.Join(work, name)); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		var adopted Adoption
		if e = readAdoptionJSON(filepath.Join(work, "adoption.json"), &adopted); e == nil {
			if e = adopted.Validate(data, id); e != nil {
				return e
			}
			if !sameAdoptionValue(adopted.Intent, intent) {
				return errors.New("恢复接入批准记录与原意图不一致")
			}
		} else if !os.IsNotExist(e) {
			return e
		} else {
			verification, e := verifyAdoptionMaterial(call, data, id, work, intent)
			if e != nil {
				return e
			}
			adopted = Adoption{Intent: intent, Verification: verification, Epoch: in.Epoch}
			adopted.SHA256, e = adoptionHash(adopted)
			if e != nil {
				return e
			}
			if e = adopted.Validate(data, id); e != nil {
				return e
			}
			if e = writeAdoptionJSON(filepath.Join(work, "adoption.json"), adopted); e != nil {
				return e
			}
		}
		// No target writer or maintenance release may interleave with this final
		// source/target identity check and immutable publication.
		after, e := panelrecovery.ObserveTarget(call, intent.Rollback)
		if e != nil {
			return e
		}
		if !sameAdoptionValue(after, intent.Before) {
			return errors.New("目标资源在恢复接入期间变化，保留材料并停止")
		}
		current, e := panelruntime.Read(data)
		if e != nil {
			return e
		}
		currentHold, e := storage.ReadServiceHold(data)
		if e != nil {
			return e
		}
		if currentHold != hold || !sameAdoptionValue(current, running) {
			return errors.New("恢复接入期间停机或批准程序发生变化")
		}
		if e = checkAdoptionWork(work); e != nil {
			return e
		}
		if e = syncDir(work); e != nil {
			return e
		}
		if e = unix.Renameat2(unix.AT_FDCWD, work, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE); e != nil {
			return e
		}
		if e = syncDir(root); e != nil {
			return e
		}
		out = AdoptionStatus{State: "adopted", Adoption: &adopted, Expired: adopted.Intent.ExpiresAt <= time.Now().Unix()}
		return nil
	})
	return out, err
}

func matchAdoptionInput(i AdoptionIntent, in AdoptInput, hold storage.ServiceHold, running panelruntime.Snapshot, rollback panelrecovery.Receipt) error {
	p := i.Preparation
	if p.Source.ApplicationVersion != running.Release.Version || p.Source.Database.SchemaVersion != running.Release.DatabaseSchema || p.Source.AgentProtocol != running.Release.AgentProtocol || p.Source.ParserVersion != nginxconfig.ParserVersion || p.Source.PolicyVersion != nginxconfig.PolicyVersion {
		return errors.New("恢复接入的源格式与当前批准程序不匹配")
	}
	if i.PreparationSHA256 != in.PreparationSHA256 || i.Rollback.Manifest.OperationID != in.SnapshotID || p.MaintenanceID != in.MaintenanceID || i.Stop != hold || p.Target.ReleaseID != running.Release.ID || p.Target.Runtime != running.Deployment.Mode || i.BinarySHA256 != running.Release.BinarySHA256 || i.UID != running.Deployment.UID || i.GID != running.Deployment.GID || !sameAdoptionValue(i.Rollback, rollback) {
		return errors.New("恢复接入标识已有不同的准备、回退、目标或原停机依据")
	}
	return nil
}
func sameAdoptionValue(a, b any) bool {
	first, err := json.Marshal(a)
	if err != nil {
		return false
	}
	second, err := json.Marshal(b)
	return err == nil && bytes.Equal(first, second)
}
func verifyAdoptionMaterial(ctx context.Context, data, id, dir string, intent AdoptionIntent) (out MaterialVerification, err error) {
	if err = callAdoptionMaterialHelper(ctx, data, id, dir, intent, "backup-adoption-verify-data", intent.Preparation, &out); err != nil {
		return out, err
	}
	expected, err := preparationHash(intent.Preparation)
	if err != nil {
		return out, err
	}
	if out.OperationID != id || out.PreparationSHA256 != expected || out.Database != intent.Preparation.Database || out.VerifiedAt < intent.Preparation.PreparedAt || out.VerifiedAt > time.Now().Unix()+300 {
		return out, errors.New("恢复接入助手核对了不同材料")
	}
	return out, nil
}

func callAdoptionMaterialHelper(ctx context.Context, data, id, dir string, intent AdoptionIntent, command string, input, out any) (err error) {
	defer func() { err = errors.Join(err, cleanupAdoptionCheck(data, id, intent.GID)) }()
	if err = prepareAdoptionCheck(ctx, data, id, filepath.Join(dir, "panel.db"), intent); err != nil {
		return err
	}
	var files []*os.File
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	for i, r := range resources {
		f, info, e := secure.OpenRootFile(filepath.Join(dir, r.local), r.limit)
		if e != nil {
			return e
		}
		files = append(files, f)
		if info.Mode().Perm() != 0400 || info.Size() != intent.Preparation.Files[i].Size {
			return errors.New("恢复接入资源尚未全部固定")
		}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return runPreparationHelper(ctx, data, command, id, raw, files, out)
}
