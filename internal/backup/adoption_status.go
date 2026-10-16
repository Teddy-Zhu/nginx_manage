package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

func readFinalAdoption(ctx context.Context, data, id, dir string) (out AdoptionStatus, err error) {
	items, _, err := adoptionEntries(dir)
	if err != nil {
		return out, err
	}
	if len(items) != 6 {
		return out, errors.New("已接入恢复目录包含不完整或额外资源")
	}
	var adopted Adoption
	if err = readAdoptionJSON(filepath.Join(dir, "adoption.json"), &adopted); err != nil {
		return out, err
	}
	if err = adopted.Validate(data, id); err != nil {
		return out, err
	}
	var intent AdoptionIntent
	if err = readAdoptionJSON(filepath.Join(dir, "intent.json"), &intent); err != nil {
		return out, err
	}
	if !sameAdoptionValue(intent, adopted.Intent) {
		return out, errors.New("恢复接入原意图与批准记录不一致")
	}
	for index, r := range resources {
		if err = hashAdoptionFile(ctx, filepath.Join(dir, r.local), adopted.Intent.Preparation.Files[index]); err != nil {
			return out, err
		}
	}
	return AdoptionStatus{State: "adopted", Adoption: &adopted, Expired: adopted.Intent.ExpiresAt <= time.Now().Unix()}, nil
}
func readAdoptionStatus(ctx context.Context, data, id string) (out AdoptionStatus, err error) {
	final, err := adoptionDirectory(data, id, false)
	if err != nil {
		return out, err
	}
	root := filepath.Dir(final)
	paths := []string{final, filepath.Join(root, ".adopting-"+id), filepath.Join(root, ".cleaning-"+id), filepath.Join(root, ".cleaned-"+id)}
	found := -1
	for index, path := range paths {
		if _, e := os.Lstat(path); e == nil {
			if found != -1 {
				return out, errors.New("恢复接入存在冲突阶段目录")
			}
			found = index
		} else if !os.IsNotExist(e) {
			return out, e
		}
	}
	switch found {
	case -1:
		return AdoptionStatus{State: "absent"}, nil
	case 0:
		return readFinalAdoption(ctx, data, id, paths[0])
	case 2:
		return readAdoptionHistory(data, id, paths[2], false)
	case 3:
		return readAdoptionHistory(data, id, paths[3], true)
	}
	partial := paths[1]
	items, _, err := adoptionEntries(partial)
	if err != nil {
		return out, err
	}
	for _, item := range items {
		if item.Name() == "cleanup.json" || item.Name() == "cleaned.json" {
			return out, errors.New("恢复接入意图目录混入清理记录")
		}
	}
	var intent AdoptionIntent
	if err = readAdoptionJSON(filepath.Join(partial, "intent.json"), &intent); os.IsNotExist(err) {
		for _, item := range items {
			if item.Name() != ".json-copy" {
				return out, errors.New("恢复接入存在资源但缺少原持久意图")
			}
		}
		return AdoptionStatus{State: "intent_incomplete"}, nil
	} else if err != nil {
		return out, err
	}
	if err = intent.Validate(data, id); err != nil {
		return out, err
	}
	return AdoptionStatus{State: "copying", Intent: &intent, Expired: intent.ExpiresAt <= time.Now().Unix()}, nil
}

// QueryAdoption reads root receipts and hashes fixed files; it never opens
// SQLite as root, renews authorization or claims the target has been installed.
func QueryAdoption(ctx context.Context, data, id string) (AdoptionStatus, error) {
	if !validID.MatchString(id) {
		return AdoptionStatus{}, errors.New("恢复接入操作标识无效")
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return AdoptionStatus{}, err
	}
	defer unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return readAdoptionStatus(call, data, id)
}

// CleanupAdoption removes only uninstalled copies under the matching original
// stop. Approval/cleanup receipts, rollback snapshots, startup fences and all
// Agent history are retained.
func CleanupAdoption(ctx context.Context, data, id string) error {
	if !validID.MatchString(id) {
		return errors.New("恢复接入操作标识无效")
	}
	unlock, root, err := lockAdoptionStore(data, false)
	if err != nil {
		return err
	}
	defer unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	status, err := readAdoptionStatus(call, data, id)
	if err != nil {
		return err
	}
	if status.State == "absent" || status.State == "cleaned" {
		return syncDir(root)
	}
	if err = adoptionRestoreSettled(data, id); err != nil {
		return err
	}
	running, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	hold, err := storage.ReadServiceHold(data)
	if err != nil {
		return err
	}
	unlockWriter, err := storage.LockWriterForMaintenance(data, running.Deployment.GID)
	if err != nil {
		return err
	}
	defer unlockWriter()
	intent := status.Intent
	if status.Adoption != nil {
		intent = &status.Adoption.Intent
	}
	if intent != nil && intent.Stop != hold || status.Cleanup != nil && status.Cleanup.Stop != hold {
		return errors.New("恢复接入清理须保持原停机事务，不能清理其他恢复依据")
	}
	gid := running.Deployment.GID
	if intent != nil {
		gid = intent.GID
	}
	if err = cleanupAdoptionCheck(data, id, gid); err != nil {
		return err
	}
	dir, _ := adoptionDirectory(data, id, status.State != "adopted")
	cleaning := filepath.Join(root, ".cleaning-"+id)
	if status.State == "cleaning" {
		dir = cleaning
	} else {
		if err = unix.Renameat2(unix.AT_FDCWD, dir, unix.AT_FDCWD, cleaning, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = syncDir(root); err != nil {
			return err
		}
		dir = cleaning
	}
	cleanup := status.Cleanup
	if cleanup == nil {
		record := AdoptionCleanup{Schema: 1, DataDir: data, OperationID: id, Stop: hold, StartedAt: time.Now().Unix()}
		if intent != nil {
			record.IntentSHA256, err = adoptionValueHash(*intent)
			if err != nil {
				return err
			}
		}
		var adopted Adoption
		if err = readAdoptionJSON(filepath.Join(dir, "adoption.json"), &adopted); err == nil {
			if err = adopted.Validate(data, id); err != nil {
				return err
			}
			if intent == nil || !sameAdoptionValue(adopted.Intent, *intent) {
				return errors.New("恢复接入清理存在不同批准记录")
			}
			record.AdoptionSHA256 = adopted.SHA256
		} else if !os.IsNotExist(err) {
			return err
		}
		if err = writeAdoptionJSON(filepath.Join(dir, "cleanup.json"), record); err != nil {
			return err
		}
		cleanup = &record
	}
	items, _, err := adoptionEntries(dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		switch item.Name() {
		case "intent.json", "adoption.json", "cleanup.json", "cleaned.json":
			continue
		}
		if err = call.Err(); err != nil {
			return err
		}
		if err = os.Remove(filepath.Join(dir, item.Name())); err != nil {
			return err
		}
		if err = syncDir(dir); err != nil {
			return err
		}
	}
	if _, e := os.Lstat(filepath.Join(dir, "cleaned.json")); os.IsNotExist(e) {
		hash, e := adoptionValueHash(*cleanup)
		if e != nil {
			return e
		}
		if e = writeAdoptionJSON(filepath.Join(dir, "cleaned.json"), adoptionCleaned{CleanupSHA256: hash, CompletedAt: time.Now().Unix()}); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if _, err = readAdoptionHistory(data, id, dir, true); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, dir, unix.AT_FDCWD, filepath.Join(root, ".cleaned-"+id), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(root)
}
