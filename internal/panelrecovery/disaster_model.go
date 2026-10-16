package panelrecovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

// DisasterIntent separates portable material approval from the authenticated
// target snapshot. Neither receipt is rewritten to impersonate the other.
type DisasterIntent struct {
	Schema         int                 `json:"schema"`
	DataDir        string              `json:"data_dir"`
	OperationID    string              `json:"operation_id"`
	AdoptionSHA256 string              `json:"adoption_sha256"`
	PlanID         string              `json:"plan_id"`
	PlanSHA256     string              `json:"plan_sha256"`
	Stop           storage.ServiceHold `json:"stop"`
	Rollback       Receipt             `json:"rollback"`
	Files          []File              `json:"files"`
	Before         []Original          `json:"before"`
	ReleaseID      string              `json:"release_id"`
	BinarySHA256   string              `json:"binary_sha256"`
	ApprovalEpoch  string              `json:"approval_epoch"`
	CreatedAt      int64               `json:"created_at"`
	ExpiresAt      int64               `json:"expires_at"`
}

func (i DisasterIntent) Validate() error {
	if _, err := panelruntime.Root(i.DataDir); err != nil {
		return err
	}
	h := i.Stop
	if !idValue.MatchString(i.PlanID) || i.PlanID == i.OperationID || !hashValue.MatchString(i.PlanSHA256) {
		return errors.New("独立恢复缺少原目标计划批准摘要")
	}
	if i.Schema != 1 || !idValue.MatchString(i.OperationID) || !hashValue.MatchString(i.AdoptionSHA256) || !hashValue.MatchString(i.ReleaseID) || !hashValue.MatchString(i.BinarySHA256) || !idValue.MatchString(i.ApprovalEpoch) || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || i.ExpiresAt <= i.CreatedAt || i.ExpiresAt > i.Rollback.Manifest.ExpiresAt || i.ExpiresAt-i.CreatedAt > 24*60*60 || h.Schema != 1 || !idValue.MatchString(h.OperationID) || !idValue.MatchString(h.MaintenanceID) || !hashValue.MatchString(h.RequestSHA256) || !hashValue.MatchString(h.BindingSHA256) || h.ReleaseID != i.ReleaseID || h.OperationID == i.OperationID || h.MaintenanceID == i.OperationID {
		return errors.New("独立恢复安装意图无效")
	}
	if err := i.Rollback.Validate(i.DataDir, i.Rollback.Manifest.OperationID); err != nil {
		return err
	}
	m := i.Rollback.Manifest
	if m.OperationID == i.OperationID || m.MaintenanceID != h.MaintenanceID || m.CaptureBinarySHA256 != i.BinarySHA256 || m.CreatedAt > i.CreatedAt || len(i.Files) != len(resources) {
		return errors.New("独立恢复缺少匹配的目标回退依据")
	}
	for index, f := range i.Files {
		r := resources[index]
		if f.Name != r.name || f.Size < 1 || f.Size > r.limit || !hashValue.MatchString(f.SHA256) || index == 1 && f.Size != 32 {
			return errors.New("独立恢复材料清单无效")
		}
	}
	if err := ValidateOriginals(i.Before); err != nil {
		return err
	}
	if !i.Before[5].Present {
		return errors.New("独立恢复缺少目标原数据库依据")
	}
	for index, position := range []int{2, 3, 4} {
		before, snapshot := i.Before[position], m.Files[index+1]
		if !before.Present || before.Size != snapshot.Size || before.SHA256 != snapshot.SHA256 {
			return errors.New("独立恢复目标密钥或 TLS 与回退快照不一致")
		}
	}
	return nil
}

func (i DisasterIntent) SHA256() string { raw, _ := json.Marshal(i); return secure.Hash(raw) }
func (i DisasterIntent) Fence() storage.WriterFence {
	return storage.WriterFence{Schema: 1, OperationID: i.OperationID, SnapshotID: i.Rollback.Manifest.OperationID, MaintenanceID: i.Stop.MaintenanceID, RequestSHA256: i.SHA256()}
}

func disasterRoot(data string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("独立恢复存储仅供 root 使用")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return "", err
	}
	return filepath.Join(data, "agent", "disaster-restores"), nil
}
func disasterDirectory(data, id string) (string, error) {
	if !idValue.MatchString(id) {
		return "", errors.New("独立恢复标识无效")
	}
	root, err := disasterRoot(data)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, id), nil
}

func ReadDisasterIntent(data, id string) (out DisasterIntent, err error) {
	dir, err := disasterDirectory(data, id)
	if err != nil {
		return out, err
	}
	if err = checkPrivateDir(dir); err != nil {
		return out, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, "intent.json"), 32<<10)
	if err != nil {
		return out, err
	}
	if err = decode(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return out, errors.New("独立恢复意图不是原始规范记录")
	}
	if err = out.Validate(); err != nil {
		return out, err
	}
	if out.DataDir != data || out.OperationID != id {
		return out, errors.New("独立恢复意图身份不一致")
	}
	f, info, err := secure.OpenRootFile(filepath.Join(dir, "intent.json"), 32<<10)
	if err != nil {
		return out, err
	}
	f.Close()
	if info.Mode().Perm() != 0400 {
		return out, errors.New("独立恢复意图须为 root 只读")
	}
	return out, nil
}

// SaveDisasterIntent publishes approval before any fence or business mutation.
// Existing approval is compared exactly; no update or expiry extension exists.
func SaveDisasterIntent(i DisasterIntent) error {
	if err := i.Validate(); err != nil {
		return err
	}
	dir, err := disasterDirectory(i.DataDir, i.OperationID)
	if err != nil {
		return err
	}
	if previous, err := ReadDisasterIntent(i.DataDir, i.OperationID); err == nil {
		if previous.SHA256() != i.SHA256() {
			return errors.New("独立恢复标识已有不同安装意图")
		}
		return syncDir(dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	root := filepath.Dir(dir)
	if err = privateDir(root); err != nil {
		return err
	}
	if err = disasterBudget(root, dir, i); err != nil {
		return err
	}
	if err = privateDir(dir); err != nil {
		return err
	}
	items, err := disasterEntries(dir, 1)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Name() != "intent.copy" {
			return errors.New("独立恢复缺少批准但已有未知材料")
		}
	}
	scratch := filepath.Join(dir, "intent.copy")
	if _, err := os.Lstat(scratch); err == nil {
		f, info, e := secure.OpenRootFile(scratch, 32<<10)
		if e != nil {
			return e
		}
		f.Close()
		if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
			return errors.New("独立恢复意图暂存权限无效")
		}
		if e = os.Remove(scratch); e != nil {
			return e
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(i)
	if err != nil {
		return err
	}
	if err = writeFile(scratch, raw, 0400); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, scratch, unix.AT_FDCWD, filepath.Join(dir, "intent.json"), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}

func disasterBudget(root, current string, i DisasterIntent) error {
	entries, err := disasterEntries(root, SnapshotMax)
	if err != nil {
		return err
	}
	if len(entries) > SnapshotMax {
		return errors.New("独立恢复记录达到保留上限，须受控归档")
	}
	_, err = os.Lstat(current)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return err
	}
	if fresh && len(entries) >= SnapshotMax {
		return errors.New("独立恢复记录达到保留上限，须受控归档")
	}
	var used int64
	for _, entry := range entries {
		if !idValue.MatchString(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("独立恢复存储存在未知资源")
		}
		dir := filepath.Join(root, entry.Name())
		if err = checkPrivateDir(dir); err != nil {
			return err
		}
		items, e := disasterEntries(dir, 3)
		if e != nil {
			return e
		}
		for _, item := range items {
			name := filepath.Join(dir, item.Name())
			if item.Name() == "before" {
				if e = checkPrivateDir(name); e != nil {
					return e
				}
				files, e := disasterEntries(name, 12)
				if e != nil {
					return e
				}
				for _, file := range files {
					limit := int64(0)
					tmp := temporary(file.Name(), ".before-")
					for index, spec := range restoreFiles {
						if file.Name() == fmt.Sprintf("%02d", index) {
							limit = spec.limit
						}
					}
					if tmp {
						limit = DatabaseMax * 2
					}
					if limit == 0 {
						return errors.New("独立恢复原件目录存在未知文件")
					}
					f, info, e := secure.OpenRootFile(filepath.Join(name, file.Name()), limit)
					if e != nil {
						return e
					}
					f.Close()
					if info.Mode().Perm() != 0400 && (!tmp || info.Mode().Perm() != 0600) {
						return errors.New("独立恢复原件文件权限无效")
					}
					used += info.Size()
				}
			} else if item.Name() == "intent.json" || item.Name() == "intent.copy" {
				f, info, e := secure.OpenRootFile(name, 32<<10)
				if e != nil {
					return e
				}
				f.Close()
				used += info.Size()
			} else {
				return errors.New("独立恢复目录存在未知文件")
			}
		}
	}
	var need, copySpace int64
	for _, file := range i.Before {
		need += file.Size
		copySpace = max(copySpace, file.Size)
	}
	for _, file := range i.Files {
		copySpace = max(copySpace, file.Size)
	}
	if used+need+(1<<20) > StoreMax {
		return errors.New("独立恢复保留空间达到 2 GiB 上限，未删除原恢复依据")
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(root, &disk); err != nil {
		return err
	}
	if disk.Bsize <= 0 || disk.Bavail < uint64((need+copySpace+(128<<20)+int64(disk.Bsize)-1)/int64(disk.Bsize)) {
		return errors.New("独立恢复原件及安装暂存的磁盘余量不足")
	}
	return nil
}

func disasterEntries(dir string, limit int) ([]os.DirEntry, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	items, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(items) > limit {
		return nil, errors.New("独立恢复目录资源超过扫描预算")
	}
	return items, nil
}
