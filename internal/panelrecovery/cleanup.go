package panelrecovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/secure"
)

const cleanupEntryMax = 128

// AllRestores is reserved for explicit retirement of an expired snapshot after
// its original maintenance grant has been released. An update's own cleanup
// still validates against its single original restore UUID.
const AllRestores = "*"

// CleanupPlan is an immutable inventory, published by the owning root update
// before any unlink. It names only one approved snapshot and its own restore.
type CleanupPlan struct {
	SnapshotID    string         `json:"snapshot_id"`
	ReceiptSHA256 string         `json:"receipt_sha256"`
	RestoreID     string         `json:"restore_id"`
	CreatedAt     int64          `json:"created_at"`
	Entries       []CleanupEntry `json:"entries"`
	Bytes         int64          `json:"bytes"`
	SHA256        string         `json:"sha256"`
}

type CleanupEntry struct {
	Path       string `json:"path"`
	Directory  bool   `json:"directory"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	GID        uint32 `json:"gid"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	ModifiedAt int64  `json:"modified_at"`
	ChangedAt  int64  `json:"changed_at"`
}

func cleanupHash(p CleanupPlan) string {
	p.SHA256 = ""
	raw, _ := json.Marshal(p)
	return secure.Hash(raw)
}

func temporary(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) == 0 || len(suffix) > 20 {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func cleanupPath(name, restore string) (directory bool, limit int64, err error) {
	if name == "." {
		return true, 0, nil
	}
	if name == "snapshot.age" {
		return false, ArchiveMax, nil
	}
	if name == "receipt.json" {
		return false, manifestMax + 2048, nil
	}
	parts := strings.Split(name, "/")
	if restore == "" || parts[0] != "restores" {
		return false, 0, errors.New("清理清单包含原事务之外的资源")
	}
	if len(parts) == 1 {
		return true, 0, nil
	}
	if restore == AllRestores && !idValue.MatchString(parts[1]) || restore != AllRestores && parts[1] != restore {
		return false, 0, errors.New("清理清单包含其他恢复操作")
	}
	if len(parts) == 2 {
		return true, 0, nil
	}
	if parts[2] != "after" && parts[2] != "before" && !temporary(parts[2], ".after-") {
		return false, 0, errors.New("清理清单包含未知恢复目录")
	}
	if len(parts) == 3 {
		return true, 0, nil
	}
	if len(parts) != 4 {
		return false, 0, errors.New("清理清单目录层级无效")
	}
	leaf := parts[3]
	if parts[2] == "before" && temporary(leaf, ".before-") {
		return false, DatabaseMax * 2, nil
	}
	if parts[2] != "before" && leaf == "receipt.json" {
		return false, manifestMax + 2048, nil
	}
	index, e := strconv.Atoi(leaf)
	if e != nil || len(leaf) != 2 || fmt.Sprintf("%02d", index) != leaf || index < 0 {
		return false, 0, errors.New("清理清单恢复文件名无效")
	}
	if parts[2] == "before" && index < len(restoreFiles) {
		return false, restoreFiles[index].limit, nil
	}
	if parts[2] != "before" && index < len(resources) {
		return false, resources[index].limit, nil
	}
	return false, 0, errors.New("清理清单恢复文件索引无效")
}

func (p CleanupPlan) Validate(r Receipt, restore string) error {
	if err := r.Validate(r.Manifest.DataDir, r.Manifest.OperationID); err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	if restore != "" && restore != AllRestores && !idValue.MatchString(restore) || p.SnapshotID != r.Manifest.OperationID || p.RestoreID != restore || p.ReceiptSHA256 != secure.Hash(raw) || p.CreatedAt <= 0 || p.CreatedAt > time.Now().Unix()+300 || len(p.Entries) == 0 || len(p.Entries) > cleanupEntryMax || p.SHA256 != cleanupHash(p) {
		return errors.New("清理批准与原快照或恢复操作不一致")
	}
	var total int64
	seen := map[string]bool{}
	for i, e := range p.Entries {
		dir, limit, err := cleanupPath(e.Path, restore)
		if err != nil {
			return err
		}
		if e.Directory != dir || e.Device == 0 || e.Inode == 0 || seen[e.Path] || i == 0 && e.Path != "." || i > 0 && !seen[filepath.ToSlash(filepath.Dir(e.Path))] {
			return errors.New("清理资源身份、顺序或层级无效")
		}
		if dir {
			if e.Mode != 0700 || e.Size != 0 || e.SHA256 != "" || e.ModifiedAt != 0 || e.ChangedAt != 0 {
				return errors.New("清理目录元数据无效")
			}
		} else if e.Mode != 0400 && e.Mode != 0600 || e.Size < 0 || e.Size > limit || !hashValue.MatchString(e.SHA256) || e.ModifiedAt <= 0 || e.ChangedAt <= 0 {
			return errors.New("清理文件元数据无效")
		}
		seen[e.Path] = true
		total += e.Size
	}
	if !seen["snapshot.age"] || !seen["receipt.json"] || total != p.Bytes || total > 4*StoreMax {
		return errors.New("清理清单不完整或超出保留预算")
	}
	return nil
}

func cleanupEntry(name, relative string) (CleanupEntry, error) {
	e := CleanupEntry{Path: relative}
	info, err := os.Lstat(name)
	if err != nil {
		return e, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 {
		return e, errors.New("清理资源须为 root 原始资源")
	}
	e.Directory = info.IsDir()
	e.Device = uint64(st.Dev)
	e.Inode = st.Ino
	e.GID = st.Gid
	e.Mode = uint32(info.Mode().Perm())
	if e.Directory {
		if e.Mode != 0700 {
			return e, errors.New("清理目录权限无效")
		}
	} else {
		if !info.Mode().IsRegular() || st.Nlink != 1 || e.Mode != 0400 && e.Mode != 0600 {
			return e, errors.New("清理文件类型、链接或权限无效")
		}
		e.Size = info.Size()
		e.ModifiedAt = info.ModTime().UnixNano()
		e.ChangedAt = st.Ctim.Sec*1e9 + st.Ctim.Nsec
	}
	return e, nil
}

// LockCleanup serializes encrypted-store capture and cleanup. It does not hold
// business write admission or access the live application database.
func LockCleanup(data string) (func(), error) {
	store, err := root(data)
	if err != nil {
		return nil, err
	}
	if err = checkPrivateDir(store); err != nil {
		return nil, err
	}
	return captureLock(store)
}

func MaterialPresent(data, id string) (bool, error) {
	if !idValue.MatchString(id) {
		return false, errors.New("清理快照标识无效")
	}
	store, err := root(data)
	if err != nil {
		return false, err
	}
	if err = checkPrivateDir(store); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err == nil {
		if _, err = os.Lstat(filepath.Join(store, id)); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	parent := filepath.Dir(workspace(data, id))
	info, err := os.Lstat(parent)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm() != 0700 && info.Mode().Perm() != 0711 {
		return false, errors.New("快照助手父目录身份无效")
	}
	_, err = os.Lstat(workspace(data, id))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// PrepareCleanup authenticates the approved archive and inventories root-only
// recovery material. Caller holds the owning transaction locks and LockCleanup;
// AllRestores additionally requires explicit expired-snapshot retirement.
func PrepareCleanup(ctx context.Context, r Receipt, restore string) (CleanupPlan, error) {
	p := CleanupPlan{SnapshotID: r.Manifest.OperationID, RestoreID: restore, CreatedAt: time.Now().Unix()}
	if os.Geteuid() != 0 {
		return p, errors.New("恢复材料清理需要 root")
	}
	if err := r.Validate(r.Manifest.DataDir, r.Manifest.OperationID); err != nil {
		return p, err
	}
	stored, err := ReceiptFor(r.Manifest.DataDir, r.Manifest.OperationID)
	if err != nil {
		return p, err
	}
	raw, _ := json.Marshal(r)
	actual, _ := json.Marshal(stored)
	if string(raw) != string(actual) {
		return p, errors.New("待清理快照与原批准不同")
	}
	p.ReceiptSHA256 = secure.Hash(raw)
	if _, err = os.Lstat(workspace(r.Manifest.DataDir, r.Manifest.OperationID)); !errors.Is(err, os.ErrNotExist) {
		return p, errors.New("快照助手仍有未批准材料，须本机处理")
	}
	store, _ := root(r.Manifest.DataDir)
	base := filepath.Join(store, p.SnapshotID)
	err = filepath.WalkDir(base, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(p.Entries) >= cleanupEntryMax {
			return errors.New("清理资源超过数量预算")
		}
		relative, err := filepath.Rel(base, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		directory, limit, err := cleanupPath(relative, restore)
		if err != nil {
			return err
		}
		e, err := cleanupEntry(name, relative)
		if err != nil {
			return err
		}
		if directory != e.Directory {
			return errors.New("清理资源类型与固定目录布局不同")
		}
		if !directory {
			e.SHA256, e.Size, err = rootFileHash(ctx, name, limit, os.FileMode(e.Mode))
			if err != nil {
				return err
			}
			if relative == "snapshot.age" && (e.Size != r.ArchiveSize || e.SHA256 != r.ArchiveSHA256) {
				return errors.New("待清理归档与原批准不同")
			}
			if relative == "receipt.json" && e.SHA256 != p.ReceiptSHA256 {
				return errors.New("待清理批准记录内容不同")
			}
			p.Bytes += e.Size
			if p.Bytes > 4*StoreMax {
				return errors.New("清理资源超过容量预算")
			}
		}
		p.Entries = append(p.Entries, e)
		return nil
	})
	if err != nil {
		return p, err
	}
	p.SHA256 = cleanupHash(p)
	return p, p.Validate(r, restore)
}

// RemoveApproved is replayable only with the original durable inventory. Every
// surviving entry must match it, and directories are removed without recursion.
// Caller holds the owning transaction locks and LockCleanup throughout deletion.
func RemoveApproved(ctx context.Context, r Receipt, p CleanupPlan) error {
	if os.Geteuid() != 0 {
		return errors.New("恢复材料清理需要 root")
	}
	if err := p.Validate(r, p.RestoreID); err != nil {
		return err
	}
	store, _ := root(r.Manifest.DataDir)
	if err := checkPrivateDir(store); err != nil {
		return err
	}
	base := filepath.Join(store, p.SnapshotID)
	expected := make(map[string]CleanupEntry, len(p.Entries))
	for _, e := range p.Entries {
		expected[e.Path] = e
	}
	// Validate the entire remaining tree before deleting any further entry.
	err := filepath.WalkDir(base, func(name string, entry os.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) && name == base {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(base, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		original, ok := expected[relative]
		if !ok {
			return errors.New("清理期间出现未批准资源")
		}
		observed, err := cleanupEntry(name, relative)
		if err != nil {
			return err
		}
		observed.SHA256 = original.SHA256
		if observed != original {
			return errors.New("清理资源已偏离原批准")
		}
		if !observed.Directory {
			hash, n, err := rootFileHash(ctx, name, observed.Size, os.FileMode(observed.Mode))
			if err != nil {
				return err
			}
			if n != original.Size || hash != original.SHA256 {
				return errors.New("清理文件内容已变化")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	entries := append([]CleanupEntry(nil), p.Entries...)
	// Keep the top-level archive and receipt until all restore material is gone.
	rank := func(name string) int {
		switch name {
		case ".":
			return -3
		case "receipt.json":
			return -2
		case "snapshot.age":
			return -1
		default:
			return strings.Count(name, "/")
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := rank(entries[i].Path), rank(entries[j].Path)
		return a > b || a == b && entries[i].Path > entries[j].Path
	})
	for _, e := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		name := filepath.Join(base, filepath.FromSlash(e.Path))
		current, e2 := cleanupEntry(name, e.Path)
		if errors.Is(e2, os.ErrNotExist) {
			continue
		}
		if e2 != nil {
			return e2
		}
		current.SHA256 = e.SHA256
		if current != e {
			return errors.New("清理前资源身份已变化")
		}
		if err = os.Remove(name); err != nil {
			return err
		}
		if err = syncDir(filepath.Dir(name)); err != nil {
			return err
		}
	}
	return syncDir(store)
}
