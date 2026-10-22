package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

const recoveryHistoryDir = ".history"
const recoveryHistoryKeep = 32
const recoveryHistoryBatch = 32
const recoveryHistoryShardCount = 64
const recoveryHistoryShardBytes = 1 << 20

type recoveryHistoryKind string

const (
	recoveryAdoptionHistory recoveryHistoryKind = "adoption"
	recoveryPublicationHistory recoveryHistoryKind = "publication"
	recoveryPlanHistory recoveryHistoryKind = "plan"
)

// All callers hold the adoption store lock. New admission also holds the root
// maintenance lock, so retiring metadata cannot race an independent restore.
// Entire original files/directories move; archives never authorize new work.
func recoveryHistoryName(kind recoveryHistoryKind, id string) string {
	if kind == recoveryPlanHistory {
		return id + ".json"
	}
	return ".cleaned-" + id
}

func recoveryHistoryPath(root string, kind recoveryHistoryKind, id string) (string, bool, error) {
	if !validID.MatchString(id) {
		return "", false, errors.New("恢复历史标识无效")
	}
	archive := filepath.Join(root, recoveryHistoryDir)
	shard := filepath.Join(archive, id[:2])
	path := filepath.Join(shard, recoveryHistoryName(kind, id))
	for _, dir := range []string{root, archive, shard} {
		if err := privateAdoptionDirectory(dir, false); os.IsNotExist(err) {
			return path, false, nil
		} else if err != nil {
			return "", false, err
		}
	}
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return path, false, nil
	}
	return path, err == nil, err
}

func recoveryLiveEntries(root string, limit int) ([]os.DirEntry, error) {
	items, err := boundedEntries(root, limit+1)
	if err != nil {
		return nil, err
	}
	out := make([]os.DirEntry, 0, len(items))
	for _, item := range items {
		if item.Name() == recoveryHistoryDir {
			if err := privateAdoptionDirectory(filepath.Join(root, item.Name()), false); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, item)
	}
	if len(out) > limit {
		return nil, errors.New("恢复历史热区超出扫描预算")
	}
	return out, nil
}

// Complete a rename's directory durability before admitting unrelated new work,
// including when an earlier process stopped after the move but before fsync.
func syncRecoveryHistory(root string) error {
	archive := filepath.Join(root, recoveryHistoryDir)
	if err := privateAdoptionDirectory(archive, false); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	items, err := boundedEntries(archive, 256)
	if err != nil {
		return err
	}
	for _, item := range items {
		if len(item.Name()) != 2 || strings.Trim(item.Name(), "0123456789abcdef") != "" {
			return errors.New("恢复历史归档包含未知分片")
		}
		shard := filepath.Join(archive, item.Name())
		if err = privateAdoptionDirectory(shard, false); err != nil {
			return err
		}
		if err = syncDir(shard); err != nil {
			return err
		}
	}
	return errors.Join(syncDir(archive), syncDir(root))
}

func recoveryHistorySettled(data, id string) (bool, error) {
	if _, err := panelrecovery.ReadDisasterIntent(data, id); os.IsNotExist(err) {
		if _, err := os.Lstat(filepath.Join(data, "agent", "operations", id+".json")); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
		_, err = (&agent.Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	} else if err != nil {
		return false, err
	}
	r, err := agent.DisasterRestoreStatus(data, id)
	if err != nil {
		return false, err
	}
	return r.State == "succeeded" && r.Stage == "committed" && r.DisasterActivation != nil && r.DisasterActivation.ReleaseAcknowledged || r.State == "rolled_back" && r.Stage == "files_compensated", nil
}

type recoveryHistoryCandidate struct {
	id, name string
	at int64
}

func recoveryPublicationHistoryPath(data, id string) (string, bool, error) {
	root := restorePublicationRoot(data)
	cold, archived, err := recoveryHistoryPath(root, recoveryPublicationHistory, id)
	if err != nil {
		return "", false, err
	}
	paths := []string{filepath.Join(root, id), filepath.Join(root, ".cleaning-"+id), filepath.Join(root, ".cleaned-"+id)}
	if archived {
		paths = append(paths, cold)
	}
	found := -1
	for index, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			if found != -1 {
				return "", false, errors.New("恢复发布副本同时存在冲突阶段或归档记录")
			}
			found = index
		} else if !os.IsNotExist(err) {
			return "", false, err
		}
	}
	if found == -1 {
		return "", false, nil
	}
	return paths[found], found >= 2, nil
}

func recoveryHistoryCandidateFor(data, root string, kind recoveryHistoryKind, name string) (*recoveryHistoryCandidate, error) {
	var id string
	var at int64
	switch kind {
	case recoveryAdoptionHistory:
		if !strings.HasPrefix(name, ".cleaned-") {
			return nil, nil
		}
		id = strings.TrimPrefix(name, ".cleaned-")
		if !validID.MatchString(id) {
			return nil, errors.New("恢复接入历史名称无效")
		}
		dir := filepath.Join(root, name)
		if _, err := readAdoptionHistory(data, id, dir, true); err != nil {
			return nil, err
		}
		var done adoptionCleaned
		if err := readAdoptionJSON(filepath.Join(dir, "cleaned.json"), &done); err != nil {
			return nil, err
		}
		at = done.CompletedAt
	case recoveryPublicationHistory:
		if !strings.HasPrefix(name, ".cleaned-") {
			return nil, nil
		}
		id = strings.TrimPrefix(name, ".cleaned-")
		if !validID.MatchString(id) {
			return nil, errors.New("恢复发布历史名称无效")
		}
		var receipt restorationPublicationReceipt
		if err := readAdoptionJSON(filepath.Join(root, name, "publication.json"), &receipt); err != nil {
			return nil, err
		}
		if receipt.Publication.RevisionID != id || !validID.MatchString(receipt.OperationID) || !validHash.MatchString(receipt.PreparationSHA256) {
			return nil, errors.New("恢复发布历史身份无效")
		}
		settled, err := recoveryHistorySettled(data, receipt.OperationID)
		if err != nil || !settled {
			return nil, err
		}
		at = receipt.Publication.CreatedAt
	case recoveryPlanHistory:
		if !strings.HasSuffix(name, ".json") || !validID.MatchString(strings.TrimSuffix(name, ".json")) {
			return nil, nil
		}
		id = strings.TrimSuffix(name, ".json")
		p, err := readRestorePlan(data, id)
		if err != nil {
			return nil, err
		}
		if p.ExpiresAt > time.Now().Unix() {
			return nil, nil
		}
		settled, err := recoveryHistorySettled(data, p.OperationID)
		if err != nil || !settled {
			return nil, err
		}
		publication, cleaned, err := recoveryPublicationHistoryPath(data, id)
		if err != nil {
			return nil, err
		}
		if publication != "" && !cleaned || p.Preview.Publication != nil && !cleaned {
			return nil, nil
		}
		if cleaned {
			files, _, err := publicationEntries(publication)
			if err != nil || len(files) != 1 || files[0].Name() != "publication.json" {
				return nil, errors.Join(err, errors.New("恢复计划的发布副本尚未完整清理"))
			}
			var receipt restorationPublicationReceipt
			if err = readAdoptionJSON(filepath.Join(publication, "publication.json"), &receipt); err != nil {
				return nil, err
			}
			if receipt.OperationID != p.OperationID || receipt.PreparationSHA256 != p.PreparationSHA256 || p.Preview.Publication != nil && !sameAdoptionValue(receipt.Publication, *p.Preview.Publication) {
				return nil, errors.New("恢复计划与原发布清理历史不一致")
			}
		}
		at = p.CreatedAt
	default:
		return nil, errors.New("恢复历史类别无效")
	}
	if at <= 0 || at > time.Now().Unix()+300 {
		return nil, errors.New("恢复历史时间无效")
	}
	if kind == recoveryAdoptionHistory {
		settled, err := recoveryHistorySettled(data, id)
		if err != nil || !settled {
			return nil, err
		}
	}
	if kind != recoveryAdoptionHistory {
		if _, err := os.Lstat(restorePublicationWork(data, id)); err == nil {
			return nil, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return &recoveryHistoryCandidate{id: id, name: name, at: at}, nil
}

type recoveryHistoryIdentity struct {
	Device, Inode uint64
	GID, Mode uint32
	Size, Modified, Changed int64
	SHA256 string
}

func recoveryFileIdentity(info os.FileInfo) (recoveryHistoryIdentity, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return recoveryHistoryIdentity{}, errors.New("恢复历史文件归属无效")
	}
	return recoveryHistoryIdentity{Device: uint64(st.Dev), Inode: st.Ino, GID: st.Gid, Mode: uint32(info.Mode()), Size: info.Size(), Modified: st.Mtim.Nano(), Changed: st.Ctim.Nano()}, nil
}

func recoveryHistoryInventory(ctx context.Context, path string, kind recoveryHistoryKind) (map[string]recoveryHistoryIdentity, int64, error) {
	out := map[string]recoveryHistoryIdentity{}
	var bytes int64
	files := []string{""}
	var directory recoveryHistoryIdentity
	if kind != recoveryPlanHistory {
		if err := privateAdoptionDirectory(path, false); err != nil {
			return nil, 0, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, 0, err
		}
		directory, err = recoveryFileIdentity(info)
		if err != nil {
			return nil, 0, err
		}
		items, err := boundedEntries(path, 4)
		if err != nil {
			return nil, 0, err
		}
		files = []string{}
		for _, item := range items {
			valid := item.Name() == "publication.json"
			if kind == recoveryAdoptionHistory {
				valid = item.Name() == "intent.json" || item.Name() == "adoption.json" || item.Name() == "cleanup.json" || item.Name() == "cleaned.json"
			}
			if !valid {
				return nil, 0, errors.New("已清理恢复历史含有材料或未知文件")
			}
			files = append(files, item.Name())
		}
		if kind == recoveryPublicationHistory && len(files) != 1 || kind == recoveryAdoptionHistory && len(files) < 2 {
			return nil, 0, errors.New("已清理恢复历史缺少完整回执")
		}
	}
	for _, name := range files {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		file := path
		if name != "" {
			file = filepath.Join(path, name)
		}
		info, err := os.Lstat(file)
		if err != nil {
			return nil, 0, err
		}
		before, err := recoveryFileIdentity(info)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
			return nil, 0, errors.Join(err, errors.New("恢复历史须为 root 只读文件"))
		}
		raw, err := secure.ReadRootFile(file, adoptionRecordMax)
		if err != nil {
			return nil, 0, err
		}
		after, err := os.Lstat(file)
		if err != nil {
			return nil, 0, err
		}
		latest, err := recoveryFileIdentity(after)
		if err != nil || latest != before || int64(len(raw)) != info.Size() {
			return nil, 0, errors.Join(err, errors.New("恢复历史在核对期间变化"))
		}
		before.SHA256 = secure.Hash(raw)
		out[name] = before
		bytes += int64(len(raw))
	}
	if kind != recoveryPlanHistory {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, 0, err
		}
		latest, err := recoveryFileIdentity(info)
		if err != nil || latest != directory {
			return nil, 0, errors.Join(err, errors.New("恢复历史目录在核对期间变化"))
		}
		out["."] = directory
	}
	return out, bytes, nil
}

type recoveryHistoryUsage struct { count int; bytes int64 }

func validateRecoveryLive(root string, kind recoveryHistoryKind, items []os.DirEntry) error {
	for _, item := range items {
		if item.Name() == ".lock" && kind == recoveryAdoptionHistory {
			continue
		}
		path := filepath.Join(root, item.Name())
		if kind == recoveryPlanHistory {
			scratch := item.Name() == ".json-copy"
			if !scratch && (!strings.HasSuffix(item.Name(), ".json") || !validID.MatchString(strings.TrimSuffix(item.Name(), ".json"))) {
				return errors.New("恢复计划存储存在未知文件")
			}
			f, info, err := secure.OpenRootFile(path, adoptionRecordMax)
			if err != nil {
				return err
			}
			f.Close()
			if info.Mode().Perm() != 0400 && (!scratch || info.Mode().Perm() != 0600) {
				return errors.New("恢复计划记录或暂存权限无效")
			}
			continue
		}
		id := item.Name()
		for _, prefix := range []string{".adopting-", ".cleaning-", ".cleaned-"} {
			if strings.HasPrefix(id, prefix) {
				if prefix == ".adopting-" && kind != recoveryAdoptionHistory {
					return errors.New("恢复发布存储包含未知阶段")
				}
				id = strings.TrimPrefix(id, prefix)
				break
			}
		}
		if !validID.MatchString(id) {
			return errors.New("恢复历史存储包含未知资源")
		}
		var err error
		if kind == recoveryAdoptionHistory {
			_, _, err = adoptionEntries(path)
		} else {
			_, _, err = publicationEntries(path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func recoveryHistoryUsageAt(ctx context.Context, root string, kind recoveryHistoryKind, prefix string) (recoveryHistoryUsage, error) {
	u := recoveryHistoryUsage{}
	for _, dir := range []string{filepath.Join(root, recoveryHistoryDir), filepath.Join(root, recoveryHistoryDir, prefix)} {
		if err := privateAdoptionDirectory(dir, false); os.IsNotExist(err) {
			return u, nil
		} else if err != nil {
			return u, err
		}
	}
	shard := filepath.Join(root, recoveryHistoryDir, prefix)
	items, err := boundedEntries(shard, recoveryHistoryShardCount)
	if err != nil {
		return u, err
	}
	for _, item := range items {
		id := strings.TrimPrefix(item.Name(), ".cleaned-")
		if kind == recoveryPlanHistory {
			id = strings.TrimSuffix(item.Name(), ".json")
		}
		if !validID.MatchString(id) || id[:2] != prefix || item.Name() != recoveryHistoryName(kind, id) {
			return u, errors.New("恢复历史分片存在未知回执")
		}
		_, size, err := recoveryHistoryInventory(ctx, filepath.Join(shard, item.Name()), kind)
		if err != nil {
			return u, err
		}
		u.count++
		u.bytes += size
	}
	if u.bytes > recoveryHistoryShardBytes {
		return u, errors.New("恢复历史归档已超出内容预算，保留原回执")
	}
	return u, nil
}

// Automatic archival is capacity-triggered and retains recent eligible history.
// A bounded immutable archive remains part of target-local recovery metadata;
// neither the business backup nor restoration can replace it.
func archiveRecoveryHistory(ctx context.Context, data, root string, kind recoveryHistoryKind) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncRecoveryHistory(root); err != nil {
		return err
	}
	items, err := recoveryLiveEntries(root, AdoptionRecordMax+1)
	if err != nil {
		return err
	}
	if err = validateRecoveryLive(root, kind, items); err != nil {
		return err
	}
	candidates := []recoveryHistoryCandidate{}
	count := 0
	for _, item := range items {
		if item.Name() == ".lock" && kind == recoveryAdoptionHistory || item.Name() == ".json-copy" && kind == recoveryPlanHistory {
			continue
		}
		count++
	}
	if count < AdoptionRecordMax {
		return nil
	}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate, err := recoveryHistoryCandidateFor(data, root, kind, item.Name())
		if err != nil {
			return err
		}
		if candidate != nil {
			candidates = append(candidates, *candidate)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].at > candidates[j].at || candidates[i].at == candidates[j].at && candidates[i].id > candidates[j].id })
	type approval struct {
		candidate recoveryHistoryCandidate
		identity map[string]recoveryHistoryIdentity
		bytes int64
	}
	approved := []approval{}
	usage := map[string]recoveryHistoryUsage{}
	full := false
	for i := len(candidates)-1; i >= recoveryHistoryKeep && len(approved) < recoveryHistoryBatch; i-- {
		c := candidates[i]
		if _, archived, err := recoveryHistoryPath(root, kind, c.id); err != nil {
			return err
		} else if archived {
			return errors.New("恢复历史同时存在热区和归档记录")
		}
		identity, size, err := recoveryHistoryInventory(ctx, filepath.Join(root, c.name), kind)
		if err != nil {
			return err
		}
		prefix := c.id[:2]
		u, ok := usage[prefix]
		if !ok {
			u, err = recoveryHistoryUsageAt(ctx, root, kind, prefix)
			if err != nil {
				return err
			}
			usage[prefix] = u
		}
		if u.count >= recoveryHistoryShardCount || u.bytes+size > recoveryHistoryShardBytes {
			full = true
			continue
		}
		u.count++
		u.bytes += size
		usage[prefix] = u
		approved = append(approved, approval{candidate: c, identity: identity, bytes: size})
	}
	if full && len(approved) == 0 {
		return errors.New("恢复历史归档达到保留预算，原回执继续保留")
	}
	for _, a := range approved {
		c := a.candidate
		current, err := recoveryHistoryCandidateFor(data, root, kind, c.name)
		if err != nil || current == nil || *current != c {
			return errors.Join(err, errors.New("恢复历史已变化或仍被恢复引用"))
		}
		archive, shard := filepath.Join(root, recoveryHistoryDir), filepath.Join(root, recoveryHistoryDir, c.id[:2])
		for _, dir := range []string{archive, shard} {
			if err = privateAdoptionDirectory(dir, true); err != nil {
				return err
			}
		}
		u, err := recoveryHistoryUsageAt(ctx, root, kind, c.id[:2])
		if err != nil {
			return err
		}
		if u.count >= recoveryHistoryShardCount || u.bytes+a.bytes > recoveryHistoryShardBytes {
			return errors.New("恢复历史归档预算在执行前已变化，保留原回执")
		}
		identity, size, err := recoveryHistoryInventory(ctx, filepath.Join(root, c.name), kind)
		if err != nil || size != a.bytes || !reflect.DeepEqual(identity, a.identity) {
			return errors.Join(err, errors.New("原恢复回执身份已变化"))
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = unix.Renameat2(unix.AT_FDCWD, filepath.Join(root, c.name), unix.AT_FDCWD, filepath.Join(shard, c.name), unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = errors.Join(syncDir(shard), syncDir(archive), syncDir(root)); err != nil {
			return err
		}
	}
	return nil
}
