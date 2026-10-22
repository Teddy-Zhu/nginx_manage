package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

const journalArchiveDir = "receipt-archive"
const journalArchiveFileLimit = 256 << 10
const journalArchiveShardBytes = 1 << 20
const journalArchiveShardCount = 128

// This allowlist excludes authority-bearing checkpoints and every future Record
// extension by default. Moving a receipt must not remove it from a coordinator's
// live checkpoint scan. Physical anchors are checked separately before approval.
func retirableJournalReceipt(r Record) bool {
	if !validID(r.OperationID) || !validSwitchDigest(r.RequestHash) || r.UpdatedAt <= 0 {
		return false
	}
	base := Record{OperationID: r.OperationID, RequestHash: r.RequestHash, Kind: r.Kind, State: r.State, Stage: r.Stage, UpdatedAt: r.UpdatedAt, Error: r.Error}
	switch r.Kind {
	case runtimeHistoryKind:
		if r.State != "succeeded" || validRuntimeHistory(r) != nil {
			return false
		}
		base.MaintenanceEpoch, base.RuntimeHistory = r.MaintenanceEpoch, r.RuntimeHistory
	case panelUpdateKind:
		if validPanelUpdate(r) != nil || !panelUpdateTerminal(r) || r.PanelUpdate.Cleanup == nil || r.PanelUpdate.Cleanup.Status.State != "done" {
			return false
		}
		base.MaintenanceEpoch, base.Deadline, base.PanelUpdate = r.MaintenanceEpoch, r.Deadline, r.PanelUpdate
	case agentUpgradeKind:
		if validAgentUpgrade(r) != nil || !agentUpgradeTerminal(r) {
			return false
		}
		base.AgentUpgrade = r.AgentUpgrade
	case "nginx.apply", "nginx.validate":
		if !historyTerminal(r) || r.AfterDir != r.OperationID || r.BeforeDir != "bootstrap" && !validID(r.BeforeDir) || !validID(r.AfterRevision) || r.BeforeRevision != "" && !validID(r.BeforeRevision) {
			return false
		}
		if r.State == "succeeded" && (r.Kind == "nginx.apply" && r.Stage != "runtime_confirmed" || r.Kind == "nginx.validate" && r.Stage != "nginx_tested" || !validSwitchDigest(r.CandidateHash)) || r.State == "rolled_back" && r.Stage != "rollback_confirmed" || r.State == "cancelled" {
			return false
		}
		base.BeforeRevision, base.AfterRevision = r.BeforeRevision, r.AfterRevision
		base.BeforeDir, base.AfterDir = r.BeforeDir, r.AfterDir
		base.CandidateHash, base.ObservedRevision, base.DiagnosticsCount = r.CandidateHash, r.ObservedRevision, r.DiagnosticsCount
	default:
		return false
	}
	return reflect.DeepEqual(r, base)
}

func journalReceiptID(target string) (string, bool) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || parts[0] != "agent" || parts[1] != "operations" || !strings.HasSuffix(parts[2], ".json") {
		return "", false
	}
	id := strings.TrimSuffix(parts[2], ".json")
	return id, validID(id)
}

func (j *Journal) receiptArchivePath(id string) string {
	return filepath.Join(j.Dir, journalArchiveDir, id[:2], id+".json")
}

func (j *Journal) archivedJournalReceipt(id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("invalid archived receipt ID")
	}
	path := j.receiptArchivePath(id)
	for _, dir := range []string{filepath.Join(j.Dir, journalArchiveDir), filepath.Dir(path), j.Dir} {
		if err := maintenanceArchiveDirectory(dir, false); err != nil {
			return Record{}, err
		}
	}
	r, err := readPrivateJournalReceipt(path, id, journalArchiveFileLimit)
	if err == nil && !retirableJournalReceipt(r) {
		err = errors.New("archived receipt is not a retired journal operation")
	}
	return r, err
}

func (j *Journal) archivedOperation(id string) (Record, string, error) {
	r, err := j.archivedMaintenance(id)
	if err == nil {
		return r, j.maintenanceArchivePath(id), nil
	}
	if !os.IsNotExist(err) {
		return Record{}, "", err
	}
	r, err = j.archivedJournalReceipt(id)
	if err != nil {
		return Record{}, "", err
	}
	return r, j.receiptArchivePath(id), nil
}

// Typed readers retain their own size and node-binding checks. Archived records
// have already been checked against their original canonical bytes, so encoding
// the immutable value returns exactly the original document.
func (j *Journal) readOperationBytes(id string, limit int64) ([]byte, error) {
	if !validID(id) {
		return nil, errors.New("invalid operation ID")
	}
	raw, err := secure.ReadRootFile(filepath.Join(j.Dir, id+".json"), limit)
	if !os.IsNotExist(err) {
		return raw, err
	}
	r, err := j.archivedJournalReceipt(id)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(r)
	if err == nil && int64(len(raw)) > limit {
		err = errors.New("archived operation exceeds its original size limit")
	}
	return raw, err
}

func sameJournalReceipt(a, b Record) bool {
	a.UpdatedAt, b.UpdatedAt = 0, 0
	return reflect.DeepEqual(a, b)
}

type journalArchiveUsage struct {
	count int
	bytes int64
}

// The archive has 256 fixed UUID prefixes, bounded directory reads, 32,768
// receipts and at most 256 MiB. Unknown files consume no implicit authority.
func (j *Journal) receiptArchiveUsage(prefix string) (journalArchiveUsage, error) {
	var usage journalArchiveUsage
	root := filepath.Join(j.Dir, journalArchiveDir)
	for _, dir := range []string{j.Dir, root, filepath.Join(root, prefix)} {
		if err := maintenanceArchiveDirectory(dir, false); os.IsNotExist(err) {
			return usage, nil
		} else if err != nil {
			return usage, err
		}
	}
	f, err := os.Open(filepath.Join(root, prefix))
	if err != nil {
		return usage, err
	}
	entries, readErr := f.Readdir(journalArchiveShardCount + 1)
	closeErr := f.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err = errors.Join(readErr, closeErr); err != nil {
		return usage, err
	}
	if len(entries) > journalArchiveShardCount {
		return usage, errors.New("journal receipt archive exceeds its count budget")
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !strings.HasSuffix(entry.Name(), ".json") || !validID(id) || id[:2] != prefix || !ok || !entry.Mode().IsRegular() || entry.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || entry.Size() <= 0 || entry.Size() > journalArchiveFileLimit {
			return usage, errors.New("untrusted journal archive entry")
		}
		usage.count++
		usage.bytes += entry.Size()
	}
	if usage.bytes > journalArchiveShardBytes {
		return usage, errors.New("journal receipt archive exceeds its byte budget")
	}
	return usage, nil
}

func (n *Nginx) journalReceiptEligible(r Record) (bool, error) {
	if !retirableJournalReceipt(r) {
		return false, nil
	}
	if r.Kind == runtimeHistoryKind {
		return true, nil
	}
	if r.Kind == panelUpdateKind || r.Kind == agentUpgradeKind {
		return n.updateReceiptEligible(r)
	}
	// Both publication identities must already have been retired. The initial
	// bootstrap and disaster/restore anchors never enter this allowlist.
	for _, dir := range []string{r.BeforeDir, r.AfterDir} {
		_, err := os.Lstat(filepath.Join(n.DataDir, "nginx", "revisions", dir))
		if err == nil {
			return false, nil
		}
		if !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}

func (n *Nginx) updateReceiptEligible(r Record) (bool, error) {
	var maintenanceID string
	var target *AgentProgram
	if r.Kind == panelUpdateKind {
		i := r.PanelUpdate.Intent
		if i.Input.Stage.DataDir != n.DataDir {
			return false, ErrExternalChange
		}
		present, err := panelrecovery.MaterialPresent(n.DataDir, i.SnapshotID)
		if err != nil || present {
			return false, err
		}
		maintenanceID = i.Input.MaintenanceID
		if i.Agent != nil {
			target = &i.Agent.Target
		}
	} else {
		i := r.AgentUpgrade.Intent
		if i.Input.Stage.DataDir != n.DataDir {
			return false, ErrExternalChange
		}
		maintenanceID, target = i.Input.MaintenanceID, &i.Target
	}
	grant, err := n.Journal.Get(maintenanceID)
	if err != nil {
		return false, err
	}
	if !releasedMaintenance(grant) {
		return false, nil
	}
	if target != nil {
		// These hot receipts are the ownership register used by program
		// reclamation. Keep them until the target directory is gone, including
		// after compensation, and never retire the currently selected program.
		current, err := readAgentLink()
		if err != nil {
			return false, err
		}
		if current == target.Link {
			return false, nil
		}
		if _, err = os.Lstat(filepath.Join(agentBootstrapRoot, target.Link)); !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}

func (n *Nginx) journalHistory(ctx context.Context, records []Record) ([]historyCandidate, error) {
	candidates := []historyCandidate{}
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := n.journalReceiptEligible(r)
		if err != nil {
			return nil, err
		}
		if ok {
			raw, err := secure.ReadRootFile(filepath.Join(n.Journal.Dir, r.OperationID+".json"), journalArchiveFileLimit)
			if err != nil {
				return nil, err
			}
			stored, err := decodePrivateJournalReceipt(raw, r.OperationID)
			if err != nil || !reflect.DeepEqual(r, stored) {
				return nil, ErrExternalChange
			}
			candidates = append(candidates, historyCandidate{target: "agent/operations/" + r.OperationID + ".json", at: r.UpdatedAt, manifest: manifest{Files: map[string]string{".": secure.Hash(raw)}}})
		}
	}
	return candidates, nil
}

func (n *Nginx) receiptArchiveRoom(e runtimeHistoryEntry, usage map[string]journalArchiveUsage) (bool, error) {
	id, ok := journalReceiptID(e.Path)
	if !ok {
		return false, ErrExternalChange
	}
	prefix := id[:2]
	u, found := usage[prefix]
	if !found {
		var err error
		u, err = n.Journal.receiptArchiveUsage(prefix)
		if err != nil {
			return false, err
		}
	}
	if u.count >= journalArchiveShardCount || u.bytes+e.Size > journalArchiveShardBytes {
		return false, nil
	}
	u.count++
	u.bytes += e.Size
	usage[prefix] = u
	return true, nil
}

// Check every remaining source and destination before the first move. A
// persisted approval may outlive a restart or a partially completed batch.
func (n *Nginx) archiveJournalHistory(ctx context.Context, plan runtimeHistoryPlan) error {
	if plan.Preview.Filter.Kind != "root_receipt" {
		return ErrExternalChange
	}
	usage := map[string]journalArchiveUsage{}
	for _, e := range plan.Entries {
		moved, err := n.journalArchiveSource(ctx, e)
		if err != nil {
			return err
		}
		if !moved {
			room, err := n.receiptArchiveRoom(e, usage)
			if err != nil || !room {
				return errors.Join(err, fault.Conflict("root 回执归档达到保留预算，原回执继续保留"))
			}
		}
	}
	for _, e := range plan.Entries {
		if err := n.archiveJournalReceipt(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (n *Nginx) journalArchiveSource(ctx context.Context, old runtimeHistoryEntry) (bool, error) {
	id, ok := journalReceiptID(old.Path)
	if !ok {
		return false, ErrExternalChange
	}
	j := n.Journal
	files := n.historyFiles("root_receipt")
	target := j.receiptArchivePath(id)
	if r, err := j.archivedJournalReceipt(id); err == nil {
		eligible, err := n.journalReceiptEligible(r)
		if err != nil || !eligible {
			return false, errors.Join(err, ErrExternalChange)
		}
		rel, err := filepath.Rel(n.DataDir, target)
		if err != nil {
			return false, err
		}
		moved, err := files.historyEntry(ctx, filepath.ToSlash(rel))
		// Rename updates ctime but preserves file identity, bytes and mtime.
		moved.Path, moved.Changed = old.Path, old.Changed
		if err != nil || moved != old {
			return false, errors.Join(err, ErrExternalChange)
		}
		if _, err = os.Lstat(filepath.Join(n.DataDir, filepath.FromSlash(old.Path))); !os.IsNotExist(err) {
			return false, errors.Join(err, ErrExternalChange)
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	current, err := files.historyEntry(ctx, old.Path)
	if err != nil || current != old {
		return false, errors.Join(err, ErrExternalChange)
	}
	r, err := readPrivateJournalReceipt(filepath.Join(j.Dir, id+".json"), id, journalArchiveFileLimit)
	if err != nil {
		return false, err
	}
	eligible, err := n.journalReceiptEligible(r)
	if err != nil || !eligible {
		return false, errors.Join(err, fault.Conflict("原 root 回执仍有运行材料或已变化"))
	}
	return false, nil
}

func (n *Nginx) archiveJournalReceipt(ctx context.Context, old runtimeHistoryEntry) error {
	j := n.Journal
	j.mu.Lock()
	defer j.mu.Unlock()
	moved, err := n.journalArchiveSource(ctx, old)
	if err != nil {
		return err
	}
	id, _ := journalReceiptID(old.Path)
	target := j.receiptArchivePath(id)
	if moved {
		return syncMaintenanceArchive(j.Dir, filepath.Dir(target))
	}
	room, err := n.receiptArchiveRoom(old, map[string]journalArchiveUsage{})
	if err != nil || !room {
		return errors.Join(err, fault.Conflict("root 回执归档达到保留预算，原回执继续保留"))
	}
	for _, dir := range []string{filepath.Join(j.Dir, journalArchiveDir), filepath.Dir(target)} {
		if err = maintenanceArchiveDirectory(dir, true); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, filepath.Join(j.Dir, id+".json"), unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncMaintenanceArchive(j.Dir, filepath.Dir(target))
}
