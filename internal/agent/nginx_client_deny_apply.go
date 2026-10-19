package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/secure"
)

const clientDenyKind = "nginx.client-deny"
const clientDenyJournalLimit = 512 << 10

var errClientDenyRecovery = errors.New("客户端拒绝集合恢复尚未确认")

// One journal slot is a recovery checkpoint, not an operation history. Reusing
// it prevents periodic ban reconciliation from exhausting the root journal.
type clientDenyIntent struct {
	ManifestHash string             `json:"manifest_hash"`
	Before       clientDenySnapshot `json:"before"`
	After        clientDenySnapshot `json:"after"`
}

func pendingNginxRecord(r Record) bool {
	return strings.HasPrefix(r.Kind, "nginx.") && (r.State == "running" || r.State == "compensating" || r.State == "recovery_required")
}

func clientDenyCheckpoint(records []Record) (*Record, error) {
	var out *Record
	for _, r := range records {
		if r.Kind != clientDenyKind {
			continue
		}
		if out != nil || r.ClientDeny == nil || !validID(r.OperationID) || r.BeforeDir != r.AfterDir || r.BeforeRevision != r.AfterRevision || !fail2banDigest.MatchString(r.ClientDeny.ManifestHash) {
			return nil, errors.New("客户端拒绝恢复记录无效")
		}
		encoded, _ := json.Marshal(r.ClientDeny)
		whole, _ := json.Marshal(r)
		_, _, beforeErr := renderClientDenySnapshot(r.ClientDeny.Before)
		_, _, afterErr := renderClientDenySnapshot(r.ClientDeny.After)
		if len(whole) > clientDenyJournalLimit || r.RequestHash != secure.Hash(encoded) || beforeErr != nil || afterErr != nil {
			return nil, errors.New("客户端拒绝恢复快照无法核对")
		}
		switch r.State {
		case "running", "compensating", "recovery_required", "succeeded", "failed":
		default:
			return nil, errors.New("客户端拒绝恢复状态无效")
		}
		copy := r
		out = &copy
	}
	return out, nil
}

func (n *Nginx) replaceClientDeny(expected, next clientDenySnapshot) error {
	current, _, err := n.readClientDenySnapshot()
	if err != nil {
		return err
	}
	before, _, err := renderClientDenySnapshot(expected)
	if err != nil {
		return err
	}
	actual, _, _ := renderClientDenySnapshot(current)
	if !bytes.Equal(before, actual) {
		return ErrExternalChange
	}
	raw, _, err := renderClientDenySnapshot(next)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(n.clientDenyPath()), ".sets-"+secure.ID())
	defer os.Remove(tmp)
	if err = durableFile(tmp, raw, 0440, n.gid); err != nil {
		return err
	}
	if err = os.Rename(tmp, n.clientDenyPath()); err != nil {
		return err
	}
	return syncDir(filepath.Dir(n.clientDenyPath()))
}

func (n *Nginx) clientDenyUnchanged(dir string, m manifest, expected clientDenySnapshot) error {
	active, verified, err := n.active()
	if err != nil || active != dir || manifestHash(verified) != manifestHash(m) {
		return ErrExternalChange
	}
	actual, _, err := n.readClientDenySnapshot()
	if err != nil {
		return err
	}
	actualBytes, _, _ := renderClientDenySnapshot(actual)
	expectedBytes, _, _ := renderClientDenySnapshot(expected)
	if !bytes.Equal(actualBytes, expectedBytes) {
		return ErrExternalChange
	}
	return nil
}

// Caller holds n.mu and has revalidated the authoritative source after collection.
func (n *Nginx) applyClientDeny(ctx context.Context, expectedDir, expectedHash string, desired clientDenySnapshot) (string, error) {
	if n.closed || n.unlock == nil || n.disasterBusy != "" || n.http01 != nil && n.http01.busy() {
		return "", ErrBusy
	}
	if err := fail2banUpgradeRestoreIdle(n.DataDir, ""); err != nil {
		return "", err
	}
	if err := fail2banUpgradeQuiesceIdle(n.DataDir, ""); err != nil {
		return "", err
	}
	records, err := n.Journal.List()
	if err != nil {
		return "", err
	}
	for _, r := range records {
		if pendingNginxRecord(r) {
			if r.Kind == fail2banUpgradeActivationKind {
				if err = fail2banUpgradeActivationActions(ctx, n.DataDir); err != nil {
					return "", err
				}
				continue
			}
			return "", ErrBusy
		}
	}
	checkpoint, err := clientDenyCheckpoint(records)
	if err != nil {
		return "", err
	}
	dir, m, err := n.active()
	if err != nil || dir != expectedDir || manifestHash(m) != expectedHash {
		return "", ErrExternalChange
	}
	before, beforeGeneration, err := n.readClientDenySnapshot()
	if err != nil {
		return "", err
	}
	if checkpoint == nil {
		if before.SourceKey != "" || before.ObservedAt != 0 || len(before.Entries) != 0 {
			return "", ErrExternalChange
		}
	} else {
		expected := checkpoint.ClientDeny.Before
		if checkpoint.State == "succeeded" {
			expected = checkpoint.ClientDeny.After
		}
		actualBytes, _, _ := renderClientDenySnapshot(before)
		expectedBytes, _, _ := renderClientDenySnapshot(expected)
		if !bytes.Equal(actualBytes, expectedBytes) {
			return "", ErrExternalChange
		}
	}
	_, generation, err := renderClientDenySnapshot(desired)
	if err != nil {
		return "", err
	}
	if err = n.observe(ctx, m); err != nil {
		return "", errors.New("更新拒绝集合前无法确认当前 Nginx 运行代次")
	}
	if generation == beforeGeneration && desired.SourceKey == before.SourceKey {
		return generation, n.clientDenyUnchanged(dir, m, before)
	}
	id := secure.ID()
	if checkpoint != nil {
		id = checkpoint.OperationID
	}
	intent := &clientDenyIntent{ManifestHash: manifestHash(m), Before: before, After: desired}
	encoded, _ := json.Marshal(intent)
	r := Record{OperationID: id, Kind: clientDenyKind, RequestHash: secure.Hash(encoded), State: "running", Stage: "replace_pending", BeforeDir: dir, AfterDir: dir, BeforeRevision: m.RevisionID, AfterRevision: m.RevisionID, ClientDeny: intent}
	if err = n.persist(r); err != nil {
		return "", err
	}
	if err = n.replaceClientDeny(before, desired); err == nil {
		err = n.test(ctx, dir)
	}
	if err == nil && generation != beforeGeneration {
		err = n.reload()
	}
	if err == nil {
		err = n.waitObserved(ctx, m)
	}
	if err == nil {
		err = n.clientDenyUnchanged(dir, m, desired)
	}
	if err == nil {
		r.State, r.Stage, r.ObservedRevision = "succeeded", "runtime_confirmed", m.RevisionID
		err = n.persist(r)
	}
	if err != nil {
		if recoverErr := n.recoverClientDeny(r); recoverErr != nil {
			return "", errors.Join(err, recoverErr)
		}
		return "", errors.Join(errors.New("客户端拒绝集合应用失败，已确认恢复原集合"), err)
	}
	return generation, nil
}

// Restart always compensates an interrupted batch; fresh official bans are
// collected separately. Cached after-images are never replayed as authority.
func (n *Nginx) recoverClientDeny(r Record) error {
	if _, err := clientDenyCheckpoint([]Record{r}); err != nil {
		return errors.Join(errClientDenyRecovery, err)
	}
	r.State, r.Stage = "compensating", "rollback_pending"
	if err := n.persist(r); err != nil {
		return errors.Join(errClientDenyRecovery, err)
	}
	err := func() error {
		dir, m, err := n.active()
		if err != nil || dir != r.BeforeDir || m.RevisionID != r.BeforeRevision || manifestHash(m) != r.ClientDeny.ManifestHash {
			return ErrExternalChange
		}
		current, _, err := n.readClientDenySnapshot()
		if err != nil {
			return err
		}
		actual, _, _ := renderClientDenySnapshot(current)
		before, _, _ := renderClientDenySnapshot(r.ClientDeny.Before)
		after, _, _ := renderClientDenySnapshot(r.ClientDeny.After)
		if !bytes.Equal(actual, before) {
			if !bytes.Equal(actual, after) {
				return ErrExternalChange
			}
			if err = n.replaceClientDeny(current, r.ClientDeny.Before); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err = n.test(ctx, dir); err != nil {
			return err
		}
		if err = n.reload(); err != nil {
			return err
		}
		if err = n.waitObserved(ctx, m); err != nil {
			return err
		}
		return n.clientDenyUnchanged(dir, m, r.ClientDeny.Before)
	}()
	if err != nil {
		r.State, r.Stage, r.Error = "recovery_required", "rollback_unconfirmed", "拒绝集合回滚未确认，须本机处理；"+err.Error()
	} else {
		r.State, r.Stage, r.Error = "failed", "rolled_back", "拒绝集合已恢复原代次"
	}
	if err = errors.Join(err, n.persist(r)); err != nil {
		return errors.Join(errClientDenyRecovery, err)
	}
	return nil
}
