package agent

import (
	"context"
	"time"
)

// The conflicted directory is retained and is never reloaded as a rollback
// target. After a possible switch, recovery completes only the recorded managed
// candidate, or remains blocked for local intervention.
func (n *Nginx) executeRestore(record Record) {
	uncertain := func() {
		record.State, record.Stage, record.Error = "recovery_required", "restore_unconfirmed", "受管恢复尚未确认；保留原外部副本，停止后续冲突操作"
		_ = n.persist(record)
	}
	fail := func(stage, message string) {
		record.State, record.Stage, record.Error = "failed", stage, message
		_ = n.persist(record)
	}
	beforeSwitch := record.Stage == "prepared" || record.Stage == "testing"
	if record.AfterDir != record.OperationID || !validID(record.AfterDir) || (record.BeforeDir != "bootstrap" && !validID(record.BeforeDir)) || len(record.RestoreSnapshot) != 64 || len(record.CandidateHash) != 64 {
		uncertain()
		return
	}
	testCandidate := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return n.test(ctx, record.AfterDir)
	}
	tested := false
	if beforeSwitch {
		record.Stage = "testing"
		if n.persist(record) != nil {
			return
		}
		if testCandidate() != nil {
			fail("nginx_test_failed", "恢复候选未通过 Nginx 校验；原发布指针未改变")
			return
		}
		tested = true
	}
	candidate, err := n.readManifest(record.AfterDir)
	if err != nil || candidate.RevisionID != record.AfterRevision || manifestHash(candidate) != record.CandidateHash {
		if beforeSwitch {
			fail("candidate_changed", "恢复候选已变化；原发布指针未改变")
		} else {
			uncertain()
		}
		return
	}
	dir, current, err := n.activeMetadata()
	if err != nil || (dir != record.BeforeDir && dir != record.AfterDir) {
		uncertain()
		return
	}
	if dir == record.BeforeDir {
		if current.RevisionID != record.BeforeRevision {
			uncertain()
			return
		}
		if !tested {
			if testCandidate() != nil {
				uncertain()
				return
			}
			tested = true
		}
		snapshot, err := n.scanExternal(dir, current, "", nil, nil, nil)
		if err != nil || !snapshot.Complete || snapshot.Snapshot != record.RestoreSnapshot {
			if beforeSwitch {
				fail("external_conflict", "外部副本已再次变化，原发布指针未改变")
			} else {
				uncertain()
			}
			return
		}
		record.Stage = "restore_switch_pending"
		if n.persist(record) != nil {
			return
		}
		if n.switchTo(record.AfterDir, record.BeforeDir) != nil {
			uncertain()
			return
		}
		record.Stage = "restore_switched"
		if n.persist(record) != nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = n.observe(ctx, candidate)
	cancel()
	if err != nil {
		// On restart the binary or dependencies may differ. Revalidate the
		// immutable candidate and the active pointer before sending HUP.
		if !tested && testCandidate() != nil {
			uncertain()
			return
		}
		active, verified, activeErr := n.active()
		if activeErr != nil || active != record.AfterDir || manifestHash(verified) != record.CandidateHash || n.reload() != nil {
			uncertain()
			return
		}
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		err = n.waitObserved(ctx, candidate)
		cancel()
		if err != nil {
			uncertain()
			return
		}
	}
	active, verified, err := n.active()
	if err != nil || active != record.AfterDir || manifestHash(verified) != record.CandidateHash {
		uncertain()
		return
	}
	record.State, record.Stage, record.Error, record.ObservedRevision = "succeeded", "restore_confirmed", "", record.AfterRevision
	if n.persist(record) != nil {
		uncertain()
	}
}
