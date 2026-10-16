package agent

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

type Fail2banNginxStatus struct {
	At          int64                 `json:"at"`
	Queued      bool                  `json:"queued"`
	State       string                `json:"state"`
	Registry    fail2banNginxRegistry `json:"registry"`
	CollectedAt int64                 `json:"collected_at"`
	ConfirmedAt int64                 `json:"confirmed_at"`
	Generation  string                `json:"generation"`
	Protected   int                   `json:"protected"`
	Inactive    int                   `json:"inactive"`
	Reason      string                `json:"reason"`
}

type fail2banNginxExecutor struct {
	nginx           *Nginx
	wake            chan struct{}
	mu              sync.Mutex
	value           Fail2banNginxStatus
	registryVersion uint64
}

func (f *fail2banNginxExecutor) status() Fail2banNginxStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.value
	out.At = time.Now().Unix()
	return out
}

func (f *fail2banNginxExecutor) enqueue() {
	f.mu.Lock()
	f.value.Queued = true
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fail2banNginxExecutor) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	dirty := true
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.wake:
			dirty = true
		case <-ticker.C:
		}
		if time.Since(last) < 5*time.Second || !dirty && time.Since(last) < 30*time.Second {
			continue
		}
		last, dirty = time.Now(), false
		f.mu.Lock()
		f.value.Queued, f.value.State, f.value.Reason = false, "collecting", ""
		registryVersion := f.registryVersion
		f.mu.Unlock()
		call, cancel := context.WithTimeout(ctx, 45*time.Second)
		result, err := f.reconcile(call)
		cancel()
		f.mu.Lock()
		result.Queued = f.value.Queued
		if f.registryVersion != registryVersion {
			result.Registry = f.value.Registry
		}
		if err != nil {
			result.State, result.Reason = "failed", err.Error()
			if errors.Is(err, errClientDenyRecovery) {
				result.State = "recovery_required"
			}
		}
		f.value = result
		f.mu.Unlock()
	}
}

func (f *fail2banNginxExecutor) reconcile(ctx context.Context) (Fail2banNginxStatus, error) {
	out := Fail2banNginxStatus{State: "idle", Registry: fail2banNginxRegistry{Schema: 1, Grants: []fail2banNginxGrant{}}}
	n := f.nginx
	leave, ok := n.maintenance.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	n.mu.Lock()
	registry, err := loadFail2banNginxRegistry(n.DataDir)
	out.Registry = registry
	if err != nil {
		n.mu.Unlock()
		return out, err
	}
	records, err := n.Journal.List()
	if err != nil {
		n.mu.Unlock()
		return out, err
	}
	checkpoint, err := clientDenyCheckpoint(records)
	if err != nil {
		n.mu.Unlock()
		return out, err
	}
	for _, r := range records {
		if pendingNginxRecord(r) && r.Kind != clientDenyKind {
			n.mu.Unlock()
			return out, ErrBusy
		}
	}
	if checkpoint != nil && pendingNginxRecord(*checkpoint) {
		if err = n.recoverClientDeny(*checkpoint); err != nil {
			n.mu.Unlock()
			return out, err
		}
	}
	dir, m, err := n.active()
	if err != nil {
		n.mu.Unlock()
		return out, err
	}
	current, _, err := n.readClientDenySnapshot()
	if os.IsNotExist(err) && len(registry.Grants) == 0 && len(m.ClientDeny) == 0 {
		n.mu.Unlock()
		return out, nil
	}
	if err != nil {
		n.mu.Unlock()
		return out, err
	}
	if len(registry.Grants) == 0 && len(current.Entries) == 0 {
		n.mu.Unlock()
		return out, nil
	}
	n.mu.Unlock()
	collectContext, stopCollect := context.WithTimeout(ctx, 20*time.Second)
	sample, err := collectFail2banNginx(collectContext, n.DataDir, registry, m.ClientDeny)
	stopCollect()
	if err != nil {
		return out, err
	}
	out.CollectedAt, out.Protected, out.Inactive = sample.snapshot.ObservedAt, sample.protected, sample.inactive
	n.mu.Lock()
	defer n.mu.Unlock()
	latest, err := loadFail2banNginxRegistry(n.DataDir)
	if err != nil || latest.ID != registry.ID {
		return out, errors.New("收集期间 Nginx 动作授权变化，等待重新收集")
	}
	if time.Now().Unix()-sample.snapshot.ObservedAt > 5 {
		return out, errors.New("拒绝集合样本等待超时，等待重新收集")
	}
	if sample.binding != nil {
		if err = fail2banCurrentBinding(n.DataDir, sample.binding, true); err != nil {
			return out, err
		}
		live, err := readFail2banLiveService(ctx, sample.binding)
		if err != nil || !sameFail2banLive(sample.live, live) {
			return out, errors.New("提交集合前 Fail2ban 实例身份变化")
		}
	}
	generation, err := n.applyClientDeny(ctx, dir, manifestHash(m), sample.snapshot)
	if err != nil {
		return out, err
	}
	out.State, out.Generation, out.ConfirmedAt = "confirmed", generation, time.Now().Unix()
	return out, nil
}
