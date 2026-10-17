package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/nginxswitch"
)

// RunNginxSwitchJob consumes one persisted authorization in an independent unit.
// Neither a restarted unit nor a status query can reuse a claimed grant.
func RunNginxSwitchJob(ctx context.Context, data, id string) (Record, error) {
	var r Record
	if os.Geteuid() != 0 || !validID(id) {
		return r, errors.New("独立切换服务身份无效")
	}
	if _, err := installationExecutable(); err != nil {
		return r, err
	}
	if _, _, err := switchJobHost(ctx, data, id); err != nil {
		return r, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".nginx-switch-api.lock")
	if err != nil {
		return r, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return r, err
	}
	r, err = switchJobRecord(data, id)
	if err != nil {
		access()
		return r, err
	}
	if nginxswitch.Terminal(r.State) {
		access()
		return r, nil
	}
	job := r.NginxSwitchJob
	a := &job.Authorizations[len(job.Authorizations)-1]
	now := time.Now().Unix()
	if a.ClaimedAt != 0 || a.Request.AuthorizationUntil <= now || r.State != "queued" {
		access()
		return r, errors.New("切换启动授权已使用或过期，须显式续办原任务")
	}
	if err = installGrant(j, job.Input.MaintenanceID, a.Request.Epoch, false); err != nil {
		access()
		return r, err
	}
	a.ClaimedAt = now
	r.State, r.Stage = "running", "validating"
	err = j.Put(r)
	access()
	if err != nil {
		return r, err
	}
	child, e := switchJobChild(data, r)
	if e != nil {
		return r, e
	}
	rollback := false
	for _, a := range job.Authorizations {
		if a.Request.Command == "rollback" {
			rollback = true
		}
	}
	if child == nil && rollback {
		r.State, r.Stage, r.Error = "failed", "cancelled_before_switch", "已取消尚未创建独立切换的派发"
		return r, j.Put(r)
	}
	if child == nil {
		_, err = SwitchNginx(ctx, NginxSwitchOptions{DataDir: data, Input: job.Source, OperationID: job.ChildID, Epoch: a.Request.Epoch, dispatchID: id, expected: &job.Input})
	} else if !nginxswitch.Terminal(child.State) {
		_, err = SwitchNginx(ctx, NginxSwitchOptions{DataDir: data, OperationID: job.ChildID, Epoch: a.Request.Epoch, Resume: !rollback, Rollback: rollback, dispatchID: id, expected: &job.Input})
	}
	child, e = switchJobChild(data, r)
	if e != nil {
		return r, errors.Join(err, e)
	}
	if child != nil {
		r.State, r.Stage, r.Error = child.State, child.Stage, child.Error
		if !nginxswitch.Terminal(r.State) {
			r.State = "recovery_required"
		}
	} else {
		if err == nil {
			err = errors.New("切换执行器未创建原子操作记录")
		}
		r.State, r.Stage, r.Error = "failed", "preflight_rejected", err.Error()
	}
	if e = j.Put(r); e != nil {
		return r, errors.Join(err, e)
	}
	return r, err
}
