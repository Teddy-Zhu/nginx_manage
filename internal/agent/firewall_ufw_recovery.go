package agent

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Only the original parent's closed temporary transition is compensated here.
// Every family must match a whole original/candidate image. Foreign drift is a
// conflict, not an excuse to replay an old complete filter-table export.
func recoverUFWChange(ctx context.Context, dataDir string) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	v, err := loadUFWChange(dataDir)
	if err != nil || v == nil {
		return err
	}
	terminal := slices.Contains([]string{"succeeded", "rolled_back", "failed"}, v.Operation.State)
	if terminal {
		r, err := loadUFWReceipt(dataDir, v.Operation.ID)
		if err == nil && ufwChangeReceiptMatches(r, v) {
			return nil
		}
	}
	authority, err := ufwRegistrationAuthority(dataDir)
	if err != nil || authority.NextClaim.Owner != v.Transition.Owner || authority.NextClaim.MachineHash != v.Transition.MachineHash || authority.NextClaim.OperationID != v.Transition.RegistrationOperationID {
		return errors.New("UFW 原业务恢复材料不属于当前宿主机授权，禁止续办")
	}
	if terminal {
		// Repair only publication of the trusted original checkpoint. This
		// never changes a contradictory terminal receipt into a new operation.
		return saveUFWChange(dataDir, v)
	}
	if err = recoverUFWRestore(ctx, dataDir); err != nil {
		return err
	}
	v.Rollback = true
	v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "compensating", "restoring_previous", time.Now().Unix()
	v.Operation.Error = "未确认的 UFW 变更恢复原运行状态"
	if err = saveUFWChange(dataDir, v); err != nil {
		return err
	}
	fail := func(cause error) error {
		v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "recovery_required", "recovery_blocked", time.Now().Unix()
		v.Operation.Error = "UFW 原业务规则尚未恢复；保留原快照，须核对配置、工具和内核范围"
		return errors.Join(cause, saveUFWChange(dataDir, v))
	}
	if err = checkUFWTransitionSources(ctx, dataDir, &v.Transition); err != nil {
		return fail(err)
	}
	for _, material := range v.Transition.Materials {
		image, err := readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
		if err != nil {
			return fail(err)
		}
		if sameUFWReloadImage(image, material.BeforeKernel) {
			continue
		}
		if !sameUFWReloadImage(image, material.AfterKernel) {
			return fail(errors.New("UFW 原地址族出现外部规则变化，禁止快照覆盖"))
		}
		var id string
		for _, step := range v.Steps {
			if step.Family == material.Family && step.Target == "previous" {
				id = step.ID
			}
		}
		_, restoreErr := runUFWRestore(ctx, dataDir, ufwRestoreRequest{ID: id, OperationID: v.Operation.ID, Target: "previous"})
		// A missing reply is not success. Once the exact child has ended,
		// observation may prove that its original one-use restore did finish.
		if ufwRestoreProcessPending(dataDir) {
			return fail(errors.Join(restoreErr, errors.New("UFW 原恢复进程尚未结束，禁止继续补偿")))
		}
		image, err = readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
		if err != nil || !sameUFWReloadImage(image, material.BeforeKernel) {
			return fail(errors.Join(restoreErr, err, errors.New("UFW 原地址族恢复结果尚未核对")))
		}
	}
	lock, err := lockUFWManager()
	if err != nil {
		return fail(err)
	}
	defer lock.Close()
	if err = checkUFWTransitionSources(ctx, dataDir, &v.Transition); err != nil {
		return fail(err)
	}
	for _, material := range v.Transition.Materials {
		image, err := readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
		if err != nil || !sameUFWReloadImage(image, material.BeforeKernel) {
			return fail(errors.Join(err, errors.New("UFW 完整原运行状态尚未核对")))
		}
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = verifyUFWManagerLock(lock); err != nil {
		return fail(err)
	}
	v.Operation.State, v.Operation.Stage, v.Operation.UpdatedAt = "rolled_back", "restored_previous", time.Now().Unix()
	return saveUFWChange(dataDir, v)
}
