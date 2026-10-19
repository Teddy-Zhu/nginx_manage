package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func fail2banUpgradePreparationAccess(data, scope, id string) (func(), error) {
	if err := fail2banManagedRoot(data, scope); err != nil {
		return nil, err
	}
	if !validID(id) {
		return nil, errors.New("升级准备须使用独立操作 UUID")
	}
	unhost, err := fail2banHostSyncLocks(data)
	if err != nil {
		return nil, err
	}
	maintenance, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).maintenanceLock()
	if err != nil {
		unhost()
		return nil, err
	}
	return func() { maintenance(); unhost() }, nil
}

func (i fail2banUpgradePreparation) result(receipt fail2banUpgradePreparationReceipt) Fail2banUpgradePreparation {
	return Fail2banUpgradePreparation{State: "prepared_unacknowledged", ID: i.Request.OperationID, CreatedAt: i.CreatedAt, Target: i.Request.Target, InstallationID: i.Basis.Current.OperationID, EventID: i.Basis.Current.EventID, Source: fail2banUpgradeComponent(&i.Basis.Current), Candidate: fail2banUpgradeComponent(&i.Basis.Candidate), IntentSHA256: receipt.IntentSHA256, ConfigurationSHA256: receipt.ConfigurationSHA256, UnitSHA256: receipt.UnitSHA256, CandidateJailSelection: i.Material.IDs.Jails, NginxRegistryID: i.Material.IDs.Nginx, HostSourcesID: i.Material.IDs.Sources, HostSyncID: i.Material.IDs.Sync}
}

func fail2banUpgradePreparationStatus(ctx context.Context, i fail2banUpgradePreparation, receipt fail2banUpgradePreparationReceipt) (Fail2banUpgradePreparation, error) {
	out := i.result(receipt)
	audit, err := readFail2banUpgradeReceipt(i.Request.DataDir, i.Request.OperationID)
	if err != nil {
		return out, err
	}
	if audit != nil {
		if !sameFail2banUpgradePreparationRecord(*audit, i.record(receipt)) {
			return out, errors.New("升级准备审计与原材料不匹配")
		}
		out.State = "prepared"
	}
	basis, err := readFail2banUpgradeBasis(ctx, i.Request.DataDir, &i.Basis.Candidate)
	if err != nil {
		return out, err
	}
	recovery, err := readFail2banUpgradeHostRecovery(i.Request.DataDir, basis)
	if err != nil {
		return out, err
	}
	scope := basis.hash() == i.Request.Target && fail2banUpgradeGrantScopeHash(basis) == i.Grants.ScopeSHA256
	checkpoint := recovery.hash() == i.Recovery.hash()
	out.ScopeCurrent, out.CheckpointCurrent = &scope, &checkpoint
	return out, ctx.Err()
}

// Status authenticates the published preparation and its exact generated
// files. Current identity checks do not replace execution-time code checks.
func ReadFail2banUpgradePreparation(parent context.Context, data, scope, id string) (Fail2banUpgradePreparation, error) {
	unlock, err := fail2banUpgradePreparationAccess(data, scope, id)
	if err != nil {
		return Fail2banUpgradePreparation{}, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	i, receipt, err := readFail2banUpgradePreparation(data, id, filepath.Join(fail2banUpgradePreparations(data), id))
	if err != nil {
		return Fail2banUpgradePreparation{}, err
	}
	return fail2banUpgradePreparationStatus(ctx, i, receipt)
}

func existingFail2banUpgradePreparation(ctx context.Context, in Fail2banUpgradePreparationOptions) (Fail2banUpgradePreparation, bool, error) {
	var out Fail2banUpgradePreparation
	dir := filepath.Join(fail2banUpgradePreparations(in.DataDir), in.OperationID)
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return out, false, nil
	} else if err != nil {
		return out, true, err
	}
	i, receipt, err := readFail2banUpgradePreparation(in.DataDir, in.OperationID, dir)
	if err != nil {
		return out, true, err
	}
	if in.hash() != i.Request.hash() {
		return out, true, errors.New("同一升级准备 UUID 的请求或目标已变化")
	}
	if err = acknowledgeFail2banUpgradePreparation(i, receipt); err != nil {
		return i.result(receipt), true, err
	}
	out, err = fail2banUpgradePreparationStatus(ctx, i, receipt)
	return out, true, err
}

// Preparation reserves immutable candidate events and saves full before-images
// while preserving the running selection. Stop, snapshot, switch and recovery
// remain distinct durable execution stages and cannot be inferred from ready.
func PrepareFail2banUpgrade(parent context.Context, in Fail2banUpgradePreparationOptions) (out Fail2banUpgradePreparation, err error) {
	return prepareFail2banUpgradeFor(parent, in, "")
}

func prepareFail2banUpgradeFor(parent context.Context, in Fail2banUpgradePreparationOptions, allowed string) (out Fail2banUpgradePreparation, err error) {
	if !fail2banDigest.MatchString(in.Target) {
		return out, errors.New("升级准备须提供原候选预览的精确目标摘要")
	}
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	existing, found, err := existingFail2banUpgradePreparation(ctx, in)
	unlock()
	if found || err != nil {
		return existing, err
	}
	_, err = planFail2banUpgrade(ctx, in.Fail2banUpgradeOptions, allowed, func(ctx context.Context, plan Fail2banUpgradePlan, basis fail2banUpgradeBasis) error {
		if allowed != "" && !plan.Running {
			return errors.New("网页升级准备仅接受正在运行的受管实例")
		}
		var e error
		out, e = prepareFail2banUpgradeLocked(ctx, in, plan, basis, allowed)
		return e
	})
	return out, err
}

// Caller holds host, binding and maintenance locks, and authenticates the exact
// original candidate. A stopped capture may only change the service observation.
func prepareFail2banUpgradeLocked(ctx context.Context, in Fail2banUpgradePreparationOptions, plan Fail2banUpgradePlan, basis fail2banUpgradeBasis, allowed string) (out Fail2banUpgradePreparation, resultErr error) {
	if err := fail2banUpgradeIdleFor(&Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}, allowed); err != nil {
		return out, err
	}
	if existing, found, err := existingFail2banUpgradePreparation(ctx, in); found || err != nil {
		out = existing
		return out, err
	}
	if plan.Target != in.Target {
		return out, errors.New("升级准备的实例、配置、服务或候选预览已变化")
	}
	if !plan.Grants.ScopeVerified {
		return out, errors.New("升级动作范围或恢复依据存在阻塞：" + strings.Join(plan.Grants.Blockers, "；"))
	}
	recovery, err := readFail2banUpgradeHostRecovery(in.DataDir, basis)
	if err != nil {
		return out, err
	}
	i := fail2banUpgradePreparation{Schema: 1, CreatedAt: time.Now().Unix(), Request: in, Basis: basis, Grants: plan.Grants, Recovery: recovery}
	i.Material, err = buildFail2banUpgradeMaterial(basis, plan.Grants, recovery, newFail2banUpgradeMaterialIDs(basis, plan.Grants), i.CreatedAt)
	if err != nil {
		return out, err
	}
	if err = i.validate(in.DataDir, in.OperationID); err != nil {
		return out, err
	}
	if audit, err := readFail2banUpgradeReceipt(in.DataDir, in.OperationID); err != nil {
		return out, err
	} else if audit != nil {
		return out, errors.New("升级准备 UUID 已被已有审计占用")
	}
	store := fail2banUpgradePreparations(in.DataDir)
	if err = fail2banStatePrivateDir(store, true); err != nil {
		return out, err
	}
	if err = syncDir(filepath.Dir(store)); err != nil {
		return out, err
	}
	if err = fail2banUpgradePreparationQuota(store); err != nil {
		return out, err
	}
	tmp, err := os.MkdirTemp(store, ".prepare-")
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	if err = prepareFail2banJailConfigAt(&basis.Candidate, i.Material.Bundle, filepath.Join(tmp, "config")); err != nil {
		return out, err
	}
	if err = writeFail2banUpgradeUnit(filepath.Join(tmp, "candidate.service"), basis.Candidate.unit()); err != nil {
		return out, err
	}
	if err = writeFail2banUpgradePreparationJSON(filepath.Join(tmp, "intent.json"), i); err != nil {
		return out, err
	}
	receipt, err := i.receipt()
	if err != nil {
		return out, err
	}
	if err = writeFail2banUpgradePreparationJSON(filepath.Join(tmp, "receipt.json"), receipt); err != nil {
		return out, err
	}
	if err = fail2banUpgradePreparationSize(tmp); err != nil {
		return out, err
	}
	if _, err = fail2banManagedExec(ctx, basis.Candidate.python(), basis.Candidate.args(true, "-c", filepath.Join(tmp, "config"), "-s", fail2banManagedSocket, "-t"), 8*time.Second, 16384); err != nil {
		return out, errors.Join(errors.New("候选官方客户端未通过已暂存完整配置校验"), err)
	}
	if err = verifyFail2banManaged(ctx, &basis.Current, true); err != nil {
		return out, err
	}
	if err = verifyFail2banManaged(ctx, &basis.Candidate, false); err != nil {
		return out, err
	}
	after, err := readFail2banUpgradeBasis(ctx, in.DataDir, &basis.Candidate)
	if err != nil || after.hash() != basis.hash() {
		return out, errors.Join(errors.New("升级准备期间原实例或动作范围已变化"), err)
	}
	afterGrants, err := planFail2banUpgradeGrants(in.DataDir, after)
	if err != nil || afterGrants.hash() != plan.Grants.hash() {
		return out, errors.Join(errors.New("升级准备期间原动作批准或运行检查点已变化"), err)
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = fail2banUpgradeIdleFor(&Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}, allowed); err != nil {
		return out, err
	}
	out = i.result(receipt)
	out.State = "preparation_unknown"
	if err = publishFail2banUpgradePreparation(tmp, i); err != nil {
		return out, err
	}
	out.State = "prepared_unacknowledged"
	if err = acknowledgeFail2banUpgradePreparation(i, receipt); err != nil {
		return out, err
	}
	scopeCurrent, checkpointCurrent := true, true
	out.State, out.ScopeCurrent, out.CheckpointCurrent = "prepared", &scopeCurrent, &checkpointCurrent
	return out, nil
}
