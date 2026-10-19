package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func readFail2banUpgradeVerificationSwitch(data, id string) (fail2banUpgradeSwitch, fail2banUpgradeSwitchReceipt, error) {
	i, err := readFail2banUpgradeSwitch(data, id)
	if err != nil {
		return i, fail2banUpgradeSwitchReceipt{}, err
	}
	u, err := i.undo()
	if err != nil {
		return i, fail2banUpgradeSwitchReceipt{}, err
	}
	r, err := i.receipt()
	if err != nil {
		return i, fail2banUpgradeSwitchReceipt{}, err
	}
	if r == nil || r.Outcome != "selected" || u != nil {
		return i, fail2banUpgradeSwitchReceipt{}, errors.New("保护核对须引用已完成候选选择且未撤回的原切换")
	}
	audit, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if err != nil {
		return i, *r, err
	}
	if !sameFail2banUpgradePreparationRecord(audit, i.record(r, nil)) {
		return i, *r, errors.New("保护核对前须先完成原切换审计确认")
	}
	return i, *r, nil
}

func checkFail2banUpgradeCandidateLineage(i fail2banUpgradeSelection, r fail2banManagedRecord) error {
	if r.ActionState != "completed" {
		return errors.New("目标实例仍有待核对服务操作")
	}
	for n := 0; n < 128; n++ {
		if !fail2banUpgradeCandidateCore(i.Managed, r) {
			return errors.New("当前代码或 jail 不属于本次授权选择")
		}
		if r.EventID == i.Managed.EventID {
			if !fail2banUpgradeOneOf(r, i.Managed) {
				return errors.New("原选择事件内容变化")
			}
			return nil
		}
		if !validID(r.PreviousEvent) {
			return errors.New("服务事件缺少本次授权选择祖先")
		}
		var previous fail2banManagedRecord
		if err := readFail2banUpgradeSwitchJSON(filepath.Join(fail2banManagedDir(i.DataDir), "history", r.PreviousEvent+".json"), &previous); err != nil {
			return err
		}
		if previous.EventID != r.PreviousEvent {
			return errors.New("受管事件历史指针不匹配")
		}
		if err := validateFail2banManagedRecord(previous, i.DataDir); err != nil {
			return err
		}
		r = previous
	}
	return errors.New("受管选择历史超过 128 项核对预算，须本机维护")
}

func observeFail2banUpgradeVerification(ctx context.Context, in Fail2banUpgradeVerificationOptions, i fail2banUpgradeSelection, result Fail2banStateRecovery, o fail2banStateRecoveryObservation) (fail2banUpgradeVerification, error) {
	var v fail2banUpgradeVerification
	if !fail2banUpgradeOneOf(o.Receipt, i.Snapshot) || !fail2banUpgradeOneOf(o.Manifest, i.Manifest) {
		return v, errors.New("升级保护核对未使用原切换固定的状态快照")
	}
	if err := checkFail2banUpgradeCandidateLineage(i, *o.Managed); err != nil {
		return v, err
	}
	if !fail2banUpgradeOneOf(o.Bundle, i.Bundle) {
		return v, errors.New("当前完整 jail 材料与授权选择不同")
	}
	if err := checkFail2banUpgradeVerificationGrants(in.DataDir, i); err != nil {
		return v, err
	}
	_, boot, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return v, err
	}
	if boot != i.Manifest.Basis.BootID {
		return v, errors.New("原升级启动代次已变化，不能沿用旧切换范围出具保护证明")
	}
	host, err := readFail2banUpgradeHostVerification(ctx, i, o.Actual)
	if err != nil {
		return v, err
	}
	nginx, err := readFail2banUpgradeNginxVerification(ctx, in, i, o)
	if err != nil {
		return v, err
	}
	if host != nil {
		if err = host.unchanged(ctx, in.DataDir); err != nil {
			return v, err
		}
	}
	if nginx != nil {
		after, err := readFail2banUpgradeNginxVerification(ctx, in, i, o)
		if err != nil {
			return v, err
		}
		if !fail2banUpgradeOneOf(after, nginx) {
			return v, errors.New("核对期间 Nginx 进程、配置、拒绝集合或回执变化")
		}
	}
	// Bracket all action reads with the same full official sample. New bans and
	// expirations require a fresh observation; cached subsets cannot prove success.
	actual, err := readFail2banJailRuntime(ctx, o.Managed, o.Bundle)
	if err != nil {
		return v, err
	}
	if !fail2banUpgradeOneOf(actual, o.Actual) {
		return v, errors.New("动作核对期间官方完整封禁变化，须重新采样")
	}
	current, err := loadFail2banManaged(in.DataDir)
	if err != nil {
		return v, err
	}
	if !fail2banUpgradeOneOf(current, o.Managed) {
		return v, errors.New("核对期间候选选择事件变化")
	}
	if err = checkFail2banUpgradeVerificationGrants(in.DataDir, i); err != nil {
		return v, err
	}
	live, err := readFail2banLiveService(ctx, o.Managed.binding())
	if err != nil {
		return v, err
	}
	if !sameFail2banLive(o.Live, live) {
		return v, errors.New("动作核对期间候选实例或 Socket 代次变化")
	}
	result.At = time.Now().Unix()
	v = fail2banUpgradeVerification{Schema: 1, Request: in, CreatedAt: result.At, SourceSHA256: i.SHA256, SourceReceiptSHA256: i.ReceiptSHA256, Managed: *o.Managed, Recovery: result, Expected: o.Expected, Actual: o.Actual, Host: host, Nginx: nginx}
	if err = v.validate(in.DataDir, in.OperationID, i); err != nil {
		return v, err
	}
	return v, ctx.Err()
}

// VerifyFail2banUpgrade performs one bounded root observation. It never starts an engine,
// repairs actions, replays bans or changes a service/database/configuration.
func VerifyFail2banUpgrade(parent context.Context, in Fail2banUpgradeVerificationOptions) (out Fail2banUpgradeVerification, resultErr error) {
	if !fail2banUpgradeSelectionRef(in.SwitchID, in.RestoreID) || fail2banUpgradeSelectionSourceID(in.SwitchID, in.RestoreID) == in.OperationID {
		return out, errors.New("升级保护核对须使用独立 UUID，并且只指定一个已完成切换或停止态恢复 UUID")
	}
	unlock, err := fail2banUpgradePreparationAccess(in.DataDir, in.Scope, in.OperationID)
	if err != nil {
		return out, err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	return verifyFail2banUpgradeLocked(ctx, in, "")
}

func verifyFail2banUpgradeLocked(ctx context.Context, in Fail2banUpgradeVerificationOptions, allowed string) (out Fail2banUpgradeVerification, resultErr error) {
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	v, i, err := readFail2banUpgradeVerification(in.DataDir, in.OperationID)
	if err == nil {
		if v.Request != in {
			return out, errors.New("相同保护核对 UUID 已绑定其他切换或 Nginx 运行来源")
		}
		out, err = v.result(i)
		if err != nil {
			return out, err
		}
		if err = acknowledgeFail2banUpgradeVerification(v, j); err != nil {
			return out, err
		}
		out.State = "verified"
		return out, nil
	}
	if !errors.Is(err, errFail2banUpgradeVerificationAbsent) {
		return out, err
	}
	if _, err = j.Get(in.OperationID); !os.IsNotExist(err) {
		return out, errors.Join(errors.New("保护核对 UUID 已存在其他审计或原证明丢失"), err)
	}
	if err = fail2banUpgradeIdleFor(j, allowed); err != nil {
		return out, err
	}
	i, err := readFail2banUpgradeSelection(in.DataDir, in.SwitchID, in.RestoreID)
	if err != nil {
		return out, err
	}
	if err = i.independentID(in.OperationID); err != nil {
		return out, err
	}
	if err = reserveFail2banUpgradeVerification(in.DataDir); err != nil {
		return out, err
	}
	_, err = verifyFail2banStateRecoveryFor(ctx, Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.Snapshot.OperationID}, j, allowed, func(result Fail2banStateRecovery, o fail2banStateRecoveryObservation) error {
		var err error
		v, err = observeFail2banUpgradeVerification(ctx, in, i, result, o)
		return err
	})
	if err != nil {
		return out, err
	}
	if err = fail2banUpgradeIdleFor(j, allowed); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out, err = v.result(i)
	if err != nil {
		return out, err
	}
	if err = writeFail2banUpgradeVerification(v); err != nil {
		out.State = "verification_unknown"
		return out, err
	}
	if err = acknowledgeFail2banUpgradeVerification(v, j); err != nil {
		return out, err
	}
	out.State = "verified"
	return out, nil
}
