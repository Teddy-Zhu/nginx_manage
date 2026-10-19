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

func checkFail2banUpgradeCandidateLineage(i fail2banUpgradeSwitch, r fail2banManagedRecord) error {
	if r.ActionState != "completed" {
		return errors.New("候选实例仍有待核对服务操作")
	}
	for n := 0; n < 128; n++ {
		if !fail2banUpgradeCandidateCore(i.After, r) {
			return errors.New("当前选择的代码或 jail 已不属于原升级候选")
		}
		if r.EventID == i.After.EventID {
			if !fail2banUpgradeOneOf(r, i.After) {
				return errors.New("原候选选择事件内容变化")
			}
			return nil
		}
		if !validID(r.PreviousEvent) {
			return errors.New("候选服务事件缺少原升级选择祖先")
		}
		var previous fail2banManagedRecord
		if err := readFail2banUpgradeSwitchJSON(filepath.Join(fail2banManagedDir(i.Request.DataDir), "history", r.PreviousEvent+".json"), &previous); err != nil {
			return err
		}
		if previous.EventID != r.PreviousEvent {
			return errors.New("候选事件历史指针不匹配")
		}
		if err := validateFail2banManagedRecord(previous, i.Request.DataDir); err != nil {
			return err
		}
		r = previous
	}
	return errors.New("候选选择历史超过 128 项核对预算，须本机维护")
}

func observeFail2banUpgradeVerification(ctx context.Context, in Fail2banUpgradeVerificationOptions, i fail2banUpgradeSwitch, receipt fail2banUpgradeSwitchReceipt, result Fail2banStateRecovery, o fail2banStateRecoveryObservation) (fail2banUpgradeVerification, error) {
	var v fail2banUpgradeVerification
	if !fail2banUpgradeOneOf(o.Receipt, i.Snapshot) || !fail2banUpgradeOneOf(o.Manifest, i.Manifest) {
		return v, errors.New("升级保护核对未使用原切换固定的状态快照")
	}
	if err := checkFail2banUpgradeCandidateLineage(i, *o.Managed); err != nil {
		return v, err
	}
	if !fail2banUpgradeOneOf(o.Bundle, i.Prepared.Material.Bundle) {
		return v, errors.New("候选完整 jail 材料与原切换不同")
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
	v = fail2banUpgradeVerification{Schema: 1, Request: in, CreatedAt: result.At, SwitchSHA256: i.hash(), SwitchReceiptSHA256: fail2banUpgradeGrantHash("switch-receipt", receipt), Managed: *o.Managed, Recovery: result, Expected: o.Expected, Actual: o.Actual, Host: host, Nginx: nginx}
	if err = v.validate(in.DataDir, in.OperationID, i, receipt); err != nil {
		return v, err
	}
	return v, ctx.Err()
}

// VerifyFail2banUpgrade performs one bounded root observation. It never starts an engine,
// repairs actions, replays bans or changes a service/database/configuration.
func VerifyFail2banUpgrade(parent context.Context, in Fail2banUpgradeVerificationOptions) (out Fail2banUpgradeVerification, resultErr error) {
	if !validID(in.SwitchID) || in.SwitchID == in.OperationID {
		return out, errors.New("升级保护核对须使用独立 UUID 并指定原切换 UUID")
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
	i, receipt, err := readFail2banUpgradeVerificationSwitch(in.DataDir, in.SwitchID)
	if err != nil {
		return out, err
	}
	if err = fail2banUpgradeVerificationID(in.OperationID, i); err != nil {
		return out, err
	}
	if err = reserveFail2banUpgradeVerification(in.DataDir); err != nil {
		return out, err
	}
	_, err = verifyFail2banStateRecoveryFor(ctx, Fail2banStateSnapshotOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: i.Request.SnapshotID}, j, allowed, func(result Fail2banStateRecovery, o fail2banStateRecoveryObservation) error {
		var err error
		v, err = observeFail2banUpgradeVerification(ctx, in, i, receipt, result, o)
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
