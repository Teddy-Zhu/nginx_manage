package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Every pending activation has both a current fence and its original audit.
// No live state is consulted when authenticating an acknowledged historical result.
func pendingFail2banUpgradeActivation(data string) (*fail2banUpgradeActivationIntent, fail2banUpgradeActivationFacts, error) {
	var empty fail2banUpgradeActivationFacts
	var marker fail2banUpgradeActivationMarker
	err := readFail2banUpgradeActivationJSON(filepath.Join(fail2banUpgradeActivations(data), "current.json"), &marker)
	present := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, empty, err
	}
	if present && (marker.Schema != 1 || !validID(marker.ID) || !fail2banDigest.MatchString(marker.IntentSHA256)) {
		return nil, empty, errors.New("升级启动隔离格式无效")
	}
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return nil, empty, err
	}
	found := !present
	var pending *fail2banUpgradeActivationIntent
	facts := empty
	for _, r := range records {
		if r.Kind != fail2banUpgradeActivationKind {
			continue
		}
		i, _, err := readFail2banUpgradeActivation(data, r.OperationID)
		if err != nil {
			return nil, empty, err
		}
		f, err := i.facts()
		if err != nil {
			return nil, empty, err
		}
		acknowledged := f.Receipt != nil && sameFail2banUpgradePreparationRecord(r, i.record(f.Receipt))
		if !acknowledged && !pendingFail2banUpgradeActivationRecord(r, i.record(nil)) {
			return nil, empty, errors.New("升级启动原审计与意图冲突")
		}
		if present && marker.ID == i.Request.OperationID {
			if marker != i.marker() {
				return nil, empty, errors.New("升级启动隔离摘要变化")
			}
			found = true
		}
		if acknowledged {
			continue
		}
		if !present || marker != i.marker() || pending != nil {
			return nil, empty, errors.New("升级启动缺少唯一隔离，保留现场")
		}
		copy := i
		pending, facts = &copy, f
	}
	if !found {
		i, _, err := readFail2banUpgradeActivation(data, marker.ID)
		if err != nil || marker != i.marker() {
			return nil, empty, errors.Join(errors.New("升级启动隔离缺少原意图"), err)
		}
		f, err := i.facts()
		if err != nil {
			return nil, empty, err
		}
		if _, err = (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(marker.ID); !os.IsNotExist(err) {
			return nil, empty, errors.Join(errors.New("升级启动隔离的 UUID 存在其他审计"), err)
		}
		if f.Execution || f.Claim != nil || f.Started != nil || f.Stop != nil || f.Receipt != nil {
			return nil, empty, errors.New("升级启动已有执行材料但原审计丢失，不重建授权")
		}
		pending, facts = &i, f
	}
	return pending, facts, nil
}

func fail2banUpgradeActivationIdle(data, allowed string) error {
	i, _, err := pendingFail2banUpgradeActivation(data)
	if err != nil {
		return err
	}
	if i != nil && i.Request.OperationID != allowed {
		return errors.New("Fail2ban 升级启动尚未确认，须沿原 UUID 续办或停止候选")
	}
	return nil
}

func (i fail2banUpgradeActivationIntent) selection(ctx context.Context) (fail2banUpgradeSwitch, error) {
	return i.selected(ctx, true)
}

func (i fail2banUpgradeActivationIntent) engine(ctx context.Context, nginx bool) error {
	_, err := i.selected(ctx, nginx)
	return err
}

func (i fail2banUpgradeActivationIntent) selected(ctx context.Context, nginx bool) (fail2banUpgradeSwitch, error) {
	s, _, err := readFail2banUpgradeVerificationSwitch(i.Request.DataDir, i.Request.SwitchID)
	if err != nil {
		return s, err
	}
	current, err := loadFail2banManaged(i.Request.DataDir)
	if err != nil {
		return s, err
	}
	if current == nil || !fail2banUpgradeOneOf(current, s.After) {
		return s, errors.New("升级启动不得覆盖其他代码或服务选择事件")
	}
	if err = checkFail2banUpgradeVerificationGrants(i.Request.DataDir, s); err != nil {
		return s, err
	}
	machine, boot, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return s, err
	}
	if machine != s.Manifest.Basis.MachineID || boot != s.Manifest.Basis.BootID {
		return s, errors.New("升级启动已超出原机器或启动代次，保留恢复材料")
	}
	if err = verifyFail2banManaged(ctx, current, true); err != nil {
		return s, err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return s, err
	}
	if err = fail2banManagedNoOther(ctx, i.Request.DataDir, false); err != nil {
		return s, err
	}
	if nginx && i.NginxRuntimeSHA256 != "" {
		_, _, runtimeHash, e := fail2banUpgradeNginxObserver(i.verification())
		if e != nil {
			return s, e
		}
		if runtimeHash != i.NginxRuntimeSHA256 {
			return s, errors.New("升级启动期间 Nginx 运行来源变化")
		}
	}
	return s, ctx.Err()
}

// Background action executors alone may progress while waiting for protection.
// Ordinary configuration, installation and lifecycle admission still sees the fence.
func fail2banUpgradeActivationActions(ctx context.Context, data string) error {
	i, f, err := pendingFail2banUpgradeActivation(data)
	if err != nil || i == nil {
		return err
	}
	if f.Started == nil || f.Stop != nil || f.Receipt != nil || time.Now().Unix() > i.deadline() {
		return ErrBusy
	}
	s, err := i.selection(ctx)
	if err != nil {
		return err
	}
	live, err := readFail2banLiveService(ctx, s.After.binding())
	if err != nil {
		return err
	}
	return f.Started.matches(live)
}

func (s fail2banUpgradeActivationStarted) matches(live fail2banLiveService) error {
	if live.view.MainPID == nil || *live.view.MainPID != s.PID || live.invocation != s.Invocation || live.inode != s.SocketInode {
		return errors.New("升级候选运行或 Socket 代次变化")
	}
	return nil
}

// ExecStartPre does not acquire the parent's locks. One immutable claim binds
// the fixed service's actual systemd invocation and prevents automatic restarts.
func fail2banUpgradeActivationPrestart(ctx context.Context, data string, claim bool) (string, error) {
	i, f, err := pendingFail2banUpgradeActivation(data)
	if err != nil || i == nil {
		return "", err
	}
	if !f.Execution || f.Claim != nil || f.Started != nil || f.Stop != nil || f.Receipt != nil || time.Now().Unix() > i.deadline() {
		return "", errors.New("升级启动未授权本次服务启动或已消费启动许可")
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	audit, err := j.Get(i.Request.OperationID)
	if err != nil || !pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
		return "", errors.Join(errors.New("升级启动缺少原始执行审计"), err)
	}
	if _, err = i.selection(ctx); err != nil {
		return "", err
	}
	invocation := os.Getenv("INVOCATION_ID")
	service, actual, err := lifecycleService(ctx)
	if err != nil && !errors.Is(err, errFail2banLifecycleJobPending) {
		return "", err
	}
	if !fail2banInvocation.MatchString(invocation) || invocation != actual || service.Load != "loaded" || service.Active != "activating" {
		return "", errors.New("升级启动许可仅供固定服务的本次 ExecStartPre 使用")
	}
	if claim {
		if err = requestFail2banUpgradeStartClaim(ctx, *i, invocation); err != nil {
			return "", err
		}
	}
	return i.Request.OperationID, nil
}
