package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// Only durable original material authenticates a fence; status never reopens a
// terminal operation merely because the live database has since changed.
func pendingFail2banUpgradeQuiesce(data string) (*fail2banUpgradeQuiesceIntent, fail2banUpgradeQuiesceFacts, error) {
	var marker fail2banUpgradeActivationMarker
	var empty fail2banUpgradeQuiesceFacts
	err := readFail2banUpgradeActivationJSON(filepath.Join(fail2banUpgradeQuiescences(data), "current.json"), &marker)
	present := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, empty, err
	}
	if present && (marker.Schema != 1 || !validID(marker.ID) || !fail2banDigest.MatchString(marker.IntentSHA256)) {
		return nil, empty, errors.New("升级停止隔离格式无效")
	}
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return nil, empty, err
	}
	found := !present
	var active *fail2banUpgradeQuiesceIntent
	facts := empty
	for _, r := range records {
		if r.Kind != fail2banUpgradeQuiesceKind {
			continue
		}
		i, p, e := readFail2banUpgradeQuiesce(data, r.OperationID)
		if e != nil {
			return nil, empty, e
		}
		f, e := i.facts(p)
		if e != nil {
			return nil, empty, e
		}
		done := f.Receipt != nil && sameFail2banUpgradePreparationRecord(r, i.record(f.Receipt))
		if !done && !pendingFail2banUpgradeQuiesceRecord(r, i.record(nil)) {
			return nil, empty, errors.New("升级停止原审计与意图冲突")
		}
		if present && marker.ID == i.Request.OperationID {
			if marker != i.marker() {
				return nil, empty, errors.New("升级停止隔离摘要变化")
			}
			found = true
		}
		if done {
			continue
		}
		if !present || marker != i.marker() || active != nil {
			return nil, empty, errors.New("升级停止缺少唯一隔离")
		}
		copy := i
		active, facts = &copy, f
	}
	if !found {
		i, p, e := readFail2banUpgradeQuiesce(data, marker.ID)
		if e != nil || marker != i.marker() {
			return nil, empty, errors.Join(errors.New("升级停止隔离缺少原意图"), e)
		}
		f, e := i.facts(p)
		if e != nil {
			return nil, empty, e
		}
		if _, e = (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(marker.ID); !os.IsNotExist(e) {
			return nil, empty, errors.Join(errors.New("升级停止隔离的 UUID 已有其他审计"), e)
		}
		if f.Execution || f.Stopped != nil || f.Receipt != nil {
			return nil, empty, errors.New("升级停止已有执行材料但原审计丢失，不重建授权")
		}
		active, facts = &i, f
	}
	return active, facts, nil
}

func fail2banUpgradeQuiesceIdle(data, allowed string) error {
	i, _, err := pendingFail2banUpgradeQuiesce(data)
	if err != nil {
		return err
	}
	if i != nil && i.Request.OperationID != allowed {
		return errors.New("Fail2ban 升级停止与捕获尚未确认，须沿原 UUID 续办")
	}
	return nil
}

func (i fail2banUpgradeQuiesceIntent) sameSelection(b fail2banUpgradeBasis, p fail2banUpgradePreparation) bool {
	b.Service, b.Invocation = p.Basis.Service, p.Basis.Invocation
	return b.hash() == p.Basis.hash()
}

func (i fail2banUpgradeQuiesceIntent) observe(ctx context.Context, p fail2banUpgradePreparation) (fail2banUpgradeBasis, error) {
	b, err := readFail2banUpgradeBasis(ctx, i.Request.DataDir, &p.Basis.Candidate)
	if err != nil {
		return b, err
	}
	if !i.sameSelection(b, p) {
		return b, errors.New("升级停止期间原代码、配置或批准范围变化")
	}
	if b.Service.UnitFile != p.Basis.Service.UnitFile {
		return b, errors.New("升级停止期间服务启用偏好变化")
	}
	for _, entry := range []struct {
		r     *fail2banManagedRecord
		files bool
	}{{&b.Current, true}, {&b.Candidate, false}} {
		if err = verifyFail2banManaged(ctx, entry.r, entry.files); err != nil {
			return b, err
		}
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return b, err
	}
	if err = fail2banManagedNoOther(ctx, i.Request.DataDir, false); err != nil {
		return b, err
	}
	machine, boot, err := hostBootIdentity("nginxpanel:fail2ban-state-machine:v1:")
	if err != nil {
		return b, err
	}
	if machine != i.MachineID || boot != i.BootID {
		return b, errors.New("升级停止已超出原机器或启动代次")
	}
	directory, err := fail2banStateDirectoryIdentity(filepath.Join(b.Current.work(), "state"))
	if err != nil {
		return b, err
	}
	if directory != i.Directory {
		return b, errors.New("升级停止的原状态目录身份变化")
	}
	recovery, err := readFail2banUpgradeHostRecovery(i.Request.DataDir, b)
	if err != nil {
		return b, err
	}
	if recovery.hash() != i.Recovery.hash() {
		return b, errors.New("升级停止期间原动作检查点或审计变化")
	}
	if root := b.HostRegistration; root != nil && root.State == "registered" {
		copy := p
		copy.Recovery = i.Recovery
		program, _ := fail2banUpgradeOriginalHostProgram(copy)
		kernel, e := program.snapshot(ctx)
		if e != nil {
			return b, e
		}
		if !fail2banHostProgramShape(program, kernel) || kernel.NamespaceID != i.Kernel.NamespaceID || kernel.Fingerprint != i.Kernel.Fingerprint {
			return b, errors.New("升级停止期间原内核动作规则变化")
		}
	}
	nginx, err := readFail2banUpgradeQuiesceNginx(i.Request.DataDir, p)
	if err != nil {
		return b, err
	}
	if !fail2banUpgradeOneOf(nginx, i.Nginx) {
		return b, errors.New("升级停止期间原 Nginx 配置元数据、拒绝集合或检查点变化")
	}
	return b, ctx.Err()
}

// lifecycleService accepts both absent and all-zero IDs for inactive units.
// Only the stopped-service/socket check makes either form admissible.
func (i fail2banUpgradeQuiesceIntent) stoppedInvocation(invocation string) bool {
	return invocation == "" || invocation == "00000000000000000000000000000000" || invocation == i.Invocation
}
