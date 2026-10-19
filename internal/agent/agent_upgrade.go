package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/panelruntime"
)

type agentUpgradeWorker struct {
	j *Journal
	r Record
}

func (w *agentUpgradeWorker) save() error {
	w.r.UpdatedAt = time.Now().Unix()
	if err := validAgentUpgrade(w.r); err != nil {
		return err
	}
	return w.j.Put(w.r)
}
func (w *agentUpgradeWorker) stage(stage string) error {
	w.r.Stage = stage
	if w.r.AgentUpgrade.Rollback {
		w.r.State = "compensating"
	} else {
		w.r.State = "running"
	}
	w.r.Error = ""
	return w.save()
}
func agentUpgradeLocks(ctx context.Context, data string) (*Journal, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("Agent 升级需要本机 root")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return nil, nil, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	upgrade, err := j.waitRootLock(ctx, ".agent-upgrade.lock")
	if err != nil {
		return nil, nil, err
	}
	// Share the first-install lock so an installer cannot race the bootstrap
	// pointer or systemd registrations while the Agent is being replaced.
	installation, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		upgrade()
		return nil, nil, err
	}
	return j, func() { installation(); upgrade() }, nil
}

func QueueAgentUpgrade(ctx context.Context, in AgentUpgradeInput, id, epoch string) (Record, error) {
	var zero Record
	if !validID(id) || !validID(in.MaintenanceID) || !validID(epoch) {
		return zero, errors.New("Agent 升级须提供新操作 UUID 和已持有的维护身份")
	}
	j, unlock, err := agentUpgradeLocks(ctx, in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	defer unlock()
	if prior, err := AgentUpgradeStatus(in.Stage.DataDir, id); err == nil {
		if len(prior.AgentUpgrade.Authorizations) != 0 {
			return zero, errors.New("托管 Agent 升级须由原 API 授权续办")
		}
		if prior.AgentUpgrade.Intent.Input != in {
			return zero, errors.New("Agent 升级标识已用于不同请求")
		}
		return prior, nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	access, err := panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
	if err != nil {
		return zero, err
	}
	defer access()
	r, err := prepareAgentUpgrade(ctx, in, id, epoch)
	if err != nil {
		return zero, err
	}
	w := &agentUpgradeWorker{j: j, r: r}
	if err := w.save(); err != nil {
		return zero, err
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", agentUpgradeUnit(id))
	return w.r, err
}

// Called with the upgrade, installer and maintenance locks held. Preparation
// publishes only immutable program material; the caller persists authorization
// before it can dispatch an independent worker.
func prepareAgentUpgrade(ctx context.Context, in AgentUpgradeInput, id, epoch string) (Record, error) {
	var zero Record
	if _, err := installationExecutable(); err != nil {
		return zero, err
	}
	panel, err := panelruntime.Read(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	target, err := panelruntime.Stage(ctx, in.Stage)
	if err != nil {
		return zero, err
	}
	if err = target.RequireCurrent(); err != nil {
		return zero, err
	}
	if target.Release.AgentProtocol != panel.Release.AgentProtocol || target.Release.DatabaseSchema != panel.Release.DatabaseSchema || target.Release.LauncherVersion != panel.Release.LauncherVersion {
		return zero, errors.New("Agent 独立升级须与当前面板的协议、数据库及 launcher 合同一致；其他变更须使用协调部署流程")
	}
	before, err := readAgentProgram()
	if err != nil {
		return zero, err
	}
	if before.BinarySHA256 == target.Release.BinarySHA256 {
		return zero, errors.New("Agent 已使用此程序，不创建重复升级")
	}
	agentUnit, workerUnit, _, err := agentUpgradeUnits(ctx, in.Stage.DataDir, id)
	if err != nil {
		return zero, err
	}
	process, err := agentUpgradeObserve(ctx, in.Stage.DataDir, id, before)
	if err != nil {
		return zero, err
	}
	if !agentProcessValid(process) {
		return zero, errors.New("Agent 升级要求原服务正常运行")
	}
	// The held grant was checked under its cross-process lock. Do not reenter
	// that lock through the HTTP acquire endpoint during authorization.
	program, err := publishAgentProgram(ctx, filepath.Join(target.Directory, "nginxpanel"), target.Release.BinarySHA256)
	if err != nil {
		return zero, err
	}
	now := time.Now().Unix()
	i := AgentUpgradeIntent{Input: in, Before: before, Target: program, BeforeProcess: process, PanelID: panel.Release.ID, BindingSHA256: selectionValueHash(panel.Deployment), TargetVersion: target.Release.Version, ApprovalSHA256: selectionValueHash(target.Approval), AgentUnit: agentUnit, WorkerUnit: workerUnit, Epoch: epoch, CreatedAt: now, Deadline: now + 600}
	return Record{OperationID: id, Kind: agentUpgradeKind, State: "running", Stage: "authorized", RequestHash: agentUpgradeHash(id, i), AgentUpgrade: &AgentUpgradeOperation{Intent: i}}, nil
}

func ResumeAgentUpgrade(ctx context.Context, data, id string) (Record, error) {
	j, unlock, err := agentUpgradeLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := AgentUpgradeStatus(data, id)
	if err != nil || agentUpgradeTerminal(r) {
		return r, err
	}
	if len(r.AgentUpgrade.Authorizations) != 0 {
		return r, errors.New("托管 Agent 升级须由原 API 授权续办")
	}
	access, err := panelUpdateAccess(ctx, j, id, r.AgentUpgrade.Intent.Input.MaintenanceID, "", true)
	if err != nil {
		return r, err
	}
	defer access()
	a, b, _, err := agentUpgradeUnits(ctx, data, id)
	if err != nil {
		return r, err
	}
	if a != r.AgentUpgrade.Intent.AgentUnit || b != r.AgentUpgrade.Intent.WorkerUnit {
		return r, errors.New("Agent 升级服务已偏离原登记")
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", agentUpgradeUnit(id))
	return r, err
}

func (w *agentUpgradeWorker) guard(ctx context.Context, forward bool) error {
	i := w.r.AgentUpgrade.Intent
	access, err := panelUpdateAccess(ctx, w.j, w.r.OperationID, i.Input.MaintenanceID, "", true)
	if err != nil {
		return err
	}
	defer access()
	panel, err := panelruntime.Read(i.Input.Stage.DataDir)
	if err != nil {
		return err
	}
	if panel.Release.ID != i.PanelID || selectionValueHash(panel.Deployment) != i.BindingSHA256 {
		return errors.New("面板或运行绑定偏离 Agent 升级快照")
	}
	a, b, _, err := agentUpgradeUnits(ctx, i.Input.Stage.DataDir, w.r.OperationID)
	if err != nil {
		return err
	}
	if a != i.AgentUnit || b != i.WorkerUnit {
		return errors.New("Agent 或独立 worker 服务登记变化")
	}
	if err := checkAgentProgram(i.Before); err != nil {
		return err
	}
	if forward {
		target, err := panelruntime.Staged(ctx, i.Input.Stage)
		if err != nil {
			return err
		}
		if target.Release.BinarySHA256 != i.Target.BinarySHA256 || selectionValueHash(target.Approval) != i.ApprovalSHA256 || target.Release.Version != i.TargetVersion {
			return errors.New("Agent 升级签名暂存来源变化")
		}
		if err := checkAgentProgram(i.Target); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (w *agentUpgradeWorker) pointer() (AgentProgram, error) {
	i := w.r.AgentUpgrade.Intent
	actual, err := readAgentLink()
	if err != nil {
		return AgentProgram{}, err
	}
	if actual == i.Before.Link {
		return i.Before, nil
	}
	if actual == i.Target.Link {
		return i.Target, nil
	}
	return AgentProgram{}, errors.New("Agent 程序选择偏离原版本和候选版本")
}
func (w *agentUpgradeWorker) observe(ctx context.Context, p AgentProgram) (AgentProcess, error) {
	return agentUpgradeObserve(ctx, w.r.AgentUpgrade.Intent.Input.Stage.DataDir, w.r.OperationID, p)
}
func (w *agentUpgradeWorker) ready(ctx context.Context, program AgentProgram) (AgentProcess, string, error) {
	i := w.r.AgentUpgrade.Intent
	call, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		before, err := w.observe(call, program)
		if err == nil && before.State == "running" {
			status, probeErr := probeAgentUpgrade(call, i.Input.Stage.DataDir, i.Input.MaintenanceID, i.Before)
			if probeErr == nil {
				after, observeErr := w.observe(call, program)
				if observeErr == nil && before == after {
					return after, status.Epoch, nil
				}
				err = errors.Join(observeErr, errors.New("Agent 就绪期间进程变化"))
			} else {
				err = probeErr
			}
		} else if err == nil {
			err = errors.New("Agent 尚未运行")
		}
		last = err
		select {
		case <-call.Done():
			return AgentProcess{}, "", fmt.Errorf("Agent 就绪未确认：%w", errors.Join(call.Err(), last))
		case <-ticker.C:
		}
	}
}
func (w *agentUpgradeWorker) forward(ctx context.Context) error {
	i := w.r.AgentUpgrade.Intent
	for {
		if err := w.guard(ctx, true); err != nil {
			return err
		}
		current, err := w.pointer()
		if err != nil {
			return err
		}
		switch w.r.Stage {
		case "authorized":
			if current != i.Before {
				return errors.New("Agent 升级尚未停机但指针已经变化")
			}
			process, err := w.observe(ctx, i.Before)
			if err != nil {
				return err
			}
			if process != i.BeforeProcess {
				return errors.New("Agent 原服务已偏离初始进程")
			}
			if err := w.stage("stopping"); err != nil {
				return err
			}
		case "stopping":
			if current != i.Before {
				return errors.New("Agent 停机前指针已变化")
			}
			process, err := w.observe(ctx, i.Before)
			if err != nil {
				return err
			}
			if process.State == "running" {
				if process != i.BeforeProcess {
					return errors.New("Agent 停机目标已不是原进程")
				}
				if _, err := installationSystemctl(ctx, "stop", "nginxpanel-agent.service"); err != nil {
					return err
				}
				process, err = w.observe(ctx, i.Before)
				if err != nil {
					return err
				}
			}
			if process.State != "stopped" {
				return errors.New("Agent 停机未确认")
			}
			if err := w.stage("stopped"); err != nil {
				return err
			}
		case "stopped", "selecting":
			process, err := w.observe(ctx, current)
			if err != nil {
				return err
			}
			if process.State != "stopped" {
				return errors.New("Agent 尚在运行，不能切换程序")
			}
			if w.r.Stage == "stopped" {
				if current != i.Before {
					return errors.New("Agent 停机回执对应不同选择")
				}
				if err := w.stage("selecting"); err != nil {
					return err
				}
			}
			if err := selectAgentProgram(w.r.OperationID, i.Before, i.Target); err != nil {
				return err
			}
			if err := w.stage("selected"); err != nil {
				return err
			}
		case "selected":
			if current != i.Target {
				return errors.New("Agent 候选指针缺失")
			}
			process, err := w.observe(ctx, i.Target)
			if err != nil {
				return err
			}
			if process.State != "stopped" {
				return errors.New("Agent 候选已被外部启动")
			}
			if err := w.stage("starting"); err != nil {
				return err
			}
		case "starting":
			if current != i.Target {
				return errors.New("Agent 候选启动时指针变化")
			}
			process, err := w.observe(ctx, i.Target)
			if err != nil {
				return err
			}
			if process.State == "stopped" {
				if _, err := installationSystemctl(ctx, "start", "nginxpanel-agent.service"); err != nil {
					return err
				}
			}
			ready, epoch, err := w.ready(ctx, i.Target)
			if err != nil {
				return err
			}
			if ready == i.BeforeProcess || epoch == i.Epoch {
				return errors.New("候选 Agent 仍返回原进程或旧启动身份")
			}
			if err := w.guard(ctx, true); err != nil {
				return err
			}
			if current, err := w.pointer(); err != nil || current != i.Target {
				return errors.Join(err, errors.New("Agent 就绪后指针偏离"))
			}
			w.r.AgentUpgrade.Ready, w.r.AgentUpgrade.ReadyEpoch = &ready, epoch
			w.r.State, w.r.Stage, w.r.Error = "succeeded", "committed", ""
			return w.save()
		default:
			return errors.New("Agent 升级无法继续未知阶段")
		}
	}
}

func (w *agentUpgradeWorker) compensate(ctx context.Context) error {
	i := w.r.AgentUpgrade.Intent
	for {
		if err := w.guard(ctx, false); err != nil {
			return err
		}
		current, err := w.pointer()
		if err != nil {
			return err
		}
		switch w.r.Stage {
		case "rollback_stopping":
			process, err := w.observe(ctx, current)
			if err != nil {
				return err
			}
			if current == i.Before && process.State == "running" {
				if err := w.stage("rollback_starting"); err != nil {
					return err
				}
				continue
			}
			if process.State == "running" {
				if current != i.Target {
					return errors.New("不能停止未知 Agent 选择")
				}
				if _, err := installationSystemctl(ctx, "stop", "nginxpanel-agent.service"); err != nil {
					return err
				}
				process, err = w.observe(ctx, current)
				if err != nil {
					return err
				}
			}
			if process.State != "stopped" {
				return errors.New("Agent 候选停止未确认，保留恢复依据")
			}
			if err := w.stage("rollback_selecting"); err != nil {
				return err
			}
		case "rollback_selecting":
			process, err := w.observe(ctx, current)
			if err != nil {
				return err
			}
			if process.State != "stopped" {
				return errors.New("Agent 恢复选择前仍有进程运行")
			}
			if err := selectAgentProgram(w.r.OperationID, i.Target, i.Before); err != nil {
				return err
			}
			if err := w.stage("rollback_starting"); err != nil {
				return err
			}
		case "rollback_starting":
			if current != i.Before {
				return errors.New("Agent 恢复启动指针不是原版本")
			}
			process, err := w.observe(ctx, i.Before)
			if err != nil {
				return err
			}
			if process.State == "stopped" {
				if _, err := installationSystemctl(ctx, "reset-failed", "nginxpanel-agent.service"); err != nil {
					return err
				}
				if _, err := installationSystemctl(ctx, "start", "nginxpanel-agent.service"); err != nil {
					return err
				}
			}
			ready, epoch, err := w.ready(ctx, i.Before)
			if err != nil {
				return err
			}
			if err := w.guard(ctx, false); err != nil {
				return err
			}
			if current, err := w.pointer(); err != nil || current != i.Before {
				return errors.Join(err, errors.New("Agent 原版本就绪后指针偏离"))
			}
			w.r.AgentUpgrade.RollbackReady, w.r.AgentUpgrade.ReadyEpoch = &ready, epoch
			w.r.State, w.r.Stage, w.r.Error = "rolled_back", "compensated", w.r.AgentUpgrade.Failure
			return w.save()
		default:
			return errors.New("Agent 补偿阶段无法确认")
		}
	}
}

func RunAgentUpgrade(ctx context.Context, data, id string) (Record, error) {
	j, unlock, err := agentUpgradeLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := AgentUpgradeStatus(data, id)
	if err != nil || agentUpgradeTerminal(r) {
		return r, err
	}
	worker, err := panelProcFile("/proc/self/cgroup", 8192)
	if err != nil {
		return r, err
	}
	owned := false
	for _, line := range strings.Split(strings.TrimSpace(string(worker)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		owned = owned || len(parts) == 3 && parts[2] == "/system.slice/"+agentUpgradeUnit(id)
	}
	if !owned {
		return r, errors.New("Agent 升级 worker 必须由独立 systemd 实例运行")
	}
	actual, err := agentUpgradeProperties(ctx, agentUpgradeUnit(id), "MainPID")
	if err != nil {
		return r, err
	}
	if actual["MainPID"] != fmt.Sprint(os.Getpid()) {
		return r, errors.New("Agent 升级 worker 不是独立服务的主进程")
	}
	service, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return r, err
	}
	defer service()
	w := &agentUpgradeWorker{j: j, r: r}
	if a := w.r.AgentUpgrade.Authorizations; len(a) != 0 {
		last := &a[len(a)-1]
		if last.ClaimedAt != 0 || last.Request.AuthorizationUntil <= time.Now().Unix() {
			return r, errors.New("Agent 升级启动授权已使用或过期，须显式续办")
		}
		access, err := panelUpdateAccess(ctx, j, id, last.Request.Input.MaintenanceID, last.Request.Epoch, false)
		if err != nil {
			return r, err
		}
		last.ClaimedAt = time.Now().Unix()
		if last.ClaimedAt >= last.Request.AuthorizationUntil {
			access()
			return r, errors.New("Agent 升级授权在领取前过期")
		}
		err = w.save()
		access()
		if err != nil {
			return r, err
		}
	}
	if !w.r.AgentUpgrade.Rollback {
		forward, cancel := context.WithDeadline(ctx, time.Unix(r.AgentUpgrade.Intent.Deadline, 0))
		err = w.forward(forward)
		cancel()
		if err == nil {
			return w.r, nil
		}
		if agentUpgradeTerminal(w.r) {
			// A terminal rename may have succeeded before its fsync failed.
			// Report the retained record; never overwrite a possible commit.
			actual, readErr := AgentUpgradeStatus(data, id)
			return actual, errors.Join(err, readErr)
		}
		w.r.AgentUpgrade.Rollback, w.r.AgentUpgrade.Failure = true, panelRestoreError(err)
		if err = w.stage("rollback_stopping"); err != nil {
			return w.r, err
		}
	}
	// Compensation survives the caller and the original forward deadline.
	recovery, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err = w.compensate(recovery); err != nil {
		if agentUpgradeTerminal(w.r) {
			actual, readErr := AgentUpgradeStatus(data, id)
			return actual, errors.Join(err, readErr)
		}
		w.r.State, w.r.Error = "recovery_required", panelRestoreError(err)
		return w.r, errors.Join(err, w.save())
	}
	return w.r, nil
}
