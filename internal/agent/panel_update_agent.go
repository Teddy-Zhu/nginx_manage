package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/protocol"
)

type CoordinatedAgentIntent struct {
	Before         AgentProgram `json:"before"`
	Target         AgentProgram `json:"target"`
	BeforeProcess  AgentProcess `json:"before_process"`
	BeforeProtocol int          `json:"before_protocol"`
	TargetProtocol int          `json:"target_protocol"`
	Launcher       int          `json:"launcher"`
	AgentUnit      string       `json:"agent_unit"`
}

type CoordinatedAgentLeg struct {
	StopIssued    bool          `json:"stop_issued"`
	StopSequence  int           `json:"stop_sequence"`
	Stopped       bool          `json:"stopped"`
	Selected      bool          `json:"selected"`
	StartIssued   bool          `json:"start_issued"`
	StartSequence int           `json:"start_sequence"`
	Process       *AgentProcess `json:"process,omitempty"`
	StopProcess   *AgentProcess `json:"stop_process,omitempty"`
	Ready         bool          `json:"ready"`
}

type CoordinatedAgentState struct {
	Forward  CoordinatedAgentLeg     `json:"forward"`
	Rollback CoordinatedAgentLeg     `json:"rollback"`
	Epoch    string                  `json:"epoch"`
	Rescue   *CoordinatedAgentRescue `json:"rescue,omitempty"`
}

type CoordinatedAgentRescue struct {
	Program      AgentProgram `json:"program"`
	Process      AgentProcess `json:"process"`
	AuthorizedAt int64        `json:"authorized_at"`
}

func validCoordinatedAgent(r Record) error {
	p := r.PanelUpdate
	i, a := p.Intent, p.Intent.Agent
	if !i.Input.CoordinateAgent {
		if i.Input.AllowDowntime || a != nil || p.Agent != nil {
			return errors.New("普通更新不能包含协调 Agent 状态")
		}
		return nil
	}
	if !i.Input.AllowDowntime || a == nil || p.Agent == nil || !agentProgramValid(a.Before) || !agentProgramValid(a.Target) || a.Before == a.Target || !agentProcessValid(a.BeforeProcess) || a.BeforeProtocol <= 0 || a.TargetProtocol <= 0 || a.Launcher <= 0 || !panelSelectionDigest.MatchString(a.AgentUnit) || !validID(p.Agent.Epoch) || p.Agent.Epoch != r.MaintenanceEpoch {
		return errors.New("协调更新的 Agent 意图或维护身份无效")
	}
	for _, leg := range []*CoordinatedAgentLeg{&p.Agent.Forward, &p.Agent.Rollback} {
		if leg.Selected && !leg.Stopped || leg.StartIssued && !leg.Selected || leg.Process != nil && !agentProcessValid(*leg.Process) || leg.StopProcess != nil && !agentProcessValid(*leg.StopProcess) || leg.Ready && leg.Process == nil || leg.StopSequence < 0 || leg.StopSequence > len(p.Authorizations) || leg.StartSequence < 0 || leg.StartSequence > len(p.Authorizations) {
			return errors.New("协调更新的 Agent 步骤证据无效")
		}
	}
	if rescue := p.Agent.Rescue; rescue != nil {
		if rescue.Program != a.Before && rescue.Program != a.Target || !agentProcessValid(rescue.Process) || rescue.Process.BootID == a.BeforeProcess.BootID || rescue.AuthorizedAt <= 0 || rescue.AuthorizedAt > time.Now().Unix()+300 || p.Failure == "" {
			return errors.New("协调更新的本机重启救援依据无效")
		}
	}
	if r.Stage == "committed" && !p.Agent.Forward.Ready || r.Stage == "compensated" && !p.Agent.Rollback.Ready {
		return errors.New("协调更新终态缺少 Agent 就绪证据")
	}
	return nil
}

func prepareCoordinatedAgent(ctx context.Context, in PanelUpdateInput, before panelruntime.Snapshot, target panelruntime.StagedRelease, id string) (*CoordinatedAgentIntent, error) {
	if !in.AllowDowntime || before.Release.AgentProtocol != Protocol || target.Release.LauncherVersion != before.Release.LauncherVersion {
		return nil, errors.New("协调升级须明确允许停机，并先满足当前 launcher 协议；跨 launcher 协议须先完成基础部署")
	}
	if _, err := installationExecutable(); err != nil {
		return nil, err
	}
	original, err := readAgentProgram()
	if err != nil {
		return nil, err
	}
	if original.BinarySHA256 == target.Release.BinarySHA256 {
		return nil, errors.New("协调更新的 Agent 已使用目标程序")
	}
	unit, _, _, err := agentUpgradeUnits(ctx, in.Stage.DataDir, id)
	if err != nil {
		return nil, err
	}
	process, err := agentUpgradeObserve(ctx, in.Stage.DataDir, id, original)
	if err != nil || !agentProcessValid(process) {
		return nil, errors.Join(err, errors.New("协调更新要求原 Agent 正常运行"))
	}
	program, err := publishAgentProgram(ctx, filepath.Join(target.Directory, "nginxpanel"), target.Release.BinarySHA256)
	if err != nil {
		return nil, err
	}
	return &CoordinatedAgentIntent{Before: original, Target: program, BeforeProcess: process, BeforeProtocol: Protocol, TargetProtocol: target.Release.AgentProtocol, Launcher: target.Release.LauncherVersion, AgentUnit: unit}, nil
}

func (w *panelUpdateWorker) agentGuard(ctx context.Context) (AgentProgram, error) {
	i := w.r.PanelUpdate.Intent
	a := i.Agent
	if a == nil {
		return AgentProgram{}, errors.New("缺少协调 Agent 意图")
	}
	s, err := w.current()
	if err != nil {
		return AgentProgram{}, err
	}
	if err = w.requireHold(); err != nil {
		return AgentProgram{}, err
	}
	o, err := observePanelService(ctx, s)
	if err != nil || o.State != "stopped" {
		return AgentProgram{}, errors.Join(err, errors.New("协调 Agent 切换前面板必须保持原事务停机"))
	}
	unit, _, _, err := agentUpgradeUnits(ctx, i.Input.Stage.DataDir, w.r.OperationID)
	if err != nil || unit != a.AgentUnit {
		return AgentProgram{}, errors.Join(err, errors.New("协调 Agent 服务定义已变化"))
	}
	for _, p := range []AgentProgram{a.Before, a.Target} {
		if err = checkAgentProgram(p); err != nil {
			return AgentProgram{}, err
		}
	}
	current, err := readAgentProgram()
	if err == nil && current != a.Before && current != a.Target {
		err = errors.New("协调 Agent 选择偏离原程序与目标程序")
	}
	return current, err
}

// The helper belongs to the program being probed, so the independent worker
// never speaks a different Agent wire protocol or expands the Unix peer ACL.
func (w *panelUpdateWorker) agentEpoch(ctx context.Context, program AgentProgram, process AgentProcess) error {
	i := w.r.PanelUpdate.Intent
	call, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		status, err := probeAgentUpgrade(call, i.Input.Stage.DataDir, i.Input.MaintenanceID, program)
		after, observed := agentUpgradeObserve(call, i.Input.Stage.DataDir, w.r.OperationID, program)
		if observed != nil || after != process {
			return errors.Join(observed, errors.New("协调 Agent 维护核对期间进程变化"))
		}
		if err == nil {
			w.epoch, w.r.MaintenanceEpoch, w.r.PanelUpdate.Agent.Epoch = status.Epoch, status.Epoch, status.Epoch
			return w.save()
		}
		select {
		case <-call.Done():
			return errors.Join(call.Err(), err)
		case <-time.After(time.Second):
		}
	}
}

func (w *panelUpdateWorker) coordinateAgent(ctx context.Context, rollback bool) error {
	i, state := w.r.PanelUpdate.Intent, w.r.PanelUpdate.Agent
	if i.Agent == nil {
		return nil
	}
	if !rollback {
		if err := w.approved(ctx); err != nil {
			return err
		}
	}
	a := i.Agent
	sequence := len(w.r.PanelUpdate.Authorizations)
	from, to, leg := a.Before, a.Target, &state.Forward
	if rollback {
		from, to, leg = a.Target, a.Before, &state.Rollback
	}
	current, err := w.agentGuard(ctx)
	if err != nil {
		return err
	}
	process, err := agentUpgradeObserve(ctx, i.Input.Stage.DataDir, w.r.OperationID, current)
	if err != nil {
		return err
	}
	if process.State == "running" {
		known := current == a.Before && process == a.BeforeProcess || state.Forward.Process != nil && current == a.Target && process == *state.Forward.Process || state.Rollback.Process != nil && current == a.Before && process == *state.Rollback.Process || state.Rescue != nil && current == state.Rescue.Program && process == state.Rescue.Process
		// A failed candidate may have restarted under the exact frozen service.
		// Only compensation can stop that same-boot, explicitly started target.
		if !known && rollback && current == a.Target && state.Forward.StartIssued && process.BootID == a.BeforeProcess.BootID {
			leg.StopProcess = &process
			if err = w.save(); err != nil {
				return err
			}
			known = true
		}
		if !known && current == a.Target && state.Forward.StartIssued && state.Forward.Process == nil && process.BootID == a.BeforeProcess.BootID {
			state.Forward.Process = &process
			if err = w.save(); err != nil {
				return err
			}
			known = true
		}
		if !known && current == a.Before && state.Rollback.StartIssued && state.Rollback.Process == nil && process.BootID == a.BeforeProcess.BootID {
			state.Rollback.Process = &process
			if err = w.save(); err != nil {
				return err
			}
			known = true
		}
		if !known {
			return errors.New("协调 Agent 的运行代次不属于原进程或已派发启动，须本机核对")
		}
		if rollback && current != to {
			if err = w.refreshCoordinatedEpoch(ctx, true); err != nil {
				return err
			}
		} else if err = w.agentEpoch(ctx, current, process); err != nil {
			return err
		}
		if current == to {
			leg.Process, leg.Ready = &process, true
			return w.save()
		}
	}
	if current != from && current != to {
		return errors.New("协调 Agent 来源无效")
	}
	if process.State == "running" {
		if leg.StopIssued && sequence <= leg.StopSequence {
			return errors.New("协调 Agent 停机请求结果不明，禁止重放")
		}
		access, e := w.access(ctx, rollback)
		if e != nil {
			return e
		}
		leg.StopIssued, leg.StopSequence = true, sequence
		err = w.save()
		if err == nil {
			_, err = installationSystemctl(ctx, "stop", "nginxpanel-agent.service")
		}
		access()
		if err != nil {
			return err
		}
	}
	current, err = w.agentGuard(ctx)
	if err != nil {
		return err
	}
	process, err = agentUpgradeObserve(ctx, i.Input.Stage.DataDir, w.r.OperationID, current)
	if err != nil || process.State != "stopped" {
		return errors.Join(err, errors.New("协调 Agent 尚未确认停机"))
	}
	leg.Stopped = true
	if err = w.save(); err != nil {
		return err
	}
	if current != to {
		if !rollback {
			if err = w.approved(ctx); err != nil {
				return err
			}
		}
		access, e := w.access(ctx, true)
		if e != nil {
			return e
		}
		err = selectAgentProgram(w.r.OperationID, from, to)
		access()
		if err != nil {
			return err
		}
	}
	leg.Selected = true
	if err = w.save(); err != nil {
		return err
	}
	if leg.StartIssued && sequence <= leg.StartSequence {
		return errors.New("协调 Agent 启动已派发但尚未观测运行，须查询原事务，禁止重放")
	}
	if !rollback {
		if err = w.approved(ctx); err != nil {
			return err
		}
	}
	leg.StartIssued, leg.StartSequence = true, sequence
	if err = w.save(); err != nil {
		return err
	}
	// No maintenance-access lock may be held across the new Agent's open/probe.
	if _, err = installationSystemctl(ctx, "reset-failed", "nginxpanel-agent.service"); err != nil {
		return err
	}
	if _, err = installationSystemctl(ctx, "start", "nginxpanel-agent.service"); err != nil {
		return err
	}
	process, err = agentUpgradeObserve(ctx, i.Input.Stage.DataDir, w.r.OperationID, to)
	if err != nil || !agentProcessValid(process) {
		return errors.Join(err, errors.New("协调 Agent 启动代次未确认"))
	}
	leg.Process = &process
	if err = w.save(); err != nil {
		return err
	}
	if err = w.agentEpoch(ctx, to, process); err != nil {
		return err
	}
	leg.Ready = true
	return w.save()
}

func (w *panelUpdateWorker) refreshCoordinatedEpoch(ctx context.Context, closing bool) error {
	i := w.r.PanelUpdate.Intent
	if i.Agent == nil {
		return nil
	}
	unlock, err := w.j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = installGrantForOperation(w.j, i.Input.MaintenanceID, "", closing, w.r.OperationID); err != nil {
		return err
	}
	grant, err := w.j.Get(i.Input.MaintenanceID)
	if err != nil {
		return err
	}
	if w.epoch != grant.MaintenanceEpoch || w.r.MaintenanceEpoch != grant.MaintenanceEpoch {
		w.epoch, w.r.MaintenanceEpoch, w.r.PanelUpdate.Agent.Epoch = grant.MaintenanceEpoch, grant.MaintenanceEpoch, grant.MaintenanceEpoch
		return w.save()
	}
	return nil
}

func (w *panelUpdateWorker) checkCoordinatedReady(ctx context.Context, rollback bool) error {
	i := w.r.PanelUpdate.Intent
	if i.Agent == nil {
		return nil
	}
	state := w.r.PanelUpdate.Agent
	program, leg := i.Agent.Target, state.Forward
	if rollback {
		program, leg = i.Agent.Before, state.Rollback
	}
	current, err := readAgentProgram()
	if err != nil || current != program || !leg.Ready || leg.Process == nil {
		return errors.Join(err, errors.New("协调 Agent 的已确认程序或就绪证据缺失"))
	}
	unit, _, _, err := agentUpgradeUnits(ctx, i.Input.Stage.DataDir, w.r.OperationID)
	if err != nil || unit != i.Agent.AgentUnit {
		return errors.Join(err, errors.New("协调 Agent 就绪时服务定义已变化"))
	}
	process, err := agentUpgradeObserve(ctx, i.Input.Stage.DataDir, w.r.OperationID, program)
	if err != nil || process != *leg.Process {
		return errors.Join(err, errors.New("协调 Agent 就绪代次已变化"))
	}
	status, err := probeAgentUpgrade(ctx, i.Input.Stage.DataDir, i.Input.MaintenanceID, program)
	if err != nil || status.Epoch != state.Epoch || status.Epoch != w.epoch {
		return errors.Join(err, errors.New("协调 Agent 与应用的维护 epoch 不一致"))
	}
	return nil
}

func (w *panelUpdateWorker) checkCoordinatedAbort(ctx context.Context) error {
	i := w.r.PanelUpdate.Intent
	if i.Agent == nil {
		return nil
	}
	current, err := readAgentProgram()
	if err != nil || current != i.Agent.Before {
		return errors.Join(err, errors.New("无副作用中止前原 Agent 选择已变化"))
	}
	process, err := agentUpgradeObserve(ctx, i.Input.Stage.DataDir, w.r.OperationID, current)
	rescue := w.r.PanelUpdate.Agent.Rescue
	if err != nil || process != i.Agent.BeforeProcess && !(rescue != nil && rescue.Program == current && rescue.Process == process) {
		return errors.Join(err, errors.New("无副作用中止前原 Agent 进程已变化"))
	}
	return nil
}

// Only the local root rescue path may register a new boot generation. The
// original intent remains immutable and every such registration forces rollback.
func registerCoordinatedBootRescue(ctx context.Context, data string, r *Record) error {
	p, a := r.PanelUpdate, r.PanelUpdate.Intent.Agent
	if a == nil {
		return nil
	}
	current, err := readAgentProgram()
	if err != nil || current != a.Before && current != a.Target {
		return errors.Join(err, errors.New("本机救援的 Agent 程序不属于原协调事务"))
	}
	unit, _, _, err := agentUpgradeUnits(ctx, data, r.OperationID)
	if err != nil || unit != a.AgentUnit {
		return errors.Join(err, errors.New("本机救援的 Agent 服务定义已变化"))
	}
	process, err := agentUpgradeObserve(ctx, data, r.OperationID, current)
	if err != nil {
		return err
	}
	if process.State == "stopped" && p.Snapshot != nil {
		if p.Failure == "" {
			p.Failure = "本机救援确认 Agent 已停止，恢复原程序与数据"
		}
		r.State, r.Stage = "compensating", "rollback_stopping"
		return nil
	}
	if process.State != "running" || process.BootID == a.BeforeProcess.BootID || p.Agent.Rescue != nil && p.Agent.Rescue.Program == current && p.Agent.Rescue.Process == process {
		return nil
	}
	p.Agent.Rescue = &CoordinatedAgentRescue{Program: current, Process: process, AuthorizedAt: time.Now().Unix()}
	if p.Failure == "" {
		p.Failure = "本机重启后的协调部署只允许恢复原程序与数据"
	}
	if p.Snapshot != nil {
		r.State, r.Stage = "compensating", "rollback_stopping"
	}
	return nil
}

type DeploymentInspection struct {
	Protocol      int    `json:"protocol"`
	Journal       int    `json:"journal"`
	MaintenanceID string `json:"maintenance_id"`
	Epoch         string `json:"epoch"`
}

func InspectDeploymentUpgrade(ctx context.Context, data, maintenanceID string) (DeploymentInspection, error) {
	var out DeploymentInspection
	if os.Geteuid() != 0 || !validID(maintenanceID) {
		return out, errors.New("协调部署检查需要 root 和原维护 UUID")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	r, err := j.Get(maintenanceID)
	if err != nil || r.Kind != "maintenance.lock" || r.RequestHash != maintenanceHashForID(maintenanceID) || r.State != "waiting_confirmation" || r.Stage != "held" || !validID(r.MaintenanceEpoch) {
		return out, errors.Join(err, errors.New("协调部署检查缺少已排空的原维护会话"))
	}
	g := &maintenanceGate{journal: j, scope: "host", id: maintenanceID, phase: "held", epoch: r.MaintenanceEpoch}
	s, err := g.statusLocked(ctx)
	if err != nil || s.Busy != 0 {
		return out, errors.Join(err, errors.New("目标程序不能确认现有独立日志或仍有冲突任务"))
	}
	if err = components.InspectRecords(filepath.Join(data, "agent", "components")); err != nil {
		return out, err
	}
	return DeploymentInspection{Protocol: Protocol, Journal: protocol.Journal, MaintenanceID: maintenanceID, Epoch: r.MaintenanceEpoch}, nil
}

func (w *panelUpdateWorker) inspectTargetAgent(ctx context.Context) error {
	i := w.r.PanelUpdate.Intent
	if i.Agent == nil {
		return nil
	}
	if err := w.approved(ctx); err != nil {
		return err
	}
	if err := checkAgentProgram(i.Agent.Target); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, i.Agent.Target.binary(), "deployment-upgrade-inspect", "--data-dir", i.Input.Stage.DataDir, "--maintenance-id", i.Input.MaintenanceID)
	cmd.Env, cmd.WaitDelay = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}, time.Second
	var output serviceOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("目标程序拒绝当前独立维护日志，尚未停止服务")
	}
	var result DeploymentInspection
	if len(output.String()) > 4096 || json.Unmarshal([]byte(output.String()), &result) != nil || result.Protocol != i.Agent.TargetProtocol || result.Journal != protocol.Journal || result.MaintenanceID != i.Input.MaintenanceID || result.Epoch != w.epoch {
		return errors.New("目标程序的协调部署检查回执不一致")
	}
	return nil
}
