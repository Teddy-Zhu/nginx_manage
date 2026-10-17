package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/nginxruntime"
)

// SwitchNginx runs outside the Agent service it controls. A resume consumes the
// original local snapshot; it cannot introduce another source or maintenance ID.
func SwitchNginx(ctx context.Context, opts NginxSwitchOptions) (Record, error) {
	var r Record
	if os.Geteuid() != 0 || !validID(opts.OperationID) || !validID(opts.Epoch) || opts.Resume && opts.Rollback {
		return r, errors.New("独立 Nginx 切换参数无效")
	}
	if _, err := installationExecutable(); err != nil {
		return r, err
	}
	cgroup, err := panelProcFile("/proc/self/cgroup", 8192)
	if err != nil {
		return r, err
	}
	if strings.Contains(string(cgroup), "/nginxpanel-agent.service") || strings.Contains(string(cgroup), "/nginxpanel-nginx.service") {
		return r, errors.New("组件切换必须运行在 Agent 与 Nginx 服务之外")
	}
	continuation := opts.Resume || opts.Rollback
	if !continuation {
		in := opts.Input
		if !validID(in.MaintenanceID) || !in.AllowDowntime || in.Source.Binary != "" || in.Source.Uninstalled || in.Source.PlanID == "" || in.Source.AssetID == "" || opts.DataDir != in.Source.DataDir {
			return r, errors.New("切换须指定签名准备资产、已持有维护会话并明确允许 Nginx 停机")
		}
		if err = in.Source.Validate(); err != nil {
			return r, err
		}
	} else if opts.Input != (NginxSwitchInput{}) {
		return r, errors.New("续办或补偿不能替换原切换输入")
	}
	j := &Journal{Dir: filepath.Join(opts.DataDir, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".nginx-switch.lock")
	if err != nil {
		return r, err
	}
	defer unlock()
	access, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return r, err
	}
	r, err = ReadNginxSwitch(opts.DataDir, opts.OperationID)
	if err == nil {
		if !continuation && r.NginxSwitch.Input != opts.Input {
			access()
			return r, errors.New("操作标识已用于不同的组件切换")
		}
		if nginxSwitchTerminal(r.State) {
			access()
			return r, nil
		}
		if !continuation {
			access()
			return r, errors.New("原切换尚未结束，须按原操作明确续办或补偿")
		}
	} else if os.IsNotExist(err) && !continuation {
		if err = installGrant(j, opts.Input.MaintenanceID, opts.Epoch, false); err == nil {
			admission, cancel := context.WithTimeout(ctx, 2*time.Minute)
			r, err = admitNginxSwitch(admission, j, opts)
			cancel()
		}
	} else if os.IsNotExist(err) {
		err = errors.New("原组件切换记录不存在，不能重新创建")
	}
	if err != nil {
		access()
		return r, err
	}
	if err = installGrant(j, r.NginxSwitch.Input.MaintenanceID, opts.Epoch, continuation && r.NginxSwitch.Touched); err != nil {
		access()
		return r, err
	}
	r.MaintenanceEpoch = opts.Epoch
	if opts.Rollback {
		r.NginxSwitch.Rollback = true
	}
	if r.NginxSwitch.Rollback {
		r.State = "compensating"
	} else {
		r.State = "running"
	}
	err = j.Put(r)
	access()
	if err != nil {
		return r, err
	}

	if !r.NginxSwitch.Rollback {
		call, cancel := context.WithDeadline(ctx, time.Unix(r.Deadline, 0))
		err = executeNginxSwitch(call, j, &r)
		cancel()
		if err == nil {
			r.State, r.Stage, r.Error = "succeeded", "committed", ""
			return r, j.Put(r)
		}
		r.Error = err.Error()
		if !r.NginxSwitch.Touched {
			r.State = "failed"
			return r, errors.Join(err, j.Put(r))
		}
		r.NginxSwitch.Rollback, r.State = true, "compensating"
		if put := j.Put(r); put != nil {
			return r, errors.Join(err, put)
		}
	}
	// A bounded independent context permits compensation after cancellation or
	// the forward deadline. A new process must explicitly resume this record.
	rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Minute)
	defer cancel()
	if failure := executeNginxSwitch(rollback, j, &r); failure != nil {
		r.State = "recovery_required"
		r.Error = errors.Join(err, failure).Error()
		return r, errors.Join(failure, j.Put(r))
	}
	r.State, r.Stage = "rolled_back", "rollback_confirmed"
	return r, j.Put(r)
}

func admitNginxSwitch(ctx context.Context, j *Journal, opts NginxSwitchOptions) (Record, error) {
	var r Record
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return r, err
	}
	for _, prior := range records {
		if prior.Kind == "maintenance.lock" {
			continue
		}
		if prior.Kind == panelUpdateKind {
			settled, e := settledPanelUpdate(prior, opts.Input.MaintenanceID)
			if e != nil {
				return r, e
			}
			if settled {
				continue
			}
		}
		switch prior.State {
		case "succeeded", "failed", "rolled_back", "cancelled":
		default:
			return r, errors.New("其他副作用操作尚未结束，不能切换 Nginx 组件")
		}
	}
	before, _, err := nginxruntime.Read(ctx, opts.DataDir)
	if err != nil {
		return r, err
	}
	candidate, err := nginxruntime.Admit(ctx, opts.Input.Source)
	if err != nil {
		return r, err
	}
	if candidate.SHA256 == before.SHA256 {
		return r, errors.New("候选与当前 Nginx 程序相同，无需切换")
	}
	n := &Nginx{DataDir: opts.DataDir, Binary: before.Binary, WorkerUser: "nginxpanel-nginx", Journal: j}
	if err = n.setup(); err != nil {
		return r, err
	}
	dir, m, err := n.active()
	if err != nil {
		return r, err
	}
	if len(m.Modules) != 0 {
		return r, errors.New("活动配置绑定动态模块，须先发布使用目标预置能力的配置")
	}
	i := NginxSwitchIntent{Input: opts.Input, Before: before, Candidate: candidate, Directory: dir, RevisionID: m.RevisionID, PublicationSHA256: manifestHash(m), Units: map[string]string{}}
	for _, unit := range []string{"nginxpanel-nginx.service", "nginxpanel-agent.service"} {
		i.Units[unit], err = switchUnitDigest(ctx, opts.DataDir, unit)
		if err != nil {
			return r, err
		}
	}
	r = Record{OperationID: opts.OperationID, Kind: nginxSwitchKind, NginxSwitch: &i, MaintenanceEpoch: opts.Epoch, State: "running", Stage: "validated", Deadline: time.Now().Add(10 * time.Minute).Unix()}
	r.RequestHash = nginxSwitchHash(r.OperationID, i)
	for _, unit := range []string{"nginxpanel-nginx.service", "nginxpanel-agent.service"} {
		state, e := switchService(ctx, r, unit)
		if e != nil {
			return Record{}, e
		}
		if !state.Running {
			return Record{}, errors.New("组件切换要求原专用 Nginx 与 Agent 已正常运行")
		}
	}
	if err = n.observe(ctx, m); err != nil {
		return Record{}, err
	}
	n.Binary = candidate.Binary
	if err = n.test(ctx, dir); err != nil {
		return Record{}, errors.New("候选 Nginx 无法通过当前完整运行配置校验")
	}
	features := n.Features(ctx)
	if !features.Available || features.Version != candidate.Version {
		return Record{}, errors.New("候选 Nginx 的实际编译版本未确认")
	}
	return r, validNginxSwitch(r)
}

func nginxSwitchStage(ctx context.Context, j *Journal, r *Record, stage string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer unlock()
	// Restarted Agent instances reopen the same durable session in closing
	// state. The admitted owner may finish or compensate while it drains again.
	if err = installGrant(j, r.NginxSwitch.Input.MaintenanceID, "", true); err != nil {
		return err
	}
	r.Stage = stage
	return j.Put(*r)
}

func switchPublication(n *Nginx, r Record) (manifest, error) {
	dir, m, err := n.active()
	if err != nil {
		return m, err
	}
	i := r.NginxSwitch
	if dir != i.Directory || manifestHash(m) != i.PublicationSHA256 || len(m.Modules) != 0 {
		return m, errors.New("运行发布已偏离原切换快照，停止控制服务")
	}
	return m, nil
}

func executeNginxSwitch(ctx context.Context, j *Journal, r *Record) error {
	i := r.NginxSwitch
	data := i.Input.Source.DataDir
	prefix := ""
	target := i.Candidate
	if i.Rollback {
		prefix, target = "rollback_", i.Before
	}
	i.Confirmation = nil
	current, err := nginxruntime.SwitchedSelection(data, r.OperationID, i.Before, i.Candidate)
	if err != nil {
		return err
	}
	if err = nginxruntime.VerifyRetained(ctx, i.Before); err != nil {
		return err
	}
	if !i.Rollback {
		candidate, e := nginxruntime.Admit(ctx, i.Input.Source)
		if e != nil {
			return e
		}
		if nginxruntime.CandidateHash(candidate) != nginxruntime.CandidateHash(i.Candidate) {
			return errors.New("候选组件已偏离原准入记录")
		}
	}
	n := &Nginx{DataDir: data, Binary: i.Before.Binary, WorkerUser: "nginxpanel-nginx", Journal: j}
	if err = n.setup(); err != nil {
		return err
	}
	m, err := switchPublication(n, *r)
	if err != nil {
		return err
	}
	selectedTarget := nginxruntime.CandidateHash(current) == nginxruntime.CandidateHash(target)
	if selectedTarget {
		// A lost final response never requires another service restart. Validate
		// current files before executing anything from the selected runtime.
		if _, _, err = nginxruntime.Selection(ctx, data); err != nil {
			return err
		}
		n.Binary = target.Binary
		proxy, e := switchService(ctx, *r, "nginxpanel-nginx.service")
		if e != nil {
			return e
		}
		agent, e := switchService(ctx, *r, "nginxpanel-agent.service")
		if e != nil {
			return e
		}
		if proxy.Running && agent.Running && n.observe(ctx, m) == nil {
			return confirmNginxSwitch(ctx, n, r, target, m)
		}
	}
	i.Touched = true
	if err = switchControl(ctx, j, r, "nginxpanel-agent.service", "stop", prefix+"stopping_agent"); err != nil {
		return err
	}
	// The stopped Agent releases its executor lock. Holding it across Nginx
	// control keeps all configuration and component writes outside this window.
	n.Binary = i.Before.Binary
	if err = n.Open(); err != nil {
		return err
	}
	defer n.Close()
	if m, err = switchPublication(n, *r); err != nil {
		return err
	}
	current, err = nginxruntime.SwitchedSelection(data, r.OperationID, i.Before, i.Candidate)
	if err != nil {
		return err
	}
	selectedTarget = nginxruntime.CandidateHash(current) == nginxruntime.CandidateHash(target)
	proxy, err := switchService(ctx, *r, "nginxpanel-nginx.service")
	if err != nil {
		return err
	}
	// If the target is already running and its exact publication is observable,
	// only finish Agent confirmation. Otherwise explicitly stop the owned unit.
	n.Binary = target.Binary
	observed := selectedTarget && proxy.Running && n.observe(ctx, m) == nil
	if !observed {
		if err = switchControl(ctx, j, r, "nginxpanel-nginx.service", "stop", prefix+"stopping_nginx"); err != nil {
			return err
		}
		if err = nginxSwitchStage(ctx, j, r, prefix+"binding"); err != nil {
			return err
		}
		if i.Rollback {
			_, err = nginxruntime.RestoreSwitched(ctx, r.OperationID, i.Before, i.Candidate)
		} else {
			_, err = nginxruntime.SwitchPrepared(ctx, i.Input.Source, r.OperationID, i.Before, i.Candidate)
		}
		if err != nil {
			return err
		}
		if _, _, err = nginxruntime.Selection(ctx, data); err != nil {
			return err
		}
		if _, err = switchPublication(n, *r); err != nil {
			return err
		}
		if err = n.test(ctx, i.Directory); err != nil {
			return err
		}
		if err = switchControl(ctx, j, r, "nginxpanel-nginx.service", "start", prefix+"starting_nginx"); err != nil {
			return err
		}
	}
	if err = nginxSwitchStage(ctx, j, r, prefix+"confirming_nginx"); err != nil {
		return err
	}
	confirmation, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = n.waitObserved(confirmation, m)
	cancel()
	if err != nil {
		return err
	}
	if _, err = switchPublication(n, *r); err != nil {
		return err
	}
	n.Close()
	if err = switchControl(ctx, j, r, "nginxpanel-agent.service", "start", prefix+"starting_agent"); err != nil {
		return err
	}
	if err = nginxSwitchStage(ctx, j, r, prefix+"confirming_agent"); err != nil {
		return err
	}
	return confirmNginxSwitch(ctx, n, r, target, m)
}

func confirmNginxSwitch(ctx context.Context, n *Nginx, r *Record, target nginxruntime.Binding, m manifest) error {
	if features := n.Features(ctx); !features.Available || features.Version != target.Version {
		return errors.New("实际 Nginx 编译版本与已选择组件不同")
	}
	probe, err := waitNativeNginxProbe(ctx, n.DataDir, target, true, m.RevisionID, m.DeploymentID)
	if err != nil {
		return err
	}
	selected, _, err := nginxruntime.Selection(ctx, n.DataDir)
	if err != nil {
		return err
	}
	if r.NginxSwitch.Rollback && nginxruntime.SelectionHash(selected) != nginxruntime.SelectionHash(target) || !r.NginxSwitch.Rollback && (selected.OperationID != r.OperationID || nginxruntime.CandidateHash(selected) != nginxruntime.CandidateHash(target)) {
		return errors.New("确认时当前组件不再属于原切换")
	}
	if _, err = switchPublication(n, *r); err != nil {
		return err
	}
	proxy, err := switchService(ctx, *r, "nginxpanel-nginx.service")
	if err != nil {
		return err
	}
	agent, err := switchService(ctx, *r, "nginxpanel-agent.service")
	if err != nil {
		return err
	}
	if !proxy.Running || !agent.Running {
		return errors.New("确认时原生服务已停止")
	}
	if err = n.observe(ctx, m); err != nil {
		return err
	}
	r.NginxSwitch.Confirmation = &NginxSwitchConfirmation{ConfirmedAt: time.Now().Unix(), BinarySHA256: target.SHA256, Version: target.Version, AgentPID: agent.PID, NginxPID: proxy.PID, Runtime: probe.Runtime}
	r.ObservedRevision = m.RevisionID
	return nil
}
