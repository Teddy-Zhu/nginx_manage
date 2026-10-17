package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const ufwPreparationSeconds = 300

type ufwPlanPreparation struct {
	status            firewall.PlanPreparation
	view              firewall.Plan
	cancel            context.CancelFunc
	done              chan struct{}
	persistedCommands int
	persistedAt       time.Time
}

func ufwPreparationPath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "ufw-preparation.json")
}

func validUFWPreparation(v firewall.PlanPreparation) bool {
	if !validID(v.ID) || !slices.Contains([]string{"apply", "remove"}, v.Action) || v.Version < 1 || v.CompletedCommands < 0 || v.CompletedCommands > v.TotalCommands || v.TotalCommands > 2*ufwDryRunCommands || v.StartedAt <= 0 || v.UpdatedAt < v.StartedAt || v.Deadline != v.StartedAt+ufwPreparationSeconds || len(v.Error) > 2048 {
		return false
	}
	switch v.State {
	case "running", "cancelling":
		return v.Error == ""
	case "ready":
		return v.Error == "" && v.CompletedCommands == v.TotalCommands
	case "failed", "cancelled":
		return v.Error != ""
	}
	return false
}

func saveUFWPreparation(dataDir string, status firewall.PlanPreparation) error {
	if !validUFWPreparation(status) {
		return errors.New("UFW 计划准备状态无效")
	}
	return rootJSONWrite(ufwPreparationPath(dataDir), struct {
		Schema int                      `json:"schema"`
		Status firewall.PlanPreparation `json:"status"`
	}{1, status}, 16<<10)
}

func (f *hostFirewall) openUFWPreparationLocked() error {
	raw, err := listenerRead(ufwPreparationPath(f.dataDir), 16<<10)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored struct {
		Schema int                      `json:"schema"`
		Status firewall.PlanPreparation `json:"status"`
	}
	if ufwToolJSON(raw, &stored) != nil || stored.Schema != 1 || !validUFWPreparation(stored.Status) {
		return errors.New("UFW 计划准备记录无法完整读取")
	}
	status := stored.Status
	if slices.Contains([]string{"running", "cancelling", "ready"}, status.State) {
		// Private write authority is deliberately volatile. Restart retains
		// a visible failed preparation; it never resumes or applies a plan.
		status.State, status.Error, status.UpdatedAt = "failed", "Agent 已重启，未应用计划已失效，请重新准备", time.Now().Unix()
		if err = saveUFWPreparation(f.dataDir, status); err != nil {
			return err
		}
	}
	f.ufwPreparation = &ufwPlanPreparation{status: status, view: ufwPreparationShell(status)}
	return nil
}

func ufwPreparationShell(status firewall.PlanPreparation) firewall.Plan {
	copy := status
	return firewall.Plan{Backend: "ufw", ID: status.ID, Action: status.Action, Version: status.Version, Preparation: &copy, Protections: []firewall.Protection{}, SSHListeners: []string{}, Baseline: firewall.KernelView{Reason: "UFW 计划准备尚未完成"}}
}

func (f *hostFirewall) ufwPreparingLocked() bool {
	return f.ufwPreparation != nil && slices.Contains([]string{"running", "cancelling"}, f.ufwPreparation.status.State)
}

func (f *hostFirewall) ufwPreparationViewLocked() *firewall.PlanPreparation {
	if f.ufwPreparation == nil {
		return nil
	}
	copy := f.ufwPreparation.status
	return &copy
}

func (f *hostFirewall) ufwPreparationPlanLocked(in firewall.RuntimeInput) (firewall.Plan, error) {
	if !validID(in.PreparationID) || !slices.Contains([]string{"apply", "remove"}, in.Action) || in.Version < 1 {
		return firewall.Plan{}, fault.Invalid("须提供原 UFW 准备 ID、动作和版本")
	}
	job := f.ufwPreparation
	if job == nil || job.status.ID != in.PreparationID {
		if private, ok := f.plans[in.PreparationID]; ok && private.view.Preparation != nil && !in.CancelPreparation && private.view.Action == in.Action && private.view.Version == in.Version && private.view.ExpiresAt > time.Now().Unix() {
			return private.view, nil
		}
		return firewall.Plan{}, fault.New(404, "FIREWALL_PREPARATION_MISSING", "原 UFW 准备记录不存在，请重新准备")
	}
	if job.status.Action != in.Action || job.status.Version != in.Version {
		return firewall.Plan{}, fault.Conflict("UFW 准备 ID 已绑定其他动作或版本")
	}
	if in.CancelPreparation {
		if !f.ufwPreparingLocked() || job.cancel == nil {
			return firewall.Plan{}, fault.Conflict("UFW 计划准备已经结束")
		}
		job.cancel()
		job.status.State, job.status.UpdatedAt = "cancelling", time.Now().Unix()
		if err := saveUFWPreparation(f.dataDir, job.status); err != nil {
			return firewall.Plan{}, err
		}
	}
	view := job.view
	view.Preparation = f.ufwPreparationViewLocked()
	return view, nil
}

func (f *hostFirewall) startUFWPreparationLocked(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var empty firewall.Plan
	if !f.ufwPlanning || !f.recovering || f.problem != "" || f.policyUncertain || f.state.Schema != 0 || f.firewalldState != nil || os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return empty, fault.Unavailable("UFW 计划须由本机 root 明确确认宿主机范围、所有者及 SSH 保护配置")
	}
	if !slices.Contains([]string{"apply", "remove"}, in.Action) || in.Version < 1 {
		return empty, fault.Invalid("UFW 策略动作、版本或后端无效")
	}
	if f.ufwPreparingLocked() || f.activeLocked() || ufwRestorePending(f.dataDir) || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return empty, fault.Conflict("存在未完成的可达性变更或 UFW 计划准备")
	}
	registered, err := ufwRegistrationAuthority(f.dataDir)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	confirmed, err := ufwCurrentConfirmed(f.dataDir, registered.NextClaim.Owner)
	if err != nil {
		return empty, fault.Conflict(err.Error())
	}
	policy, err := in.Policy.Normalize()
	if err != nil {
		return empty, err
	}
	if in.Action == "remove" {
		if policy.Hash() != firewall.DefaultPolicy().Hash() || confirmed == nil || confirmed.Action != "apply" || confirmed.Version != in.Version {
			return empty, fault.Conflict("UFW 移除计划须使用原确认版本且不能附带新策略")
		}
		policy = confirmed.Policy
	}
	if policy.Backend != "ufw" {
		return empty, fault.Conflict("期望策略后端与本机 UFW 选择不一致")
	}
	hash, err := firewall.PolicyDigest(policy)
	if err != nil {
		return empty, err
	}
	previous, err := ufwPolicyProgram(confirmed, registered.NextClaim.Owner)
	if err != nil {
		return empty, err
	}
	effect := policy
	if in.Action == "remove" {
		effect = firewall.DefaultPolicy()
	}
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return empty, fault.Unavailable(err.Error())
	}
	id := secure.ID()
	program, err := firewall.CompileUFWRuntime(policy, protections, in.Action, registered.NextClaim.Owner, id)
	if err != nil {
		return empty, err
	}
	now := time.Now()
	status := firewall.PlanPreparation{ID: id, Action: in.Action, Version: in.Version, State: "running", TotalCommands: len(previous.Rules) + len(program.Rules), StartedAt: now.Unix(), UpdatedAt: now.Unix(), Deadline: now.Unix() + ufwPreparationSeconds}
	view := ufwPreparationShell(status)
	view.PolicyHash, view.ProgramHash, view.GeneratedRules = hash, program.Hash, len(program.Rules)
	view.Protections, view.SSHProfile, view.SSHListeners = protections, f.sshMode, listeners
	view.ListenerVersion, view.Listener, view.ControlSource = f.remote.state.Version, f.remote.state.Confirmed.Listen, source
	view.ConfirmationSeconds, view.ExpiresAt = firewall.ConfirmationSeconds, status.Deadline
	record := firewallPolicyRecord{Action: in.Action, PlanID: id, Version: in.Version, Policy: policy, PolicyHash: hash, ProgramHash: program.Hash, Protections: protections, Marker: firewall.UFWCommentPrefix + registered.NextClaim.Owner + ":" + id + ":", ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: listeners, Listener: view.Listener, AllowedSources: slices.Clone(f.remote.state.Confirmed.AllowedSources), ControlSource: source}}
	if err = f.storePlanLocked(view, nil); err != nil {
		return empty, err
	}
	if err = saveUFWPreparation(f.dataDir, status); err != nil {
		delete(f.plans, id)
		return empty, err
	}
	call, cancel := context.WithDeadline(context.Background(), time.Unix(status.Deadline, 0))
	job := &ufwPlanPreparation{status: status, view: view, cancel: cancel, done: make(chan struct{}), persistedAt: now}
	f.ufwPreparation = job
	basis := ufwPreparationBasis{View: view, Record: record, Registration: registered, Confirmed: confirmed, Previous: previous, Program: program}
	go f.runUFWPreparation(call, job, basis)
	return view, nil
}

func (f *hostFirewall) runUFWPreparation(ctx context.Context, job *ufwPlanPreparation, basis ufwPreparationBasis) {
	defer close(job.done)
	defer job.cancel()
	progress := func(completed int) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		job.status.CompletedCommands, job.status.UpdatedAt = completed, time.Now().Unix()
		if completed-job.persistedCommands < 32 && time.Since(job.persistedAt) < time.Second {
			return nil
		}
		if err := saveUFWPreparation(f.dataDir, job.status); err != nil {
			return err
		}
		job.persistedCommands, job.persistedAt = completed, time.Now()
		return nil
	}
	private, resultErr := prepareUFWPlan(ctx, f.dataDir, basis, progress)
	f.dns.mu.Lock()
	defer f.dns.mu.Unlock()
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if resultErr == nil {
		resultErr = f.checkUFWPreparedBasisLocked(ctx, basis)
	}
	if resultErr == nil {
		job.status.State, job.status.CompletedCommands, job.status.UpdatedAt = "ready", job.status.TotalCommands, time.Now().Unix()
		status := job.status
		private.view.Preparation = &status
		resultErr = saveUFWPreparation(f.dataDir, status)
		if resultErr == nil {
			resultErr = f.storePlanLocked(private.view, private.record)
			if resultErr == nil {
				f.plans[private.view.ID] = private
				job.view = private.view
				return
			}
		}
	}
	delete(f.plans, job.status.ID)
	job.status.State, job.status.UpdatedAt = "failed", time.Now().Unix()
	if errors.Is(ctx.Err(), context.Canceled) {
		job.status.State = "cancelled"
	}
	message := resultErr.Error()
	if ctx.Err() != nil {
		message = "UFW 计划准备已取消或超时，未应用规则，请重新准备"
	}
	runes := []rune(strings.ToValidUTF8(message, ""))
	job.status.Error = string(runes[:min(512, len(runes))])
	if err := saveUFWPreparation(f.dataDir, job.status); err != nil {
		job.status.Error = "UFW 计划准备未完成，状态保存失败，请本机检查数据目录后重新准备"
	}
	job.view = ufwPreparationShell(job.status)
}

func (f *hostFirewall) checkUFWPreparedBasisLocked(ctx context.Context, basis ufwPreparationBasis) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !f.ufwPlanning || !f.recovering || f.policyUncertain || f.problem != "" || f.activeLocked() || ufwRestorePending(f.dataDir) || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) || f.remote.problem != "" || f.remote.pendingLocked() || f.remote.web == nil || f.remote.listener == nil || !f.remote.state.Confirmed.Enabled || f.remote.state.Version != basis.View.ListenerVersion || f.remote.state.Confirmed.Listen != basis.View.Listener || f.sshMode != basis.View.SSHProfile {
		return fault.Conflict("UFW 准备期间管理入口、宿主机授权或恢复状态变化，请重新准备")
	}
	effect := basis.Record.Policy
	if basis.Record.Action == "remove" {
		effect = firewall.DefaultPolicy()
	}
	protections, listeners, err := firewallProtectionSet(ctx, effect, f.sshMode, f.remote.state.Confirmed.Listen, f.remote.state.Confirmed.AllowedSources, basis.View.ControlSource)
	if err != nil {
		return err
	}
	actual, _ := json.Marshal(protections)
	expected, _ := json.Marshal(basis.View.Protections)
	if string(actual) != string(expected) || !slices.Equal(listeners, basis.View.SSHListeners) {
		return fault.Conflict("UFW 准备期间 SSH 监听或保护来源变化，请重新准备")
	}
	return ctx.Err()
}
