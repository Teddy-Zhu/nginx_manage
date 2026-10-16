package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const fail2banPythonPlanningKind = "nginx.fail2ban-python-plan"

type fail2banPythonPlanning struct {
	Request        fail2ban.PythonTaskRequest `json:"request"`
	OS             string                     `json:"os"`
	Version        string                     `json:"version"`
	Manager        string                     `json:"manager"`
	Sent           bool                       `json:"sent"`
	Submission     string                     `json:"submission"`
	ExecutionError string                     `json:"execution_error"`
	Plan           *fail2ban.PythonPlan       `json:"plan"`
}
type fail2banPythonTasks struct {
	server *Server
	gate   *maintenanceGate
	mu     sync.Mutex
}

func (p *fail2banPythonTasks) available() error {
	if err := (&fail2banLifecycle{server: p.server}).available(); err != nil {
		return err
	}
	if p.server.ComponentScope != "host" {
		return fault.Unavailable("须由本机确认宿主机组件范围")
	}
	return nil
}
func pythonTaskView(r Record) fail2ban.PythonTaskOperation {
	out := fail2ban.PythonTaskOperation{ID: r.OperationID, RequestHash: r.RequestHash, State: r.State, Stage: r.Stage, At: r.UpdatedAt, Python: fail2ban.Empty("host", "尚未核对系统 Python").Python, Error: r.Error}
	if r.Kind == fail2banPythonKind {
		i := r.Fail2banPython
		out.Input = i.Request.Input
		out.Submission = i.Submission
		out.Plan = &i.Plan.Plan
		out.Python = i.Python
	} else {
		i := r.Fail2banPythonPlanning
		out.Input = i.Request.Input
		out.Submission = i.Submission
		out.Plan = i.Plan
	}
	return out
}
func (p *fail2banPythonTasks) record(id string) (Record, error) {
	var out Record
	if !validID(id) {
		return out, fault.Invalid("操作 UUID 无效")
	}
	r, err := p.server.Journal.Get(id)
	if os.IsNotExist(err) {
		return out, fault.New(404, "FAIL2BAN_PYTHON_OPERATION_MISSING", "Python 依赖操作记录不存在")
	}
	if err != nil {
		return out, err
	}
	if r.Kind == fail2banPythonKind {
		return readFail2banPythonOperation(p.server.DataDir, id)
	}
	i := r.Fail2banPythonPlanning
	if r.Kind != fail2banPythonPlanningKind || i == nil || !i.Request.Valid() || i.Request.OperationID != id || i.Request.Input.Action != "plan" || r.RequestHash != i.Request.Hash() || (i.Manager != "apt" && i.Manager != "dnf") || i.Sent && i.Submission == "not_sent" || !i.Sent && i.Submission != "not_sent" || len(i.ExecutionError) > 1024 {
		return out, errors.New("Python 依赖计划持久合同无法核对")
	}
	if !fail2ban.ValidPythonTaskOperation(pythonTaskView(r)) {
		return out, errors.New("Python 依赖操作结果合同无法核对")
	}
	return r, nil
}
func (p *fail2banPythonTasks) operation(id string) (fail2ban.PythonTaskOperation, error) {
	r, err := p.record(id)
	if err != nil {
		return fail2ban.PythonTaskOperation{}, err
	}
	out := pythonTaskView(r)
	if !fail2ban.ValidPythonTaskOperation(out) {
		return out, errors.New("Python 依赖操作结果无效")
	}
	return out, nil
}
func (p *fail2banPythonTasks) submit(ctx context.Context, in fail2ban.PythonTaskRequest) (fail2ban.PythonTaskOperation, error) {
	var out fail2ban.PythonTaskOperation
	if err := p.available(); err != nil {
		return out, err
	}
	if !in.Valid() {
		return out, fault.Invalid("Python 依赖请求合同无效")
	}
	existing := func() (fail2ban.PythonTaskOperation, error) {
		old, err := p.operation(in.OperationID)
		if err == nil && old.RequestHash != in.Hash() {
			err = fault.Conflict("操作 ID 已用于其他请求")
		}
		return old, err
	}
	if old, err := existing(); err == nil {
		return old, nil
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "FAIL2BAN_PYTHON_OPERATION_MISSING" {
			return out, err
		}
	}
	leave, ok := p.gate.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	if !p.mu.TryLock() {
		return out, ErrBusy
	}
	defer p.mu.Unlock()
	if old, err := existing(); err == nil {
		return old, nil
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "FAIL2BAN_PYTHON_OPERATION_MISSING" {
			return out, err
		}
	}
	unlock, err := (&fail2banLifecycle{server: p.server}).nginxLock()
	if err != nil {
		return out, err
	}
	defer unlock()
	bindingUnlock, err := (&Journal{Dir: fail2banBindingDir(p.server.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer bindingUnlock()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = fail2banManagedIdle(p.server.DataDir, ""); err != nil {
		return out, err
	}
	if in.Input.Action == "install" {
		r, err := admitFail2banPythonInstall(p.server.DataDir, in)
		if err != nil {
			return out, err
		}
		return pythonTaskView(r), nil
	}
	osName, version, err := fail2banPythonHost()
	if err != nil {
		return out, err
	}
	manager := "apt"
	if osName == "centos" {
		manager = "dnf"
	}
	r := Record{OperationID: in.OperationID, RequestHash: in.Hash(), Kind: fail2banPythonPlanningKind, State: "running", Stage: "queued", Deadline: time.Now().Add(5 * time.Minute).Unix(), Fail2banPythonPlanning: &fail2banPythonPlanning{Request: in, OS: osName, Version: version, Manager: manager, Submission: "not_sent"}}
	if err = secure.RootDirectory(p.server.Journal.Dir, 0700); err != nil {
		return out, err
	}
	if err = fail2banPythonPersist(p.server.DataDir, &r); err != nil {
		return out, err
	}
	return pythonTaskView(r), nil
}
func (p *fail2banPythonTasks) run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for {
		if ctx.Err() != nil {
			return
		}
		call, cancel := context.WithTimeout(ctx, 45*time.Minute)
		err := p.advance(call)
		cancel()
		if err != nil && !errors.Is(err, ErrBusy) && ctx.Err() == nil {
			if !reported {
				slog.Warn("Fail2ban Python task reconciliation failed", "error", err)
			}
			reported = true
		} else {
			reported = false
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (p *fail2banPythonTasks) advance(ctx context.Context) error {
	if err := p.available(); err != nil {
		return nil
	}
	leave, ok := p.gate.enter(true)
	if !ok {
		return ErrBusy
	}
	defer leave()
	if !p.mu.TryLock() {
		return ErrBusy
	}
	defer p.mu.Unlock()
	records, err := p.server.Journal.List()
	if err != nil {
		return err
	}
	var id string
	for _, r := range records {
		if (r.Kind == fail2banPythonKind || r.Kind == fail2banPythonPlanningKind) && pendingNginxRecord(r) {
			if id != "" {
				return errors.New("存在多个未结束的 Python 依赖操作")
			}
			id = r.OperationID
		}
	}
	if id == "" {
		return nil
	}
	unlock, err := (&fail2banLifecycle{server: p.server}).nginxLock()
	if err != nil {
		return err
	}
	bindingUnlock, err := (&Journal{Dir: fail2banBindingDir(p.server.DataDir)}).rootLock("binding.lock")
	unlock()
	if err != nil {
		return err
	}
	defer bindingUnlock()
	r, err := p.record(id)
	if err != nil {
		return err
	}
	if r.Kind == fail2banPythonKind {
		_, err = runFail2banPython(ctx, p.server.DataDir, &r)
		return err
	}
	return p.runPlan(ctx, &r)
}

type fail2banPythonPlanResult struct {
	OperationID string `json:"operation_id"`
	RequestHash string `json:"request_hash"`
	PlanID      string `json:"plan_id"`
}

func (p *fail2banPythonTasks) planResultPath(id string) string {
	return filepath.Join(fail2banPythonDir(p.server.DataDir), "planning-results", id+".json")
}
func (p *fail2banPythonTasks) observePlan(r *Record) error {
	i := r.Fail2banPythonPlanning
	recovery := func(err error) error {
		r.State, r.Stage, r.Error = "recovery_required", "plan_result_unconfirmed", err.Error()
		return fail2banPythonPersist(p.server.DataDir, r)
	}
	raw, err := listenerRead(p.planResultPath(r.OperationID), 4096)
	if os.IsNotExist(err) {
		if idleErr := fail2banPythonPackageIdle(i.Manager); idleErr != nil {
			r.State, r.Stage, r.Error = "recovery_required", "package_manager_unconfirmed", idleErr.Error()
		} else {
			r.State, r.Stage, r.Error = "failed", "plan_unconfirmed", "原计划结果未保存，不自动重发索引刷新；须重新生成计划"
			if i.ExecutionError != "" {
				r.Error = i.ExecutionError
			}
		}
	} else if err == nil {
		var result fail2banPythonPlanResult
		if fail2banPythonDecode(raw, &result) != nil || result.OperationID != r.OperationID || result.RequestHash != r.RequestHash {
			return recovery(errors.New("依赖计划恢复索引无法核对"))
		}
		plan, readErr := loadFail2banPythonPlan(p.server.DataDir, result.PlanID)
		if readErr != nil {
			return recovery(readErr)
		}
		if plan.Plan.Manager != i.Manager || plan.Plan.OS != i.OS || plan.Plan.Version != i.Version {
			return recovery(errors.New("依赖计划主机身份不一致"))
		}
		i.Plan = &plan.Plan
		r.State, r.Stage, r.Error = "succeeded", "plan_ready", ""
		if i.Submission == "unknown" {
			r.Stage = "plan_ready_receipt_unknown"
		}
	} else {
		return recovery(err)
	}
	return fail2banPythonPersist(p.server.DataDir, r)
}
func (p *fail2banPythonTasks) runPlan(ctx context.Context, r *Record) error {
	i := r.Fail2banPythonPlanning
	if i.Sent {
		return p.observePlan(r)
	}
	if r.Deadline <= time.Now().Unix() {
		r.State, r.Stage, r.Error = "failed", "authorization_expired", "依赖计划排队超过五分钟，请重新确认"
		return fail2banPythonPersist(p.server.DataDir, r)
	}
	if err := fail2banManagedIdle(p.server.DataDir, r.OperationID); err != nil {
		return err
	}
	osName, version, err := fail2banPythonHost()
	if err != nil {
		r.State, r.Stage, r.Error = "failed", "preflight_failed", err.Error()
		return fail2banPythonPersist(p.server.DataDir, r)
	}
	if osName != i.OS || version != i.Version {
		r.State, r.Stage, r.Error = "failed", "host_changed", "主机发行版已变化，请重新生成计划"
		return fail2banPythonPersist(p.server.DataDir, r)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	i.Sent, i.Submission, r.Stage = true, "unknown", "planning_packages"
	if err = fail2banPythonPersist(p.server.DataDir, r); err != nil {
		return err
	}
	plan, callErr := planFail2banPython(ctx, p.server.DataDir, i.Request.Input.Refresh)
	if callErr == nil {
		callErr = storeFail2banPythonPlan(p.server.DataDir, plan)
	}
	if callErr == nil {
		path := p.planResultPath(r.OperationID)
		if callErr = secure.RootDirectory(filepath.Dir(path), 0700); callErr == nil {
			callErr = rootJSONWrite(path, fail2banPythonPlanResult{OperationID: r.OperationID, RequestHash: r.RequestHash, PlanID: plan.Plan.ID}, 4096)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if callErr == nil {
		i.Submission = "acknowledged"
	} else {
		i.ExecutionError = callErr.Error()
	}
	r.Stage = "observing_plan"
	if err = fail2banPythonPersist(p.server.DataDir, r); err != nil {
		return errors.Join(callErr, err)
	}
	return p.observePlan(r)
}
