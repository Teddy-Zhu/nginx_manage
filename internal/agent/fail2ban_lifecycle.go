package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const fail2banLifecycleKind = "nginx.fail2ban-lifecycle"

var errFail2banLifecycleJobPending = errors.New("专用服务仍有排队或执行中的 systemd 作业")

type fail2banLifecycleIntent struct {
	Request        fail2ban.LifecycleRequest `json:"request"`
	Sent           bool                      `json:"sent"`
	Submission     string                    `json:"submission"`
	Managed        fail2ban.Managed          `json:"managed"`
	Service        fail2ban.Service          `json:"service"`
	BeforeRegistry *fail2banNginxRegistry    `json:"before_registry,omitempty"`
	AfterRegistry  *fail2banNginxRegistry    `json:"after_registry,omitempty"`
}
type fail2banLifecycle struct {
	server *Server
	gate   *maintenanceGate
	mu     sync.Mutex
}

func fail2banManagedIdle(data, allowed string) error {
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return err
	}
	for _, r := range records {
		if pendingNginxRecord(r) && r.OperationID != allowed {
			return ErrBusy
		}
	}
	return nil
}
func (l *fail2banLifecycle) available() error {
	s := l.server
	if s.Dev || s.MetricsScope != "host" || s.MaintenanceScope != "host" {
		return fault.Unavailable("须由本机 root 确认宿主机 Fail2ban 与维护范围")
	}
	return fail2banManagedRoot(s.DataDir, s.MetricsScope)
}
func (l *fail2banLifecycle) nginxLock() (func(), error) {
	n := l.server.Nginx
	if n == nil {
		return func() {}, nil
	}
	if !n.mu.TryLock() {
		return nil, ErrBusy
	}
	if n.closed || n.unlock == nil {
		n.mu.Unlock()
		return nil, ErrRuntimeUnavailable
	}
	if n.disasterBusy != "" || n.http01 != nil && n.http01.busy() {
		n.mu.Unlock()
		return nil, ErrBusy
	}
	return n.mu.Unlock, nil
}
func lifecycleService(ctx context.Context) (fail2ban.Service, string, error) {
	out := fail2ban.Service{ID: fail2banManagedService}
	raw, callErr := fail2banRun(ctx, fail2banTool("systemctl"), []string{"show", "--all", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,InvocationID,Job", fail2banManagedService}, 4096)
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || len(value) > 128 {
			return out, "", errors.New("专用服务元数据格式未知")
		}
		switch key {
		case "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "InvocationID", "Job":
		default:
			return out, "", errors.New("专用服务元数据包含未知字段")
		}
		if _, duplicate := values[key]; duplicate {
			return out, "", errors.New("专用服务元数据重复")
		}
		values[key] = value
	}
	if len(values) != 8 || values["Id"] != fail2banManagedService {
		return out, "", errors.New("专用服务身份或元数据无法完整核对")
	}
	if callErr != nil {
		var exit *exec.ExitError
		if !errors.As(callErr, &exit) || ctx.Err() != nil || values["LoadState"] != "not-found" {
			return out, "", errors.New("专用服务状态无法完整读取")
		}
	}
	if !fail2banServiceWord.MatchString(values["LoadState"]) || !fail2banServiceWord.MatchString(values["ActiveState"]) || !fail2banServiceWord.MatchString(values["SubState"]) || values["UnitFileState"] != "" && !fail2banServiceWord.MatchString(values["UnitFileState"]) {
		return out, "", errors.New("专用服务状态格式未知")
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid < 0 {
		return out, "", errors.New("专用服务进程无法核对")
	}
	invocation := values["InvocationID"]
	if invocation != "" && !fail2banInvocation.MatchString(invocation) || values["ActiveState"] == "active" && (invocation == "" || invocation == strings.Repeat("0", 32)) {
		return out, "", errors.New("专用服务运行代次无法核对")
	}
	// systemctl renders Unit.Job as an empty value for no job, or a uint32 job
	// ID. ActiveState can remain stable while a job waits for dependencies.
	job := values["Job"]
	if job != "" {
		id, err := strconv.ParseUint(job, 10, 32)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != job {
			return out, "", errors.New("专用服务作业状态无法核对")
		}
	}
	out = fail2ban.Service{ID: fail2banManagedService, Available: true, Load: values["LoadState"], Active: values["ActiveState"], Sub: values["SubState"], UnitFile: values["UnitFileState"], MainPID: &pid}
	if job != "" {
		return out, invocation, errFail2banLifecycleJobPending
	}
	return out, invocation, nil
}

// The caller holds the coordinator, optional Nginx and installation locks.
func (l *fail2banLifecycle) plan(ctx context.Context, input fail2ban.LifecyclePreviewInput, allowed string) (fail2ban.LifecyclePlan, error) {
	out := fail2ban.LifecyclePlan{At: time.Now().Unix(), Input: fail2ban.LifecycleInput{LifecyclePreviewInput: input}, Jails: []string{}, Impacts: []string{}}
	if err := input.Validate(); err != nil {
		return out, err
	}
	if err := fail2banManagedIdle(l.server.DataDir, allowed); err != nil {
		return out, err
	}
	r, err := loadFail2banManaged(l.server.DataDir)
	if err != nil {
		return out, err
	}
	out.Managed = readFail2banManaged(l.server.DataDir)
	service, invocation, err := lifecycleService(ctx)
	if err != nil {
		return out, err
	}
	out.Service = service
	var candidate *fail2banManagedRecord
	selected := ""
	unknownJails := false
	if r != nil {
		out.Input.BaseID = r.OperationID
		if r.State != "rolled-back" {
			var bundle *fail2banJailBundle
			selected, bundle, err = selectedFail2banJails(r)
			if err != nil {
				if input.Action != "rollback" {
					return out, err
				}
				unknownJails = true
			}
			if bundle != nil {
				for _, jail := range bundle.Policy.Jails {
					if jail.Enabled {
						out.Jails = append(out.Jails, fail2banJailNameFor(jail.ID))
					}
				}
			}
		}
	}
	switch input.Action {
	case "install":
		if l.server.ComponentScope != "host" || l.server.ReleaseTrust == "" {
			return out, fault.Unavailable("须由本机配置宿主机组件范围与发行信任")
		}
		if r != nil && r.State != "rolled-back" {
			return out, fault.Conflict("已有受管安装，请选择原安装续办或服务操作")
		}
		if err = fail2banManagedNoOther(ctx, l.server.DataDir, true); err != nil {
			return out, err
		}
		if err = fail2banManagedOverrides(); err != nil {
			return out, err
		}
		candidate, err = admitFail2banManaged(ctx, Fail2banInstallOptions{DataDir: l.server.DataDir, Scope: l.server.MetricsScope, OperationID: secure.ID(), PlanID: input.PlanID, AssetID: input.AssetID, TrustPath: l.server.ReleaseTrust, Prerelease: input.Prerelease})
		if err != nil {
			return out, err
		}
		candidate.OperationID = ""
		candidate.ApprovedAt = 0
		out.Impacts = []string{"注册独立服务及私有配置、状态目录；不启动服务，不设置开机启用", "使用已准备的签名官方代码和现有系统 Python；不执行 pip 或安装系统包"}
	case "resume":
		if l.server.ComponentScope != "host" {
			return out, fault.Unavailable("宿主机组件范围未确认")
		}
		if r == nil || r.State != "reserved" && r.State != "ready" && r.State != "interrupted" {
			return out, fault.Conflict("没有可续办的受管安装")
		}
		if err = verifyFail2banManaged(ctx, r, false); err != nil {
			return out, err
		}
		out.Input.Start, out.Input.Enable = r.Start, r.Enable
		out.Impacts = []string{"按原资产、解释器和安装意图继续；不覆盖发生外部变化的文件"}
		if r.Start {
			out.Impacts = append(out.Impacts, "原安装意图包含启动服务，续办会启动独立实例")
		}
		if r.Enable {
			out.Impacts = append(out.Impacts, "原安装意图包含开机启用，续办会恢复该设置")
		}
	case "rollback":
		if l.server.ComponentScope != "host" {
			return out, fault.Unavailable("宿主机组件范围未确认")
		}
		if r == nil {
			return out, fault.Conflict("没有可撤回的受管安装")
		}
		out.Impacts = []string{"停止独立实例并移除其服务文件，保留配置、状态库、签名组件和审计", "受管 jail 保护可能中断；撤销该安装的 Nginx 动作授权，集合由后台独立清理"}
	default:
		if r == nil || r.State != "installed" {
			return out, fault.Conflict("请先完成原受管安装")
		}
		if err = verifyFail2banManaged(ctx, r, true); err != nil {
			return out, err
		}
		if err = fail2banManagedEffective(ctx); err != nil {
			return out, err
		}
		switch input.Action {
		case "start":
			out.Impacts = []string{"启动独立受管实例；封禁恢复由官方引擎和状态库决定，Nginx 集合另行核对"}
		case "stop":
			out.Impacts = []string{"停止独立实例，受管 jail 保护可能中断，状态库保留", "受管 Nginx 集合由后台核对停止后清理；不停止系统全局 Fail2ban"}
		case "enable":
			out.Impacts = []string{"设置独立服务开机启用；不启动当前服务"}
		case "disable":
			out.Impacts = []string{"取消独立服务开机启用；不停止当前服务或删除封禁记录"}
		}
	}
	registry, err := loadFail2banNginxRegistry(l.server.DataDir)
	if err != nil {
		return out, err
	}
	if input.Action == "install" && r != nil {
		key := fail2banNginxEngineKey(r.binding())
		for _, grant := range registry.Grants {
			if grant.EngineKey == key {
				return out, fault.Conflict("原安装仍有动作授权，请先完成原实例撤回")
			}
		}
	}
	if r != nil {
		seen := map[string]bool{}
		for _, name := range out.Jails {
			seen[name] = true
		}
		key := fail2banNginxEngineKey(r.binding())
		for _, grant := range registry.Grants {
			if grant.EngineKey == key && !seen[grant.Jail] {
				out.Jails = append(out.Jails, grant.Jail)
				seen[grant.Jail] = true
			}
		}
		sort.Strings(out.Jails)
	}
	if unknownJails {
		out.Impacts = append(out.Impacts, "当前 jail 配置无法完整核对，列出的动作授权不能代表全部运行保护；撤回将停止整个独立实例")
	}
	raw, _ := json.Marshal(struct {
		Input                          fail2ban.LifecycleInput
		Current, Candidate             *fail2banManagedRecord
		Service                        fail2ban.Service
		Invocation, Selected, Registry string
	}{out.Input, r, candidate, service, invocation, selected, registry.ID})
	out.Input.Target = secure.Hash(raw)
	return out, ctx.Err()
}
func (l *fail2banLifecycle) preview(ctx context.Context, in fail2ban.LifecyclePreviewInput) (fail2ban.LifecyclePlan, error) {
	var out fail2ban.LifecyclePlan
	if err := l.available(); err != nil {
		return out, err
	}
	leave, ok := l.gate.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	if !l.mu.TryLock() {
		return out, ErrBusy
	}
	defer l.mu.Unlock()
	unlock, err := l.nginxLock()
	if err != nil {
		return out, err
	}
	defer unlock()
	installationUnlock, err := (&Journal{Dir: fail2banBindingDir(l.server.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer installationUnlock()
	return l.plan(ctx, in, "")
}
func lifecycleView(r Record) fail2ban.LifecycleOperation {
	i := r.Fail2banLifecycle
	return fail2ban.LifecycleOperation{ID: r.OperationID, RequestHash: r.RequestHash, Input: i.Request.Input, State: r.State, Stage: r.Stage, Submission: i.Submission, At: r.UpdatedAt, Managed: i.Managed, Service: i.Service, Error: r.Error}
}
func (l *fail2banLifecycle) persist(r *Record) error {
	r.UpdatedAt = time.Now().Unix()
	return l.server.Journal.Put(*r)
}
func (l *fail2banLifecycle) operation(id string) (fail2ban.LifecycleOperation, error) {
	var out fail2ban.LifecycleOperation
	if !validID(id) {
		return out, fault.Invalid("操作 UUID 无效")
	}
	r, err := l.server.Journal.Get(id)
	if os.IsNotExist(err) {
		return out, fault.New(404, "FAIL2BAN_LIFECYCLE_OPERATION_MISSING", "受管引擎操作记录不存在")
	}
	if err != nil {
		return out, err
	}
	if r.Kind != fail2banLifecycleKind || r.Fail2banLifecycle == nil || !r.Fail2banLifecycle.Request.Valid() || r.Fail2banLifecycle.Request.OperationID != id || r.RequestHash != r.Fail2banLifecycle.Request.Hash() {
		return out, fault.Conflict("受管引擎操作持久合同无法核对")
	}
	return lifecycleView(r), nil
}
func (l *fail2banLifecycle) submit(ctx context.Context, in fail2ban.LifecycleRequest) (fail2ban.LifecycleOperation, error) {
	var out fail2ban.LifecycleOperation
	if err := l.available(); err != nil {
		return out, err
	}
	if !in.Valid() {
		return out, fault.Invalid("受管引擎操作合同无效")
	}
	if old, err := l.operation(in.OperationID); err == nil {
		if old.RequestHash != in.Hash() {
			return out, fault.Conflict("操作 ID 冲突")
		}
		return old, nil
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "FAIL2BAN_LIFECYCLE_OPERATION_MISSING" {
			return out, err
		}
	}
	leave, ok := l.gate.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	if !l.mu.TryLock() {
		return out, ErrBusy
	}
	defer l.mu.Unlock()
	// Recheck after serializing admission, before any new durable intent.
	if old, err := l.operation(in.OperationID); err == nil {
		if old.RequestHash != in.Hash() {
			return out, fault.Conflict("操作 ID 冲突")
		}
		return old, nil
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "FAIL2BAN_LIFECYCLE_OPERATION_MISSING" {
			return out, err
		}
	}
	unlock, err := l.nginxLock()
	if err != nil {
		return out, err
	}
	defer unlock()
	installationUnlock, err := (&Journal{Dir: fail2banBindingDir(l.server.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer installationUnlock()
	plan, err := l.plan(ctx, in.Input.LifecyclePreviewInput, "")
	if err != nil {
		return out, err
	}
	if plan.Input != in.Input {
		return out, fault.Conflict("实例、服务、安装资产或配置基准已变化，请重新预览")
	}
	r := Record{OperationID: in.OperationID, RequestHash: in.Hash(), Kind: fail2banLifecycleKind, State: "running", Stage: "queued", Deadline: time.Now().Add(5 * time.Minute).Unix(), Fail2banLifecycle: &fail2banLifecycleIntent{Request: in, Submission: "not_sent", Managed: plan.Managed, Service: plan.Service}}
	if in.Input.Action == "rollback" {
		before, after, e := l.withdrawal(in.OperationID, in.Hash())
		if e != nil {
			return out, e
		}
		r.Fail2banLifecycle.BeforeRegistry, r.Fail2banLifecycle.AfterRegistry = before, after
	}
	if err = l.persist(&r); err != nil {
		return out, err
	}
	return lifecycleView(r), nil
}
