package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// This queue owns no service or configuration authority. The immutable
// preparation and running transaction remain the execution/fence authorities.
const fail2banUpgradeTaskKind = "fail2ban.upgrade"

type fail2banUpgradeTaskIntent struct {
	Request        fail2ban.UpgradeRequest      `json:"request"`
	ChildID        string                       `json:"child_id"`
	TrustPath      string                       `json:"trust_path"`
	NginxBinary    string                       `json:"nginx_binary"`
	NginxWorker    string                       `json:"nginx_worker"`
	NginxContainer bool                         `json:"nginx_container"`
	Sent           bool                         `json:"sent"`
	Plan           *fail2ban.UpgradePlan        `json:"plan"`
	Preparation    *fail2ban.UpgradePreparation `json:"preparation"`
	Run            *fail2ban.UpgradeRunResult   `json:"run"`
}
type fail2banUpgradeTasks struct {
	server *Server
	gate   *maintenanceGate
	mu     sync.Mutex
}

func upgradeTaskView(r Record) fail2ban.UpgradeOperation {
	i := r.Fail2banUpgrade
	return fail2ban.UpgradeOperation{ID: r.OperationID, RequestHash: r.RequestHash, Input: i.Request.Input, ChildID: i.ChildID, State: r.State, Stage: r.Stage, At: r.UpdatedAt, Error: r.Error, Plan: i.Plan, Preparation: i.Preparation, Run: i.Run}
}
func validFail2banUpgradeTask(r Record) error {
	i := r.Fail2banUpgrade
	if r.Kind != fail2banUpgradeTaskKind || i == nil || !i.Request.Valid() || i.Request.OperationID != r.OperationID || r.RequestHash != i.Request.Hash() || r.Deadline <= 0 || !filepath.IsAbs(i.TrustPath) || filepath.Clean(i.TrustPath) != i.TrustPath || len(i.TrustPath) > 512 || !upgradeTaskView(r).Valid() || !i.Sent && (r.State != "running" && r.State != "failed" || i.Plan != nil || i.Preparation != nil || i.Run != nil) {
		return errors.New("Fail2ban 升级持久请求合同无法核对")
	}
	return nil
}
func (u *fail2banUpgradeTasks) available() error {
	if err := (&fail2banLifecycle{server: u.server}).available(); err != nil {
		return err
	}
	if u.server.ComponentScope != "host" || u.server.ReleaseTrust == "" {
		return fault.Unavailable("须由本机配置宿主机组件范围与发行信任")
	}
	return nil
}
func (u *fail2banUpgradeTasks) record(id string) (Record, error) {
	if !validID(id) {
		return Record{}, fault.Invalid("操作 UUID 无效")
	}
	r, err := u.server.Journal.Get(id)
	if os.IsNotExist(err) {
		return r, fault.New(404, "FAIL2BAN_UPGRADE_OPERATION_MISSING", "升级操作记录不存在")
	}
	if err != nil {
		return r, err
	}
	return r, validFail2banUpgradeTask(r)
}
func (u *fail2banUpgradeTasks) operation(id string) (fail2ban.UpgradeOperation, error) {
	r, err := u.record(id)
	if err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	return upgradeTaskView(r), nil
}
func (u *fail2banUpgradeTasks) submit(ctx context.Context, req fail2ban.UpgradeRequest) (fail2ban.UpgradeOperation, error) {
	if err := u.available(); err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	if !req.Valid() {
		return fail2ban.UpgradeOperation{}, fault.Invalid("升级请求合同无效")
	}
	if !u.mu.TryLock() {
		return fail2ban.UpgradeOperation{}, ErrBusy
	}
	defer u.mu.Unlock()
	if old, err := u.record(req.OperationID); err == nil {
		if old.RequestHash != req.Hash() {
			return fail2ban.UpgradeOperation{}, fault.Conflict("同一升级 UUID 不能用于其他请求")
		}
		return upgradeTaskView(old), nil
	} else {
		var known *fault.Error
		if !errors.As(err, &known) || known.Code != "FAIL2BAN_UPGRADE_OPERATION_MISSING" {
			return fail2ban.UpgradeOperation{}, err
		}
	}
	leave, ok := u.gate.enter(false)
	if !ok {
		return fail2ban.UpgradeOperation{}, ErrBusy
	}
	defer leave()
	unlock, err := fail2banUpgradePreparationAccess(u.server.DataDir, "host", req.OperationID)
	if err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	defer unlock()
	if err = fail2banUpgradeIdle(u.server.Journal); err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	records, err := u.server.Journal.List()
	if err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	for _, r := range records {
		if r.Kind == fail2banUpgradeTaskKind {
			if err = validFail2banUpgradeTask(r); err != nil {
				return fail2ban.UpgradeOperation{}, err
			}
			if r.State == "running" || r.State == "recovery_required" {
				return fail2ban.UpgradeOperation{}, ErrBusy
			}
		}
	}
	i := &fail2banUpgradeTaskIntent{Request: req, ChildID: secure.ID(), TrustPath: u.server.ReleaseTrust}
	if n := u.server.Nginx; n != nil {
		i.NginxBinary, i.NginxWorker, i.NginxContainer = n.Binary, n.WorkerUser, n.Container != nil
	}
	if i.ChildID == req.OperationID {
		return fail2ban.UpgradeOperation{}, errors.New("升级父子操作 UUID 冲突")
	}
	if _, err = u.server.Journal.Get(i.ChildID); !os.IsNotExist(err) {
		return fail2ban.UpgradeOperation{}, errors.Join(errors.New("升级子操作 UUID 已被占用"), err)
	}
	for _, store := range []string{fail2banUpgradePreparations(u.server.DataDir), fail2banUpgradeRuns(u.server.DataDir)} {
		if _, err = os.Lstat(filepath.Join(store, i.ChildID)); !os.IsNotExist(err) {
			return fail2ban.UpgradeOperation{}, errors.Join(errors.New("升级子操作 UUID 已有材料"), err)
		}
	}
	r := Record{Kind: fail2banUpgradeTaskKind, OperationID: req.OperationID, RequestHash: req.Hash(), State: "running", Stage: "queued", Deadline: time.Now().Unix() + 300, UpdatedAt: time.Now().Unix(), Fail2banUpgrade: i}
	if err = validFail2banUpgradeTask(r); err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	if err = ctx.Err(); err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	if err = u.server.Journal.Put(r); err != nil {
		return fail2ban.UpgradeOperation{}, err
	}
	return u.operation(req.OperationID)
}
func (u *fail2banUpgradeTasks) run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	last := ""
	for {
		if ctx.Err() != nil {
			return
		}
		err := u.next(ctx)
		if err != nil && err.Error() != last {
			last = err.Error()
			slog.Warn("Fail2ban 升级任务续办未确认", "error", err)
		} else if err == nil {
			last = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (u *fail2banUpgradeTasks) next(parent context.Context) error {
	if err := u.available(); err != nil {
		return nil
	}
	if !u.mu.TryLock() {
		return nil
	}
	defer u.mu.Unlock()
	leave, ok := u.gate.enter(true)
	if !ok {
		return nil
	}
	defer leave()
	records, err := u.server.Journal.List()
	if err != nil {
		return err
	}
	var pending *Record
	for _, r := range records {
		if r.Kind != fail2banUpgradeTaskKind {
			continue
		}
		if err = validFail2banUpgradeTask(r); err != nil {
			return err
		}
		if r.State != "running" && r.State != "recovery_required" {
			continue
		}
		if pending != nil {
			return errors.New("存在多个未完成的 Fail2ban 升级请求")
		}
		copy := r
		pending = &copy
	}
	if pending == nil {
		return nil
	}
	r := pending
	i := r.Fail2banUpgrade
	if !i.Sent || r.Stage == "waiting_for_admission" {
		if time.Now().Unix() > r.Deadline {
			r.State, r.Stage, r.Error = "failed", "authorization_expired", "升级排队超过五分钟，请重新检查"
			return u.server.Journal.Put(*r)
		}
		i.Sent, r.Stage, r.Error = true, "executing", ""
		if err = u.server.Journal.Put(*r); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	in := i.Request.Input
	options := Fail2banUpgradeOptions{DataDir: u.server.DataDir, Scope: "host", PlanID: in.PlanID, AssetID: in.AssetID, TrustPath: i.TrustPath, Prerelease: in.Prerelease}
	var callErr error
	switch in.Action {
	case "check":
		var plan Fail2banUpgradePlan
		plan, callErr = planFail2banUpgrade(ctx, options, r.OperationID, nil)
		if callErr == nil {
			p := &fail2ban.UpgradePlan{At: plan.At, Target: plan.Target, InstallationID: plan.InstallationID, EventID: plan.EventID, SourceVersion: plan.Current.Version, CandidateVersion: plan.Candidate.Version, Running: plan.Running, Jails: plan.Jails, Impacts: plan.Impacts, ScopeVerified: plan.Grants.ScopeVerified, Blockers: plan.Grants.Blockers, NginxGrants: len(plan.Grants.NginxMoves), HostSources: plan.Grants.MigrateHostSources, HostSync: plan.Grants.MigrateHostSync}
			if plan.Bans != nil {
				p.Bans = &fail2ban.UpgradeBans{ObservedAt: plan.Bans.ObservedAt, Count: plan.Bans.Count, SHA256: plan.Bans.SHA256}
			}
			i.Plan, r.State, r.Stage = p, "succeeded", "candidate_checked"
		}
	case "prepare":
		var prepared Fail2banUpgradePreparation
		prepared, callErr = prepareFail2banUpgradeFor(ctx, Fail2banUpgradePreparationOptions{Fail2banUpgradeOptions: options, OperationID: i.ChildID, Target: in.Target}, r.OperationID)
		if callErr == nil && prepared.State == "prepared" {
			i.Preparation = &fail2ban.UpgradePreparation{ID: prepared.ID, IntentSHA256: prepared.IntentSHA256, CreatedAt: prepared.CreatedAt, SourceVersion: prepared.Source.Version, CandidateVersion: prepared.Candidate.Version}
			r.State, r.Stage = "succeeded", "upgrade_prepared"
		} else if callErr == nil {
			callErr = errors.New("升级准备尚无完整发布及审计确认")
		}
	case "run":
		var run Fail2banUpgradeRun
		run, callErr = RunFail2banUpgrade(ctx, Fail2banUpgradeRunOptions{DataDir: u.server.DataDir, Scope: "host", OperationID: i.ChildID, PreparationID: in.PreparationID, Target: in.Target, NginxBinary: i.NginxBinary, NginxWorker: i.NginxWorker, NginxContainer: i.NginxContainer})
		if callErr == nil {
			i.Run = &fail2ban.UpgradeRunResult{ID: run.ID, State: run.State, Stage: run.Stage, CompletedAt: run.CompletedAt}
			r.State, r.Stage = run.State, run.Stage
		}
	}
	r.Error = ""
	if callErr != nil {
		// An absent immutable child directory proves no service effect was
		// admitted by this request. Published child material must be continued.
		store := fail2banUpgradePreparations(u.server.DataDir)
		if in.Action == "run" {
			store = fail2banUpgradeRuns(u.server.DataDir)
		}
		_, statErr := os.Lstat(filepath.Join(store, i.ChildID))
		r.State, r.Stage = "recovery_required", "child_unconfirmed"
		if in.Action == "check" || os.IsNotExist(statErr) {
			r.State, r.Stage = "failed", "request_rejected"
			// Background host synchronization shares the admission locks. A
			// transient conflict before child publication keeps the original
			// request queued, without renewing its five-minute authorization.
			if errors.Is(callErr, ErrBusy) || errors.Is(callErr, unix.EWOULDBLOCK) {
				r.State, r.Stage = "running", "waiting_for_admission"
			}
		}
		i.Run = nil
		message := []rune(callErr.Error())
		if len(message) > 240 {
			message = message[:240]
		}
		r.Error = string(message)
		if r.Stage == "waiting_for_admission" {
			r.Error = ""
		}
	}
	if err = validFail2banUpgradeTask(*r); err != nil {
		return errors.Join(callErr, err)
	}
	return u.server.Journal.Put(*r)
}
