package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"nginxpanel/internal/fail2ban"
)

func (l *fail2banLifecycle) run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for {
		if ctx.Err() != nil {
			return
		}
		call, cancel := context.WithTimeout(ctx, 150*time.Second)
		err := l.advance(call)
		cancel()
		if err != nil && !errors.Is(err, ErrBusy) && ctx.Err() == nil {
			if !reported {
				slog.Warn("Fail2ban lifecycle reconciliation failed", "error", err)
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
func (l *fail2banLifecycle) advance(ctx context.Context) error {
	if err := l.available(); err != nil {
		return nil
	}
	leave, ok := l.gate.enter(true)
	if !ok {
		return ErrBusy
	}
	defer leave()
	if !l.mu.TryLock() {
		return ErrBusy
	}
	defer l.mu.Unlock()
	records, err := l.server.Journal.List()
	if err != nil {
		return err
	}
	var pending *Record
	for _, r := range records {
		if r.Kind != fail2banLifecycleKind || !pendingNginxRecord(r) {
			continue
		}
		if pending != nil {
			return errors.New("存在多个未结束的 Fail2ban 实例操作")
		}
		copy := r
		pending = &copy
	}
	if pending == nil {
		return nil
	}
	record := *pending
	i := record.Fail2banLifecycle
	if i == nil || !i.Request.Valid() || i.Request.OperationID != record.OperationID || i.Request.Hash() != record.RequestHash {
		record.State, record.Stage, record.Error = "failed", "invalid_intent", "持久受管引擎合同损坏，未重新派发"
		return l.persist(&record)
	}
	unlock, err := l.nginxLock()
	if err != nil {
		return err
	}
	defer unlock()
	finish := func(stage, message string) error {
		record.State, record.Stage, record.Error = "failed", stage, message
		i.Managed = readFail2banManaged(l.server.DataDir)
		if service, _, readErr := lifecycleServiceFor(ctx, i.Service.ID); readErr == nil || errors.Is(readErr, errFail2banLifecycleJobPending) {
			i.Service = service
			if i.Sent && (readErr != nil || service.Active == "activating" || service.Active == "deactivating" || service.Active == "reloading") {
				record.State, record.Stage = "running", "service_pending"
			}
		} else {
			i.Service = fail2ban.Service{ID: i.Service.ID, Reason: "当前服务状态无法确认"}
			if i.Sent {
				record.State, record.Stage = "recovery_required", "service_unconfirmed"
			}
		}
		return l.persist(&record)
	}
	if !i.Sent {
		if record.Deadline <= time.Now().Unix() {
			return finish("authorization_expired", "Fail2ban 实例操作排队超过五分钟，请重新预览")
		}
		bindingUnlock, err := (&Journal{Dir: fail2banBindingDir(l.server.DataDir)}).rootLock("binding.lock")
		if err != nil {
			return err
		}
		plan, planErr := l.plan(ctx, i.Request.Input.LifecyclePreviewInput, record.OperationID)
		bindingUnlock()
		if planErr != nil {
			return finish("preflight_failed", "执行前无法核对原实例或依赖："+planErr.Error())
		}
		if plan.Input != i.Request.Input {
			return finish("target_changed", "原实例、服务、配置或签名资产已变化，请重新预览")
		}
		i.Sent, i.Submission = true, "unknown"
		record.Stage = "executing"
		if err = l.persist(&record); err != nil {
			return err
		}
		var callErr error
		input := i.Request.Input
		if input.EngineOwner == "existing" {
			callErr = l.dispatchExisting(ctx, i.Request)
		} else {
			switch input.Action {
			case "install":
				_, callErr = installFail2ban(ctx, Fail2banInstallOptions{DataDir: l.server.DataDir, Scope: l.server.MetricsScope, OperationID: record.OperationID, PlanID: input.PlanID, AssetID: input.AssetID, TrustPath: l.server.ReleaseTrust, Prerelease: input.Prerelease}, record.OperationID)
			case "resume":
				r, readErr := loadFail2banManaged(l.server.DataDir)
				if readErr != nil || r == nil {
					callErr = errors.New("原受管安装记录无法核对")
				} else {
					_, callErr = installFail2ban(ctx, Fail2banInstallOptions{DataDir: l.server.DataDir, Scope: l.server.MetricsScope, OperationID: r.OperationID, PlanID: r.PlanID, AssetID: r.AssetID, TrustPath: r.TrustPath, Prerelease: r.Prerelease, Start: r.Start, Enable: r.Enable, Resume: true}, record.OperationID)
				}
			default:
				_, callErr = manageFail2banManaged(ctx, l.server.DataDir, l.server.MetricsScope, input.Action, record.OperationID)
			}
		}
		// Cancellation can interrupt a service call after it took effect. Preserve
		// the sent marker for the next Agent to observe, never to replay the call.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if callErr == nil {
			i.Submission = "acknowledged"
		}
		record.Stage = "observing"
		if err = l.persist(&record); err != nil {
			return err
		}
		if callErr != nil && input.EngineOwner != "existing" {
			return finish("execution_unconfirmed", "Fail2ban 实例操作未确认完成，须重新预览实际状态；原操作不会重发："+callErr.Error())
		}
	}
	bindingUnlock, err := (&Journal{Dir: fail2banBindingDir(l.server.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return err
	}
	managed, service, proofErr := l.prove(ctx, i.Request)
	if proofErr == nil && i.Request.Input.Action == "rollback" {
		proofErr = l.completeWithdrawal(&record)
	}
	bindingUnlock()
	if proofErr != nil {
		return finish("state_unconfirmed", "原操作不会重发；当前目标状态无法确认："+proofErr.Error())
	}
	i.Managed, i.Service = managed, service
	record.State, record.Stage, record.Error = "succeeded", "lifecycle_confirmed", ""
	if i.Submission == "unknown" {
		record.Stage = "state_confirmed_receipt_unknown"
	}
	if err = l.persist(&record); err != nil {
		return err
	}
	if l.server.fail2banNginx != nil {
		l.server.fail2banNginx.enqueue()
	}
	return nil
}
func (l *fail2banLifecycle) prove(ctx context.Context, request fail2ban.LifecycleRequest) (fail2ban.Managed, fail2ban.Service, error) {
	managed := readFail2banManaged(l.server.DataDir)
	if request.Input.EngineOwner == "existing" {
		service, err := l.proveExisting(ctx, request.Input)
		return managed, service, err
	}
	var service fail2ban.Service
	r, err := loadFail2banManaged(l.server.DataDir)
	if err != nil || r == nil {
		return managed, service, errors.New("受管安装记录不存在或无法核对")
	}
	input := request.Input
	wantedID := input.BaseID
	if input.Action == "install" {
		wantedID = request.OperationID
	}
	action := input.Action
	if action == "resume" {
		action = "install"
	}
	if r.OperationID != wantedID || r.Action != action || r.ActionState != "completed" {
		return managed, service, errors.New("原实例操作尚未完成或已发生其他操作")
	}
	service, _, err = lifecycleService(ctx)
	if err != nil {
		return managed, service, err
	}
	if input.Action == "rollback" {
		if r.State != "rolled-back" || service.Load != "not-found" || service.Active != "inactive" || *service.MainPID != 0 {
			return managed, service, errors.New("独立服务撤回未确认")
		}
		return managed, service, nil
	}
	if r.State != "installed" {
		return managed, service, errors.New("安装未完成")
	}
	if err = verifyFail2banManaged(ctx, r, true); err != nil {
		return managed, service, err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return managed, service, err
	}
	switch input.Action {
	case "start":
		if service.Active != "active" {
			err = errors.New("服务尚未确认活动")
		} else {
			err = verifyFail2banManagedLive(ctx, r)
		}
	case "stop":
		err = fail2banManagedStopped(ctx)
	case "enable":
		if service.UnitFile != "enabled" {
			err = errors.New("开机启用状态未确认")
		}
	case "disable":
		if service.UnitFile != "disabled" {
			err = errors.New("开机停用状态未确认")
		}
	case "resume":
		if input.Start {
			if service.Active != "active" {
				err = errors.New("原启动意图未确认")
			} else {
				err = verifyFail2banManagedLive(ctx, r)
			}
		}
		if err == nil && input.Enable && service.UnitFile != "enabled" {
			err = errors.New("原开机启用意图未确认")
		}
	}
	return managed, service, err
}
