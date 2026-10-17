package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

func fail2banHostSyncMetadata(e *fail2banHostSyncEvent) fail2ban.HostInputSyncView {
	out := fail2ban.EmptyHostInputSync("尚未批准持续宿主机封禁同步")
	out.State = "disabled"
	if e == nil {
		return out
	}
	out.ID, out.SessionID, out.ApprovedAt, out.RetirementID = e.ID, e.SessionID, e.ApprovedAt, e.RetirementID
	out.RecoverOnBoot, out.RecoveryID = e.Action == "enable" && e.RecoverOnBoot, e.RecoveryID
	if e.Action == "enable" {
		out.Enabled, out.State, out.Reason = true, "waiting", "已批准持续同步，等待独立执行器核对"
	} else {
		out.Reason = "持续同步已停用，动作规则已清除"
		if e.RetirementID != "" {
			out.Reason = "已退役失联动作范围并停用会话；原事务结果及其他命名空间规则未确认"
		}
	}
	return out
}

func fail2banHostSyncLocks(dataDir string) (func(), error) {
	leaveHost, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("fail2ban-host-input.lock")
	if err != nil {
		return nil, err
	}
	leaveBinding, err := (&Journal{Dir: fail2banBindingDir(dataDir)}).rootLock("binding.lock")
	if err != nil {
		leaveHost()
		return nil, err
	}
	return func() { leaveBinding(); leaveHost() }, nil
}

func fail2banHostSyncAdmission(dataDir string, apply bool) (func(), error) {
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	leave, err := j.maintenanceLock()
	if err != nil {
		return nil, err
	}
	records, err := j.List()
	if err == nil {
		for _, r := range records {
			if r.Kind == "maintenance.lock" && r.State != "succeeded" {
				err = ErrBusy
				break
			}
			if apply && (r.Kind == fail2banLifecycleKind || r.Kind == fail2banJailsKind || r.Kind == fail2banExistingKind || r.Kind == fail2banExistingPolicyKind || r.Kind == fail2banExistingPolicyJobKind || r.Kind == fail2banAddressKind || r.Kind == fail2banPythonKind || r.Kind == fail2banPythonPlanningKind) && pendingNginxRecord(r) {
				err = ErrBusy
				break
			}
		}
	}
	if err != nil {
		leave()
		return nil, err
	}
	return leave, nil
}

func loadFail2banHostSyncStop(dataDir string, current *fail2banHostSyncEvent) (*fail2banHostSyncEvent, error) {
	var pointer struct {
		ID string `json:"id"`
	}
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostSyncDir(dataDir), "stopping.json"), &pointer); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	e, err := loadFail2banHostSyncEvent(dataDir, pointer.ID)
	if err != nil {
		return nil, err
	}
	if e.Action != "disable" {
		return nil, errors.New("持续同步停用意图类型无效")
	}
	if current != nil && (e.ID == current.ID || e.ID == current.PreviousID) {
		return nil, nil
	}
	if current == nil || current.Action != "enable" || e.PreviousID != current.ID || e.SessionID != current.SessionID {
		return nil, errors.New("持续同步停用意图与当前批准冲突")
	}
	return e, nil
}

func finishFail2banHostSyncStop(ctx context.Context, dataDir string, event, stopping *fail2banHostSyncEvent) error {
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return err
	}
	if root == nil || root.State != "registered" || root.OperationID != event.RegistrationID || root.Owner != event.Owner || !fail2banHostRegistrationReceipt(dataDir, root) {
		return errors.New("停用会话所属独立登记变化，禁止覆盖其他对象")
	}
	current, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return err
	}
	if current != nil && (current.State == "running" || current.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, current)) {
		if current.Intent.ControllerID != event.ID {
			return errors.New("存在不属于当前持续会话的待恢复事务")
		}
		status, e := recoverFail2banHostRuntime(ctx, dataDir, root, current)
		if e != nil && !status.Runtime.Verified {
			return e
		}
		current, err = loadFail2banHostRuntime(dataDir)
		if err != nil {
			return err
		}
	}
	if current != nil && current.Intent.ControllerID != event.ID && current.Intent.OperationID != event.RuntimeBaseID {
		return errors.New("停用会话的当前运行基础已变化")
	}
	before, expected, err := fail2banHostRuntimeBase(dataDir, root, current)
	if err != nil {
		return err
	}
	if before.Set != nil {
		leave, e := fail2banHostSyncAdmission(dataDir, false)
		if e != nil {
			return e
		}
		_, e = executeFail2banHostRuntime(ctx, dataDir, root, current, "clear", secure.ID(), event.ID)
		leave()
		if e != nil {
			return e
		}
		current, err = loadFail2banHostRuntime(dataDir)
		if err != nil {
			return err
		}
	} else {
		kernel, e := before.snapshot(ctx)
		if e != nil {
			return e
		}
		if !kernel.TableExists || kernel.NamespaceID != expected.NamespaceID || kernel.Fingerprint != expected.Fingerprint {
			return errors.New("停用前原空表无法完整证明")
		}
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	r, err := j.Get(event.ID)
	if err != nil || !fail2banHostSyncParentMatches(r, event) {
		return errors.Join(errors.New("停用父操作回执不一致"), err)
	}
	if current != nil && current.Intent.ControllerID == event.ID {
		if (current.State != "succeeded" && current.State != "failed") || current.effective().Set != nil || !fail2banHostRuntimeReceipt(dataDir, current) {
			return errors.New("停用规则清除尚未核对")
		}
	} else if r.Stage != "approved" && r.Stage != "disabled-empty" || r.AfterRevision != "" {
		return errors.New("停用前持续会话检查点缺失")
	}
	if r.State != "running" && r.State != "succeeded" {
		return errors.New("停用父操作状态无效")
	}
	if r.State == "running" {
		r.State = "succeeded"
		if current == nil || current.Intent.ControllerID != event.ID {
			r.Stage = "disabled-empty"
		}
		if err = j.Put(r); err != nil {
			return err
		}
	}
	return publishFail2banHostSync(dataDir, stopping)
}

// Enabling and stopping are explicit local root policy operations. A stop
// intent freezes new samples before any cleanup, and survives a CLI disconnect.
func ManageFail2banHostSync(ctx context.Context, dataDir, scope, action, operationID, base, runtimeBase string, recoverOnBoot bool) (fail2ban.HostInputSyncView, error) {
	out := fail2ban.EmptyHostInputSync("持续同步操作尚未核对")
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("持续同步操作须本机 root、宿主机范围及规范绝对数据目录")
	}
	if action != "enable" && action != "disable" && action != "status" && action != "refresh" {
		return out, errors.New("未知持续同步操作")
	}
	if action == "status" || action == "refresh" {
		if operationID != "" || base != "" || runtimeBase != "" || recoverOnBoot {
			return out, errors.New("同步状态及通知不接受操作、基础标识或封禁配置")
		}
		return callFail2banHostSync(ctx, dataDir, action)
	}
	if !validID(operationID) || base != "" && !validID(base) || runtimeBase != "" && !validID(runtimeBase) || operationID == base || action == "disable" && (runtimeBase != "" || recoverOnBoot) {
		return out, errors.New("同步操作 UUID 或基础标识无效，停用不接受运行基础标识")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	leave, err := fail2banHostSyncLocks(dataDir)
	if err != nil {
		return out, err
	}
	defer leave()
	if err = fail2banHostRetirementIdle(dataDir); err != nil {
		return out, err
	}
	current, err := loadFail2banHostSync(dataDir)
	if err != nil {
		return out, err
	}
	if current != nil && current.ID == operationID {
		if current.Action != action || current.PreviousID != base || action == "enable" && (current.RuntimeBaseID != runtimeBase || current.RecoverOnBoot != recoverOnBoot) {
			return out, errors.New("同一持续同步操作的请求内容变化")
		}
		return fail2banHostSyncMetadata(current), nil
	}
	if current == nil && base != "" || current != nil && current.ID != base {
		return out, errors.New("持续同步批准基础变化，请重新读取状态")
	}
	if action == "disable" {
		if current == nil || current.Action != "enable" {
			return out, errors.New("没有可停用的持续同步会话")
		}
		if _, e := (&Journal{Dir: filepath.Join(dataDir, "agent", "operations")}).Get(operationID); !os.IsNotExist(e) {
			if e == nil {
				e = errors.New("停用标识已用于其他操作")
			}
			return out, e
		}
		stopping, e := loadFail2banHostSyncStop(dataDir, current)
		if e != nil {
			return out, e
		}
		if stopping != nil && stopping.ID != operationID {
			return out, errors.New("已有持续停用意图，请沿原操作标识恢复")
		}
		if stopping == nil {
			copy := *current
			copy.ID, copy.PreviousID, copy.Action, copy.ApprovedAt = operationID, current.ID, "disable", time.Now().Unix()
			copy.RequestHash = copy.requestHash()
			stopping = &copy
			if e = writeFail2banHostSyncEvent(dataDir, stopping); e != nil {
				return out, e
			}
			if e = rootJSONWrite(filepath.Join(fail2banHostSyncDir(dataDir), "stopping.json"), struct {
				ID string `json:"id"`
			}{stopping.ID}, 1024); e != nil {
				return out, e
			}
		}
		if e = finishFail2banHostSyncStop(ctx, dataDir, current, stopping); e != nil {
			out = fail2banHostSyncMetadata(current)
			out.State, out.Reason = "stopping", "停用已持久记录，规则清除尚未完成"
			return out, e
		}
		return fail2banHostSyncMetadata(stopping), nil
	}
	if current != nil && current.Action == "enable" {
		return out, errors.New("当前持续同步仍获批准，须先停用和清除，再开启新会话")
	}
	if _, err = loadFail2banHostSyncStop(dataDir, current); err != nil {
		return out, err
	}
	observer := firewallObserver{scope: "host", ctx: ctx, dataDir: dataDir}
	call, stopObserve := context.WithTimeout(ctx, 6*time.Second)
	err = checkFirewallManagers(observer.collect(call))
	stopObserve()
	if err != nil {
		return out, err
	}
	admit, err := fail2banHostSyncAdmission(dataDir, true)
	if err != nil {
		return out, err
	}
	defer admit()
	runtime, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return out, err
	}
	if runtime == nil && runtimeBase != "" || runtime != nil && (runtime.Intent.OperationID != runtimeBase || runtime.State == "running" || runtime.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, runtime)) {
		return out, errors.New("启用同步的运行基础变化或尚未核对")
	}
	basis, err := loadFail2banHostSourcesBasis(ctx, dataDir)
	if err != nil {
		return out, err
	}
	protection, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return out, err
	}
	sources, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return out, err
	}
	if protection == nil || protection.Action != "approve" || sources == nil || sources.Action != "approve" {
		return out, errors.New("须先批准保护与官方 jail 来源")
	}
	if _, err = readFail2banHostSources(ctx, dataDir, basis.kernel, basis.registration, basis.protected); err != nil {
		return out, err
	}
	event := &fail2banHostSyncEvent{Schema: 1, ID: operationID, PreviousID: base, Action: action, SessionID: operationID, Owner: basis.root.Owner, RegistrationID: basis.root.OperationID, NamespaceID: basis.kernel.NamespaceID, EngineKey: sources.EngineKey, ProtectionID: protection.ID, SourcesID: sources.ID, RuntimeBaseID: runtimeBase, ApprovedAt: time.Now().Unix()}
	if recoverOnBoot {
		event.MachineIDHash, event.BootID, err = fail2banHostBootIdentity()
		if err != nil {
			return out, err
		}
		event.RecoverOnBoot = true
	}
	event.RequestHash = event.requestHash()
	if err = writeFail2banHostSyncEvent(dataDir, event); err != nil {
		return out, err
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if previous, e := j.Get(event.ID); e == nil {
		if !fail2banHostSyncParentMatches(previous, event) || previous.State != "running" || previous.Stage != "approved" || previous.AfterRevision != "" {
			return out, errors.New("同步会话操作标识已使用，不得回退旧会话")
		}
	} else if !os.IsNotExist(e) {
		return out, e
	} else if err = j.Put(fail2banHostSyncParent(event)); err != nil {
		return out, err
	}
	if err = publishFail2banHostSync(dataDir, event); err != nil {
		return out, err
	}
	return fail2banHostSyncMetadata(event), nil
}
