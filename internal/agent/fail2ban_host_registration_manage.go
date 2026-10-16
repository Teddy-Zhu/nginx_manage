package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type Fail2banHostInputRegistrationStatus struct {
	Registration   firewall.RegistrationView `json:"registration"`
	Kernel         firewall.KernelView       `json:"kernel"`
	OperationState string                    `json:"operation_state"`
}

func fail2banHostRegistrationStatus(dataDir string, kernel firewall.KernelView, v *fail2banHostRegistration) Fail2banHostInputRegistrationStatus {
	out := Fail2banHostInputRegistrationStatus{Kernel: kernel, Registration: fail2banHostRegistrationViewRecord(dataDir, kernel, v), OperationState: "unregistered"}
	if v != nil {
		out.OperationState = v.OperationState
	}
	return out
}

// ManageFail2banHostInputRegistration is local-root only. It never installs a
// hook, applies bans, authorizes imported policies or exposes a write IPC API.
// New writes require a caller UUID and CAS against the last root operation.
func ManageFail2banHostInputRegistration(ctx context.Context, dataDir, scope, action, operationID, base string) (Fail2banHostInputRegistrationStatus, error) {
	var out Fail2banHostInputRegistrationStatus
	if action != "init" && action != "status" && action != "recover" && action != "remove" {
		return out, errors.New("未知宿主机动作登记操作")
	}
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" {
		return out, errors.New("宿主机动作登记须本机 root 明确指定 --fail2ban-scope=host，容器范围不允许")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("宿主机动作数据目录须为规范绝对路径")
	}
	if action == "status" {
		if operationID != "" || base != "" {
			return out, errors.New("登记状态读取不接受操作或基础标识")
		}
		return readFail2banHostRegistration(ctx, dataDir)
	}
	if !validID(operationID) || base != "" && !validID(base) || base == operationID || action == "recover" && base != "" {
		return out, errors.New("须提供有效操作 UUID；恢复使用原操作标识，新建或移除使用当前登记作为基础标识")
	}
	// Shared by every future writer of this target, even across data directories.
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("fail2ban-host-input.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = secure.RootDirectory(filepath.Dir(fail2banHostRegistrationPath(dataDir)), 0700); err != nil {
		return out, err
	}
	v, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if action == "recover" {
		if v == nil || v.OperationID != operationID {
			return out, errors.New("恢复标识与当前独立登记不一致，请先读取登记状态")
		}
		return recoverFail2banHostRegistration(dataDir, v)
	}
	requestHash := fail2banHostRegistrationRequest(action, operationID, base)
	if v != nil && v.OperationID == operationID {
		if v.RequestHash != requestHash {
			return out, errors.New("相同操作标识的登记请求发生变化")
		}
		out, err = readFail2banHostRegistration(ctx, dataDir)
		if err == nil && (!fail2banHostRegistrationReceipt(dataDir, v) || v.State == "creating" || v.State == "removing") {
			err = errors.New("原登记操作待恢复，禁止重复提交")
		}
		if err == nil && v.OperationState == "failed" {
			err = errors.New(v.Error)
		}
		if err == nil && out.Registration.State != v.State {
			err = errors.New(out.Registration.Reason)
		}
		return out, err
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if _, err = j.Get(operationID); !os.IsNotExist(err) {
		if err == nil {
			err = errors.New("操作标识已使用，不得重放历史登记操作")
		}
		return out, err
	}
	if v == nil && base != "" || v != nil && v.OperationID != base {
		return out, errors.New("宿主机动作登记基础标识已变化，请重新核对")
	}
	if v != nil && (v.State == "creating" || v.State == "removing" || !fail2banHostRegistrationReceipt(dataDir, v)) {
		return out, errors.New("存在未核对的登记意图或回执，请先恢复原操作")
	}
	// Maintenance admission cannot interleave between the durable intent and
	// result; recovery itself remains observation-only and works during downtime.
	maintenanceUnlock, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenanceUnlock()
	records, err := j.List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, errors.New("独立维护正在进行，禁止新建或移除宿主机动作登记")
		}
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	var kernel firewall.KernelView
	if v != nil && v.State == "registered" {
		kernel, err = snapshotFail2banHostRegistration(call, v.Owner)
	} else {
		kernel, err = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	}
	cancel()
	if err != nil {
		return out, err
	}
	if action == "init" {
		if v != nil && v.State == "registered" || kernel.TableExists {
			return out, errors.New("宿主机动作目标已存在或已登记，不得接管或重新初始化")
		}
		v = &fail2banHostRegistration{Schema: 1, Owner: secure.ID(), OperationID: operationID, BaseOperationID: base, Action: action, State: "creating", OperationState: "running", RequestHash: requestHash, Baseline: kernel}
	} else {
		if v == nil || v.State != "registered" || !kernel.TableExists || kernel.NamespaceID != v.Confirmed.NamespaceID || kernel.Fingerprint != v.Confirmed.Fingerprint {
			return out, errors.New("只能移除原样存在且有独立所有权证明的空表")
		}
		v.OperationID, v.BaseOperationID, v.Action = operationID, base, action
		v.State, v.OperationState, v.RequestHash, v.Baseline, v.Error = "removing", "running", requestHash, kernel, ""
	}
	batch, err := prepareNFTTargetRegistration(firewall.NFTFail2banInput, v.Baseline, v.Owner, action == "remove")
	if err != nil {
		return out, err
	}
	v.TransactionHash = batch.hash
	if err = saveFail2banHostRegistration(dataDir, v); err != nil {
		return out, err
	}
	call, cancel = context.WithTimeout(ctx, 3*time.Second)
	namespace, err := nftNamespace()
	if err == nil && namespace != v.Baseline.NamespaceID {
		err = errors.New("提交宿主机动作登记前网络命名空间变化")
	}
	if err == nil {
		err = submitNFTRegistration(call, batch)
	}
	cancel()
	post, postErr := fail2banHostRegistrationSnapshotDetached(v.Owner)
	wantGeneration := v.Baseline.Generation + 1
	if wantGeneration == 0 {
		wantGeneration = 1
	}
	if err == nil && postErr == nil && post.NamespaceID == v.Baseline.NamespaceID && post.Generation == wantGeneration && post.TableExists == (action == "init") {
		if action == "init" {
			v.State, v.Confirmed = "registered", post
		} else {
			v.State = "released"
		}
		v.OperationState, v.Error = "succeeded", ""
		if err = saveFail2banHostRegistration(dataDir, v); err != nil {
			return out, err
		}
		return fail2banHostRegistrationStatus(dataDir, post, v), nil
	}
	v.OperationState, v.Error = "recovery_required", "登记提交结果未完整证明，须使用原操作标识执行 fail2ban-host-input-recover；不会自动重放"
	if saveErr := saveFail2banHostRegistration(dataDir, v); saveErr != nil {
		return out, saveErr
	}
	return fail2banHostRegistrationStatus(dataDir, post, v), errors.Join(errors.New(v.Error), err, postErr)
}

func readFail2banHostRegistration(ctx context.Context, dataDir string) (Fail2banHostInputRegistrationStatus, error) {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	kernel, err := snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	if err != nil {
		return Fail2banHostInputRegistrationStatus{}, err
	}
	v, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return Fail2banHostInputRegistrationStatus{Kernel: kernel, Registration: firewall.RegistrationView{State: "unavailable", ObservedAt: kernel.ObservedAt, Reason: "宿主机动作 root 登记无法读取，须本机检查"}, OperationState: "unconfirmed"}, err
	}
	return fail2banHostRegistrationStatus(dataDir, kernel, v), nil
}

// Reconciliation never submits a transaction or rewrites a terminal receipt.
// A missing confirmed table produces a new linked detach record instead.
func recoverFail2banHostRegistration(dataDir string, v *fail2banHostRegistration) (Fail2banHostInputRegistrationStatus, error) {
	var out Fail2banHostInputRegistrationStatus
	kernel, err := fail2banHostRegistrationSnapshotDetached(v.Owner)
	if err != nil {
		return out, err
	}
	out.Kernel = kernel
	if v.State == "released" {
		if kernel.TableExists {
			return out, errors.New("已释放登记但存在同名表，禁止接管")
		}
	} else if v.State == "registered" {
		if kernel.TableExists {
			if kernel.NamespaceID != v.Confirmed.NamespaceID || kernel.Fingerprint != v.Confirmed.Fingerprint {
				return out, errors.New("已确认登记对象发生变化，禁止更新所有权证明")
			}
		} else {
			previousID := v.OperationID
			// Preserve the completed original audit before advancing the pointer.
			if !fail2banHostRegistrationReceipt(dataDir, v) {
				if err = saveFail2banHostRegistration(dataDir, v); err != nil {
					return out, err
				}
			}
			v = &fail2banHostRegistration{Schema: 1, Owner: v.Owner, OperationID: secure.ID(), BaseOperationID: previousID, Action: "detach", State: "released", OperationState: "succeeded", Baseline: kernel, Confirmed: v.Confirmed, Error: "登记表缺失，已释放当前所有权；未重建或修改其他命名空间对象"}
			v.RequestHash = fail2banHostRegistrationRequest(v.Action, v.OperationID, v.BaseOperationID)
			v.TransactionHash = fail2banHostDetachHash(v)
		}
	} else if kernel.NamespaceID != v.Baseline.NamespaceID {
		if kernel.TableExists {
			return out, errors.New("命名空间已变化且存在同名表，禁止接管")
		}
		v.State, v.OperationState, v.Error = "released", "failed", "命名空间已变化，未证明原事务结果且未修改旧命名空间对象"
	} else if v.State == "creating" {
		if kernel.TableExists {
			v.State, v.Confirmed, v.OperationState, v.Error = "registered", kernel, "succeeded", ""
		} else {
			v.State, v.OperationState, v.Error = "released", "failed", "未观察到原登记表，未重试创建"
		}
	} else if !kernel.TableExists {
		v.State, v.OperationState, v.Error = "released", "succeeded", ""
	} else {
		if kernel.Fingerprint != v.Confirmed.Fingerprint {
			return out, errors.New("原移除结果不明且对象已变化，禁止覆盖")
		}
		v.State, v.OperationState, v.Error = "registered", "failed", "原空表仍存在，未重试移除"
	}
	if !fail2banHostRegistrationReceipt(dataDir, v) {
		if err = saveFail2banHostRegistration(dataDir, v); err != nil {
			return out, err
		}
	}
	return fail2banHostRegistrationStatus(dataDir, kernel, v), nil
}
