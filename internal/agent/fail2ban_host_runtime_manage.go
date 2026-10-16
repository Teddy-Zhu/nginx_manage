package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
)

type Fail2banHostRuntimeStatus struct {
	Runtime fail2ban.HostInputRuntimeView `json:"runtime"`
	Kernel  firewall.KernelView           `json:"kernel"`
}

func readFail2banHostRuntimeStatus(ctx context.Context, dataDir string) (Fail2banHostRuntimeStatus, error) {
	out := Fail2banHostRuntimeStatus{Runtime: fail2ban.EmptyHostInputRuntime("宿主机动作运行状态无法核对")}
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return out, err
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out.Kernel, err = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	if err != nil {
		return out, err
	}
	out.Runtime = fail2banHostRuntimeView(dataDir, out.Kernel, root)
	return out, nil
}

func fail2banHostRuntimeBase(dataDir string, root *fail2banHostRegistration, current *fail2banHostRuntime) (fail2banHostProgram, firewall.KernelView, error) {
	marker, err := nftTargetRegistrationMarker(firewall.NFTFail2banInput, root.Owner)
	if err != nil {
		return fail2banHostProgram{}, firewall.KernelView{}, err
	}
	program, expected := fail2banHostProgram{Marker: marker}, root.Confirmed
	if current != nil {
		if current.State == "running" || current.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, current) {
			return program, expected, errors.New("存在未核对宿主机动作意图，须恢复原操作")
		}
		if fail2banHostRuntimeMatches(current, root) {
			program, expected = current.effective(), current.Confirmed
		}
	}
	return program, expected, nil
}

func checkFail2banHostRuntimeInputs(ctx context.Context, dataDir string, i fail2banHostRuntimeIntent) error {
	protection, err := loadFail2banHostProtection(dataDir)
	if err != nil || protection == nil || protection.Action != "approve" || protection.ID != i.ProtectionID || protection.Owner != i.Owner || protection.RegistrationID != i.RegistrationID || protection.NamespaceID != i.Baseline.NamespaceID {
		return errors.New("提交前管理/代理保护批准变化")
	}
	sources, err := loadFail2banHostSources(dataDir)
	if err != nil || sources == nil || sources.Action != "approve" || i.Sources == nil || sources.ID != i.Sources.ID || sources.Owner != i.Owner || sources.RegistrationID != i.RegistrationID || sources.NamespaceID != i.Baseline.NamespaceID {
		return errors.New("提交前官方封禁来源批准变化")
	}
	protected, err := fail2banHostProtectedSources(ctx, protection.Policy)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(protected)
	b, _ := json.Marshal(i.Candidate.Set.Protected)
	if !bytes.Equal(a, b) {
		return errors.New("提交前本机保护地址变化，须重新采集和准备")
	}
	return ctx.Err()
}

// These local-root commands synchronize one explicit engine sample or remove
// this owner's rules. They do not expose a write IPC/API, install an action,
// replay a timed-out transaction or claim continuous ban/expiry automation.
func ManageFail2banHostRuntime(ctx context.Context, dataDir, scope, action, operationID, base string) (Fail2banHostRuntimeStatus, error) {
	out := Fail2banHostRuntimeStatus{Runtime: fail2ban.EmptyHostInputRuntime("尚未核对宿主机动作运行操作")}
	if action != "apply" && action != "clear" && action != "status" && action != "recover" {
		return out, errors.New("未知宿主机动作运行操作")
	}
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" {
		return out, errors.New("宿主机动作运行须本机 root 确认 --fail2ban-scope=host，容器范围不允许")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("宿主机动作数据目录须为规范绝对路径")
	}
	if action == "status" {
		if operationID != "" || base != "" {
			return out, errors.New("运行状态读取不接受操作或基础标识")
		}
		return readFail2banHostRuntimeStatus(ctx, dataDir)
	}
	if !validID(operationID) || base != "" && !validID(base) || operationID == base || action == "recover" && base != "" {
		return out, errors.New("须提供操作 UUID；恢复使用原标识，新事务使用当前运行操作为基础标识")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("fail2ban-host-input.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	// Freeze supported engine/lifecycle writers through sampling and submission.
	// Recovery and clear still work when the engine itself is offline.
	leaveBinding, err := (&Journal{Dir: fail2banBindingDir(dataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer leaveBinding()
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if root == nil || root.State != "registered" || !fail2banHostRegistrationReceipt(dataDir, root) {
		return out, errors.New("须先核对独立宿主机动作登记和原回执")
	}
	current, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return out, err
	}
	if action == "recover" {
		if current == nil || current.Intent.OperationID != operationID {
			// A crash between immutable intent and checkpoint publication has no
			// permission to resend. Adopt only its still-current original CAS.
			i, e := loadFail2banHostRuntimeIntent(dataDir, operationID)
			if e != nil {
				return out, e
			}
			if current == nil && i.BaseOperationID != "" || current != nil && (current.Intent.OperationID != i.BaseOperationID || current.State == "running" || current.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, current)) {
				return out, errors.New("原意图的基础操作已变化，禁止回退历史运行操作")
			}
			current = &fail2banHostRuntime{Intent: *i, State: "recovery_required", Error: "持久意图发布未完成，仅恢复观察，不重发事务"}
			if !fail2banHostRuntimeMatches(current, root) {
				return out, errors.New("原意图所属登记或命名空间已变化")
			}
			if e = saveFail2banHostRuntime(dataDir, current); e != nil {
				return out, e
			}
		}
		if !fail2banHostRuntimeMatches(current, root) {
			return out, errors.New("原运行操作所属登记已变化")
		}
		return recoverFail2banHostRuntime(ctx, dataDir, root, current)
	}
	requestHash := fail2banHostRuntimeRequest(action, operationID, base)
	if current != nil && current.Intent.OperationID == operationID {
		if current.Intent.RequestHash != requestHash {
			return out, errors.New("相同运行操作标识的请求内容变化")
		}
		out, err = readFail2banHostRuntimeStatus(ctx, dataDir)
		if err == nil && (current.State == "running" || current.State == "recovery_required" || !out.Runtime.Verified) {
			err = errors.New("原运行结果尚未完整核对，须恢复原操作")
		}
		if err == nil && current.State == "failed" {
			err = errors.New(current.Error)
		}
		return out, err
	}
	j := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
	if _, err = j.Get(operationID); !os.IsNotExist(err) {
		if err == nil {
			err = errors.New("运行操作标识已使用，禁止重放历史操作")
		}
		return out, err
	}
	if _, err = loadFail2banHostRuntimeIntent(dataDir, operationID); !os.IsNotExist(err) {
		if err == nil {
			err = errors.New("已存在原操作持久意图，请执行 fail2ban-host-runtime-recover")
		}
		return out, err
	}
	if current == nil && base != "" || current != nil && current.Intent.OperationID != base {
		return out, errors.New("宿主机动作运行基础标识变化，请重新读取状态")
	}
	before, expected, err := fail2banHostRuntimeBase(dataDir, root, current)
	if err != nil {
		return out, err
	}
	if action == "clear" && before.Set == nil {
		return out, errors.New("当前已为空表，无需创建移除规则事务")
	}
	leave, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer leave()
	records, err := j.List()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		if r.Kind == "maintenance.lock" && r.State != "succeeded" {
			return out, errors.New("维护期间禁止新增宿主机动作运行事务")
		}
		if action == "apply" && strings.HasPrefix(r.Kind, "fail2ban") && pendingNginxRecord(r) {
			return out, errors.New("存在未结束的 Fail2ban 实例或 jail 操作，暂不能同步宿主机封禁")
		}
	}
	if action == "apply" {
		observer := firewallObserver{scope: "host", ctx: ctx, dataDir: dataDir}
		call, stop := context.WithTimeout(ctx, 6*time.Second)
		err = checkFirewallManagers(observer.collect(call))
		stop()
		if err != nil {
			return out, err
		}
	}
	kernel, err := before.snapshot(ctx)
	if err != nil {
		return out, err
	}
	if !kernel.TableExists || kernel.NamespaceID != expected.NamespaceID || kernel.Fingerprint != expected.Fingerprint {
		return out, errors.New("原确认的宿主机动作对象缺失或漂移，禁止覆盖")
	}
	marker, _ := nftTargetRegistrationMarker(firewall.NFTFail2banInput, root.Owner)
	i := fail2banHostRuntimeIntent{Schema: 1, Owner: root.Owner, RegistrationID: root.OperationID, OperationID: operationID, BaseOperationID: base, Action: action, RequestHash: requestHash, Before: before, Candidate: fail2banHostProgram{Marker: marker}, Baseline: kernel}
	var sample fail2banHostSample
	if action == "apply" {
		registration := fail2banHostRegistrationViewRecord(dataDir, kernel, root)
		protection := fail2banHostProtectionView(dataDir, kernel, registration)
		if !protection.Verified {
			return out, errors.New(protection.Reason)
		}
		protected, e := fail2banHostProtectedSources(ctx, fail2ban.HostInputProtectionPolicy{AdminSources: protection.AdminSources, ProxySources: protection.ProxySources})
		if e != nil {
			return out, e
		}
		sample, e = readFail2banHostSources(ctx, dataDir, kernel, registration, protected)
		if e != nil {
			return out, e
		}
		i.ProtectionID, i.Sources = protection.ID, &sample.view
		i.Candidate = fail2banHostProgram{Set: &firewall.NFTBanSet{Addresses: sample.addresses, Protected: protected}, Marker: fail2banHostRuntimeMarker(root.Owner, operationID)}
	}
	batch, err := i.Candidate.batch(kernel)
	if err != nil {
		return out, err
	}
	i.TransactionHash = batch.Hash
	v := &fail2banHostRuntime{Intent: i, State: "running"}
	if err = saveFail2banHostRuntime(dataDir, v); err != nil {
		return out, err
	}
	// Re-read the complete original object after durable intent; the batch also
	// carries the generation precondition so concurrent policy changes reject it.
	pre, submitErr := before.snapshot(ctx)
	if submitErr == nil && (!pre.TableExists || pre.NamespaceID != kernel.NamespaceID || pre.Fingerprint != kernel.Fingerprint || pre.Generation != kernel.Generation) {
		submitErr = errors.New("提交前宿主机动作基线或内核代次变化")
	}
	if submitErr == nil && action == "apply" {
		submitErr = checkFail2banHostRuntimeInputs(ctx, dataDir, i)
		if submitErr == nil {
			submitErr = sample.unchanged(ctx, dataDir)
		}
		if submitErr == nil && time.Now().Unix()-sample.view.CollectedAt > 5 {
			submitErr = errors.New("官方封禁样本已超过提交时限，须恢复原操作后重新采集")
		}
	}
	if submitErr == nil {
		namespace, e := nftNamespace()
		if e != nil {
			submitErr = e
		} else if namespace != kernel.NamespaceID {
			submitErr = errors.New("发送宿主机动作事务前网络命名空间变化")
		}
	}
	if submitErr == nil {
		call, stop := context.WithTimeout(ctx, 3*time.Second)
		submitErr = submitNFTBatch(call, batch.Wire)
		stop()
	}
	post, postErr := i.Candidate.snapshot(context.Background())
	wantGeneration := kernel.Generation + 1
	if wantGeneration == 0 {
		wantGeneration = 1
	}
	if submitErr == nil && postErr == nil && post.TableExists && post.NamespaceID == kernel.NamespaceID && post.Generation == wantGeneration {
		v.State, v.Confirmed = "succeeded", post
		if err = saveFail2banHostRuntime(dataDir, v); err != nil {
			return out, err
		}
		return Fail2banHostRuntimeStatus{Runtime: fail2banHostRuntimeView(dataDir, post, root), Kernel: post}, nil
	}
	v.State, v.Error = "recovery_required", "宿主机动作提交结果未完整证明，须以原标识执行 fail2ban-host-runtime-recover；不会自动重发"
	if err = saveFail2banHostRuntime(dataDir, v); err != nil {
		return out, err
	}
	return Fail2banHostRuntimeStatus{Runtime: fail2banHostRuntimeView(dataDir, post, root), Kernel: post}, errors.Join(errors.New(v.Error), submitErr, postErr)
}

func recoverFail2banHostRuntime(ctx context.Context, dataDir string, root *fail2banHostRegistration, v *fail2banHostRuntime) (Fail2banHostRuntimeStatus, error) {
	var out Fail2banHostRuntimeStatus
	if v.State == "succeeded" || v.State == "failed" {
		kernel, err := v.effective().snapshot(ctx)
		if err != nil {
			return out, err
		}
		if !kernel.TableExists || kernel.NamespaceID != v.Confirmed.NamespaceID || kernel.Fingerprint != v.Confirmed.Fingerprint {
			return out, errors.New("已确认运行对象缺失或变化，禁止改写终态审计或重放封禁")
		}
		if !fail2banHostRuntimeReceipt(dataDir, v) {
			if err = saveFail2banHostRuntime(dataDir, v); err != nil {
				return out, err
			}
		}
		out = Fail2banHostRuntimeStatus{Runtime: fail2banHostRuntimeView(dataDir, kernel, root), Kernel: kernel}
		if v.State == "failed" {
			return out, errors.New(v.Error)
		}
		return out, nil
	}
	// Only the unique candidate or exact original fingerprint can settle an
	// unknown outcome. Missing/foreign objects never trigger a compensating write.
	kernel, candidateErr := v.Intent.Candidate.snapshot(ctx)
	if candidateErr == nil && kernel.TableExists && kernel.NamespaceID == v.Intent.Baseline.NamespaceID {
		v.State, v.Confirmed, v.Error = "succeeded", kernel, ""
	} else {
		before, err := v.Intent.Before.snapshot(ctx)
		if err != nil || !before.TableExists || before.NamespaceID != v.Intent.Baseline.NamespaceID || before.Fingerprint != v.Intent.Baseline.Fingerprint {
			return out, errors.Join(errors.New("原事务结果仍未知或对象漂移，保留意图，禁止重发与覆盖"), candidateErr, err)
		}
		kernel = before
		v.State, v.Confirmed, v.Error = "failed", before, "原事务未生效，已核对原对象；未重发或恢复历史封禁"
	}
	if err := saveFail2banHostRuntime(dataDir, v); err != nil {
		return out, err
	}
	out = Fail2banHostRuntimeStatus{Runtime: fail2banHostRuntimeView(dataDir, kernel, root), Kernel: kernel}
	if v.State == "failed" {
		return out, errors.New(v.Error)
	}
	return out, nil
}
