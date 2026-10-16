package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
)

func fail2banHostSourcesMetadata(event *fail2banHostSourcesEvent) fail2ban.HostInputSourcesView {
	out := fail2ban.EmptyHostInputSources("官方封禁来源尚未完整采集")
	if event == nil {
		out.State, out.Reason = "unapproved", "尚未由目标本机 root 批准官方 jail 封禁来源"
		return out
	}
	out.Managed = event.Policy.Managed
	out.ID, out.ApprovedAt, out.Jails = event.ID, event.ApprovedAt, append([]string{}, event.Policy.Jails...)
	if event.Action == "revoke" {
		out.State, out.Reason = "revoked", "官方封禁来源批准已撤销，未直接移除运行封禁"
	}
	return out
}

func readFail2banHostSources(ctx context.Context, dataDir string, kernel firewall.KernelView, registration firewall.RegistrationView, protected []string) (fail2banHostSample, error) {
	event, err := loadFail2banHostSources(dataDir)
	out := fail2banHostSample{view: fail2banHostSourcesMetadata(event), addresses: []string{}}
	if err != nil {
		out.view.State, out.view.Reason = "unavailable", "官方封禁来源批准无法完整读取"
		return out, err
	}
	if event == nil || event.Action == "revoke" {
		return out, errors.New(out.view.Reason)
	}
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		out.view.Reason = "独立登记无法完整读取"
		return out, err
	}
	if root == nil || !registration.Verified || root.State != "registered" || root.Owner != event.Owner || root.OperationID != event.RegistrationID || registration.OperationID != event.RegistrationID || kernel.NamespaceID != event.NamespaceID || root.Confirmed.NamespaceID != kernel.NamespaceID {
		out.view.State, out.view.Reason = "stale", "官方封禁来源对应的登记、所有者或命名空间变化，须目标本机重新批准"
		return out, errors.New(out.view.Reason)
	}
	sample, err := collectFail2banHost(ctx, dataDir, event, protected)
	if err != nil {
		out.view.Reason = err.Error()
		return out, err
	}
	return sample, nil
}

type fail2banHostSourcesBasis struct {
	root         *fail2banHostRegistration
	kernel       firewall.KernelView
	registration firewall.RegistrationView
	protected    []string
}

func loadFail2banHostSourcesBasis(ctx context.Context, dataDir string) (fail2banHostSourcesBasis, error) {
	var out fail2banHostSourcesBasis
	var err error
	out.root, err = loadFail2banHostRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if out.root == nil || out.root.State != "registered" {
		return out, errors.New("须先完成宿主机动作空表登记")
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	out.kernel, err = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	cancel()
	if err != nil {
		return out, err
	}
	out.registration = fail2banHostRegistrationViewRecord(dataDir, out.kernel, out.root)
	if !out.registration.Verified {
		return out, errors.New(out.registration.Reason)
	}
	protection := fail2banHostProtectionView(dataDir, out.kernel, out.registration)
	if !protection.Verified {
		return out, errors.New(protection.Reason)
	}
	out.protected, err = fail2banHostProtectedSources(ctx, fail2ban.HostInputProtectionPolicy{AdminSources: protection.AdminSources, ProxySources: protection.ProxySources})
	return out, err
}

func readFail2banHostSourcesStatus(ctx context.Context, dataDir string) (fail2ban.HostInputSourcesView, error) {
	event, err := loadFail2banHostSources(dataDir)
	out := fail2banHostSourcesMetadata(event)
	if err != nil {
		out.State, out.Reason = "unavailable", "官方封禁来源批准无法读取"
		return out, err
	}
	if event == nil || event.Action == "revoke" {
		return out, nil
	}
	basis, err := loadFail2banHostSourcesBasis(ctx, dataDir)
	if err != nil {
		out.Reason = err.Error()
		return out, err
	}
	sample, err := readFail2banHostSources(ctx, dataDir, basis.kernel, basis.registration, basis.protected)
	return sample.view, err
}

// No HTTP/IPC write entry, Nginx manifest or caller-provided ban IP exists here.
// The fixed official client reads explicitly approved names or host jails
// derived from the approved managed installation's current configuration.
func ManageFail2banHostSources(ctx context.Context, dataDir, scope, action, operationID, base, policyFile string) (fail2ban.HostInputSourcesView, error) {
	out := fail2ban.EmptyHostInputSources("尚未核对宿主机官方封禁来源")
	if action != "approve" && action != "revoke" && action != "status" {
		return out, errors.New("未知官方封禁来源操作")
	}
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" {
		return out, errors.New("官方封禁来源批准须本机 root 确认 --fail2ban-scope=host，容器范围不允许")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("封禁来源数据目录须为规范绝对路径")
	}
	if action == "status" {
		if operationID != "" || base != "" || policyFile != "" {
			return out, errors.New("封禁来源状态读取不接受操作、基础标识或文件")
		}
		return readFail2banHostSourcesStatus(ctx, dataDir)
	}
	if !validID(operationID) || base != "" && !validID(base) || operationID == base {
		return out, errors.New("须提供有效操作 UUID 与当前封禁来源批准作为基础标识")
	}
	policy := fail2banHostSourcesPolicy{Jails: []string{}}
	if action == "approve" {
		if !filepath.IsAbs(policyFile) || filepath.Clean(policyFile) != policyFile {
			return out, errors.New("来源文件须为 root 私有的规范绝对路径")
		}
		if err := readFail2banHostProtectionJSON(policyFile, &policy); err != nil {
			return out, err
		}
		var err error
		if policy, err = policy.normalize(); err != nil {
			return out, err
		}
	} else if policyFile != "" {
		return out, errors.New("撤销封禁来源不接受来源文件")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("fail2ban-host-input.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banHostRetirementIdle(dataDir); err != nil {
		return out, err
	}
	current, err := loadFail2banHostSources(dataDir)
	if err != nil {
		return out, err
	}
	if current != nil && current.ID == operationID {
		if current.Action != action || current.PreviousID != base || policy.Managed != current.Policy.Managed || !sameFail2banHostJails(policy.Jails, current.Policy.Jails) {
			return out, errors.New("相同来源操作标识的请求内容变化")
		}
		out, err = readFail2banHostSourcesStatus(ctx, dataDir)
		if err == nil && (out.ID != operationID || action == "approve" && out.State != "ready" || action == "revoke" && out.State != "revoked") {
			err = errors.New("原来源批准结果无法核对，请读取状态")
		}
		return out, err
	}
	if current == nil && base != "" || current != nil && current.ID != base {
		return out, errors.New("封禁来源批准基础标识变化，请重新读取状态")
	}
	event := &fail2banHostSourcesEvent{Schema: 1, ID: operationID, PreviousID: base, Action: action, Policy: policy, ApprovedAt: time.Now().Unix()}
	var sample fail2banHostSample
	if action == "approve" {
		journal := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
		leave, e := journal.maintenanceLock()
		if e != nil {
			return out, e
		}
		defer leave()
		records, e := journal.List()
		if e != nil {
			return out, e
		}
		for _, r := range records {
			if r.Kind == "maintenance.lock" && r.State != "succeeded" {
				return out, errors.New("维护期间禁止新增封禁来源批准")
			}
		}
		basis, e := loadFail2banHostSourcesBasis(ctx, dataDir)
		if e != nil {
			return out, e
		}
		binding, e := selectFail2banBinding(dataDir)
		if e != nil || binding == nil || binding.State != "bound" {
			return out, errors.New("没有当前有效的官方实例读取授权")
		}
		event.Owner, event.RegistrationID, event.NamespaceID, event.EngineKey = basis.root.Owner, basis.root.OperationID, basis.kernel.NamespaceID, fail2banNginxEngineKey(binding)
		event.RequestHash = event.requestHash()
		sample, e = collectFail2banHost(ctx, dataDir, event, basis.protected)
		if e != nil {
			return out, e
		}
	} else {
		if current == nil || current.Action != "approve" {
			return out, errors.New("不存在可撤销的封禁来源批准")
		}
		event.Owner, event.RegistrationID, event.NamespaceID, event.EngineKey = current.Owner, current.RegistrationID, current.NamespaceID, current.EngineKey
		event.RequestHash = event.requestHash()
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = saveFail2banHostSources(dataDir, event); err != nil {
		return out, err
	}
	saved, err := loadFail2banHostSources(dataDir)
	if err != nil || saved == nil || saved.ID != event.ID || saved.RequestHash != event.RequestHash {
		out = fail2banHostSourcesMetadata(event)
		out.State, out.Reason = "unavailable", "封禁来源批准发布结果无法完整核对，请读取状态"
		if event.Action == "revoke" {
			out.Jails = []string{}
			out.ID, out.ApprovedAt = "", 0
		}
		return out, errors.Join(errors.New(out.Reason), err)
	}
	if action == "revoke" {
		return fail2banHostSourcesMetadata(saved), nil
	}
	sample.view.ApprovedAt = saved.ApprovedAt
	return sample.view, nil
}
