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

func readFail2banHostProtection(ctx context.Context, dataDir string) (fail2ban.HostInputProtectionView, error) {
	event, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return fail2ban.EmptyHostInputProtection("宿主机保护批准记录无法读取，须本机检查"), err
	}
	if event == nil || event.Action == "revoke" {
		return fail2banHostProtectionView(dataDir, firewall.KernelView{}, firewall.RegistrationView{}), nil
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	kernel, err := snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
	registration := fail2banHostRegistrationView(dataDir, kernel)
	return fail2banHostProtectionView(dataDir, kernel, registration), err
}

// Local root approval concerns actual TCP peer ranges. It is not a jail grant,
// a claim that every proxy was discovered, or authority to submit kernel rules.
// Revocation changes only admission metadata and never removes live bans.
func ManageFail2banHostProtection(ctx context.Context, dataDir, scope, action, operationID, base, policyFile string) (fail2ban.HostInputProtectionView, error) {
	out := fail2ban.EmptyHostInputProtection("尚未核对宿主机保护来源批准")
	if action != "approve" && action != "revoke" && action != "status" {
		return out, errors.New("未知宿主机保护来源操作")
	}
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" {
		return out, errors.New("保护来源批准须本机 root 明确指定 --fail2ban-scope=host，容器范围不允许")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("宿主机保护批准数据目录须为规范绝对路径")
	}
	if action == "status" {
		if operationID != "" || base != "" || policyFile != "" {
			return out, errors.New("保护批准状态读取不接受操作、基础标识或来源文件")
		}
		return readFail2banHostProtection(ctx, dataDir)
	}
	if !validID(operationID) || base != "" && !validID(base) || operationID == base {
		return out, errors.New("保护批准须提供新操作 UUID 和当前保护批准 UUID 作为基础标识")
	}
	policy := fail2ban.HostInputProtectionPolicy{AdminSources: []string{}, ProxySources: []string{}}
	if action == "approve" {
		policy = fail2ban.HostInputProtectionPolicy{}
		if !filepath.IsAbs(policyFile) || filepath.Clean(policyFile) != policyFile {
			return out, errors.New("保护来源文件须为规范绝对路径，且由 root 私有持有")
		}
		if err := readFail2banHostProtectionJSON(policyFile, &policy); err != nil {
			return out, err
		}
		var err error
		if policy, err = policy.Normalize(); err != nil {
			return out, err
		}
	} else if policyFile != "" {
		return out, errors.New("撤销保护批准不接受来源文件")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("fail2ban-host-input.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banHostRetirementIdle(dataDir); err != nil {
		return out, err
	}
	current, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		return out, err
	}
	if current != nil && current.ID == operationID {
		if current.Action != action || current.PreviousID != base || current.PolicyHash != policy.Hash() {
			return out, errors.New("相同保护批准标识的请求内容发生变化")
		}
		out, err = readFail2banHostProtection(ctx, dataDir)
		if err == nil && action == "approve" && !out.Verified {
			err = errors.New(out.Reason)
		}
		if err == nil && (out.ID != current.ID || action == "revoke" && out.State != "revoked") {
			err = errors.New("原保护批准结果无法完整核对，请读取状态")
		}
		return out, err
	}
	if current == nil && base != "" || current != nil && current.ID != base {
		return out, errors.New("保护批准基础标识已变化，请重新读取状态")
	}
	event := &fail2banHostProtectionEvent{Schema: 1, ID: operationID, PreviousID: base, Action: action, ApprovedAt: time.Now().Unix(), Policy: policy, PolicyHash: policy.Hash()}
	var kernel firewall.KernelView
	var registration firewall.RegistrationView
	if action == "approve" {
		// New grants cannot race maintenance or registration removal. Revocation
		// remains possible during maintenance because it grants no new writes.
		journal := &Journal{Dir: filepath.Join(dataDir, "agent", "operations")}
		maintenanceUnlock, e := journal.maintenanceLock()
		if e != nil {
			return out, e
		}
		defer maintenanceUnlock()
		records, e := journal.List()
		if e != nil {
			return out, e
		}
		for _, record := range records {
			if record.Kind == "maintenance.lock" && record.State != "succeeded" {
				return out, errors.New("独立维护正在进行，禁止新增宿主机保护批准")
			}
		}
		rootRegistration, e := loadFail2banHostRegistration(dataDir)
		if e != nil {
			return out, e
		}
		if rootRegistration == nil || rootRegistration.State != "registered" {
			return out, errors.New("须先完成目标本机宿主机动作空表登记")
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		kernel, e = snapshotNFTTargetInspect(call, firewall.NFTFail2banInput, nil)
		cancel()
		if e != nil {
			return out, e
		}
		registration = fail2banHostRegistrationViewRecord(dataDir, kernel, rootRegistration)
		if !registration.Verified {
			return out, errors.New(registration.Reason)
		}
		event.Owner, event.RegistrationID, event.NamespaceID = rootRegistration.Owner, rootRegistration.OperationID, kernel.NamespaceID
	} else {
		if current == nil || current.Action != "approve" {
			return out, errors.New("不存在可撤销的保护来源批准")
		}
		event.Owner, event.RegistrationID, event.NamespaceID = current.Owner, current.RegistrationID, current.NamespaceID
	}
	event.RequestHash = event.requestHash()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = saveFail2banHostProtection(dataDir, event); err != nil {
		return out, err
	}
	out = fail2banHostProtectionView(dataDir, kernel, registration)
	if out.ID != event.ID || action == "approve" && !out.Verified || action == "revoke" && out.State != "revoked" {
		return out, errors.New("保护批准发布结果无法完整核对，请读取状态")
	}
	return out, nil
}
