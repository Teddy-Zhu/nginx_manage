package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type IPTablesRegistrationStatus = firewall.IPTablesRegistrationView

func iptablesRegistrationStatus(ctx context.Context, dataDir string) IPTablesRegistrationStatus {
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	observed := (&firewallObserver{scope: "host", dataDir: dataDir, skipIPTablesRegistration: true}).collect(call)
	cancel()
	return iptablesRegistrationView(ctx, dataDir, observed)
}

// Grant and release only metadata for an empty logical namespace. No kernel
// command, alternatives change or global manager operation belongs here.
func ManageIPTablesRegistration(parent context.Context, dataDir, scope, backend, action string) (IPTablesRegistrationStatus, error) {
	var out IPTablesRegistrationStatus
	if !slices.Contains([]string{"init", "status", "recover", "remove"}, action) || action == "init" && !validIPTablesBackend(backend) || action != "init" && backend != "" {
		return out, errors.New("初始化须显式选择 --firewall-backend=iptables-nft|iptables-legacy；状态、释放和恢复沿用原登记后端")
	}
	if os.Geteuid() != 0 || scope != "host" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("iptables 授权登记须本机 root、规范绝对数据目录及 --firewall-scope=host")
	}
	machine, boot, err := iptablesHostIdentity()
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if action == "status" {
		return iptablesRegistrationStatus(ctx, dataDir), nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	for _, dir := range []string{filepath.Dir(iptablesRegistrationPath(dataDir)), filepath.Dir(iptablesHostClaimPath)} {
		if err = secure.RootDirectory(dir, 0700); err != nil {
			return out, err
		}
	}
	j := iptablesRegistrationJournal(dataDir)
	if err = secure.RootDirectory(j.Dir, 0700); err != nil {
		return out, err
	}
	maintenanceUnlock, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenanceUnlock()
	v, err := loadIPTablesRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if v != nil && v.NextClaim.MachineHash != machine {
		return out, errors.New("iptables root 登记属于其他宿主机，禁止迁移或接管")
	}
	if action == "recover" {
		if v == nil {
			return out, errors.New("没有可恢复的 iptables 授权意图")
		}
		// Only repair the original metadata publication. There is no rule
		// invocation to retry, even after a receipt-publication crash.
		if err = iptablesRegistrationReceipt(dataDir, v); err != nil {
			if err = saveIPTablesRegistration(dataDir, v); err != nil {
				return out, err
			}
		}
		if v.State == "preparing" {
			return reconcileIPTablesRegistration(ctx, dataDir, v)
		}
		if v.State == "released" {
			if err = finishIPTablesRelease(ctx, dataDir, v); err != nil {
				return out, err
			}
		}
		return checkedIPTablesRegistrationStatus(ctx, dataDir, v.State)
	}
	if v != nil && (v.State == "preparing" || iptablesRegistrationReceipt(dataDir, v) != nil) {
		return out, errors.New("iptables 原授权操作未完成，请先执行 iptables-recover")
	}
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, errors.New("独立维护正在进行，禁止 iptables 新授权或释放")
		}
	}
	if action == "init" && v != nil && v.State == "registered" {
		if backend != v.NextClaim.Backend {
			return out, errors.New("已有其他 iptables 后端授权，须先由原数据目录明确释放")
		}
		return checkedIPTablesRegistrationStatus(ctx, dataDir, "registered")
	}
	if action == "remove" && v != nil && v.State == "released" {
		return checkedIPTablesRegistrationStatus(ctx, dataDir, "released")
	}
	claim, err := loadIPTablesHostClaim()
	if err != nil {
		return out, err
	}
	if claim != nil && claim.MachineHash != machine {
		return out, errors.New("iptables 宿主机占用属于其他机器，禁止接管")
	}
	next := iptablesHostClaim{Schema: 1, Owner: secure.ID(), OperationID: secure.ID(), DataDir: dataDir, MachineHash: machine, Backend: backend, State: "registered"}
	if action == "init" {
		if err = iptablesReleasedClaim(claim); err != nil {
			return out, err
		}
	} else {
		if v == nil || v.State != "registered" || iptablesClaimHash(claim) != iptablesClaimHash(&v.NextClaim) {
			return out, errors.New("仅可释放原数据目录占用的 iptables 空命名空间授权")
		}
		if _, err = iptablesRegistrationAuthority(dataDir); err != nil {
			return out, err
		}
		next.Owner, next.State, next.Backend = v.NextClaim.Owner, "released", v.NextClaim.Backend
	}
	baseline, err := inspectIPTablesRegistration(ctx, dataDir, next.Backend, action == "init")
	if err != nil {
		return out, err
	}
	intent := &iptablesRegistrationCheckpoint{Schema: 1, BootID: boot, Action: action, State: "preparing", OperationState: "running", PreviousClaim: claim, NextClaim: next, ConfigurationHash: baseline.Hash, ToolHash: baseline.ToolHash}
	if v != nil {
		intent.PreviousOperationID = v.NextClaim.OperationID
	}
	intent.RequestHash = iptablesRegistrationHash(intent)
	if err = saveIPTablesRegistration(dataDir, intent); err != nil {
		return out, err
	}
	return reconcileIPTablesRegistration(ctx, dataDir, intent)
}

func checkedIPTablesRegistrationStatus(ctx context.Context, dataDir, state string) (IPTablesRegistrationStatus, error) {
	out := iptablesRegistrationStatus(ctx, dataDir)
	if out.Registration.State != state || state == "registered" && !out.Registration.Verified {
		return out, errors.New("iptables 授权状态变化或核对尚未完成：" + out.Registration.Reason)
	}
	return out, nil
}

func reconcileIPTablesRegistration(ctx context.Context, dataDir string, v *iptablesRegistrationCheckpoint) (IPTablesRegistrationStatus, error) {
	var out IPTablesRegistrationStatus
	before, err := inspectIPTablesRegistration(ctx, dataDir, v.NextClaim.Backend, v.Action == "init")
	if err != nil {
		return out, iptablesRegistrationUncertain(dataDir, v, err)
	}
	claim, err := loadIPTablesHostClaim()
	if err != nil {
		return out, iptablesRegistrationUncertain(dataDir, v, err)
	}
	publishing := iptablesPublishingClaim(v)
	if iptablesClaimHash(claim) != iptablesClaimHash(&publishing) && iptablesClaimHash(claim) != iptablesClaimHash(&v.NextClaim) {
		if iptablesClaimHash(claim) != iptablesClaimHash(v.PreviousClaim) {
			return out, iptablesRegistrationUncertain(dataDir, v, errors.New("iptables 宿主机占用已变化，拒绝覆盖其他授权"))
		}
		if v.Action == "init" {
			if err = iptablesReleasedClaim(claim); err != nil {
				return out, iptablesRegistrationUncertain(dataDir, v, err)
			}
		}
		if err = listenerWrite(iptablesHostClaimPath, &publishing); err != nil {
			return out, iptablesRegistrationUncertain(dataDir, v, err)
		}
	}
	after, err := inspectIPTablesRegistration(ctx, dataDir, v.NextClaim.Backend, v.Action == "init")
	if err != nil {
		return out, iptablesRegistrationUncertain(dataDir, v, err)
	}
	if before.Hash != after.Hash {
		return out, iptablesRegistrationUncertain(dataDir, v, errors.New("iptables 环境、工具或规则在授权核对期间变化，请恢复原操作重新核对"))
	}
	current, err := loadIPTablesHostClaim()
	if err != nil || iptablesClaimHash(current) != iptablesClaimHash(&publishing) && iptablesClaimHash(current) != iptablesClaimHash(&v.NextClaim) {
		return out, iptablesRegistrationUncertain(dataDir, v, errors.New("iptables 宿主机占用在核对期间变化"))
	}
	v.State, v.OperationState, v.VerifiedConfigurationHash, v.Error = v.NextClaim.State, "succeeded", after.Hash, ""
	if err = saveIPTablesRegistration(dataDir, v); err != nil {
		return out, err
	}
	if v.Action == "remove" {
		if err = listenerWrite(iptablesHostClaimPath, &v.NextClaim); err != nil {
			return out, err
		}
	}
	out.Backend = v.NextClaim.Backend
	out.Registration = firewall.RegistrationView{State: v.State, Verified: v.State == "registered", OperationID: v.NextClaim.OperationID, ObservedAt: time.Now().Unix()}
	if out.Registration.Verified {
		out.Registration.Reason = "iptables 本机空命名空间授权已核对；未安装业务规则"
	}
	return out, nil
}

func finishIPTablesRelease(ctx context.Context, dataDir string, v *iptablesRegistrationCheckpoint) error {
	claim, err := loadIPTablesHostClaim()
	if err != nil {
		return err
	}
	publishing := iptablesPublishingClaim(v)
	if iptablesClaimHash(claim) != iptablesClaimHash(&publishing) {
		if claim != nil && claim.OperationID == v.NextClaim.OperationID && iptablesClaimHash(claim) != iptablesClaimHash(&v.NextClaim) {
			return errors.New("iptables 原释放记录变化，禁止覆盖")
		}
		return nil
	}
	before, err := inspectIPTablesRegistration(ctx, dataDir, v.NextClaim.Backend, false)
	if err != nil {
		return err
	}
	after, err := inspectIPTablesRegistration(ctx, dataDir, v.NextClaim.Backend, false)
	if err != nil {
		return err
	}
	if before.Hash != after.Hash {
		return errors.New("iptables 环境变化，尚未发布宿主机释放结果")
	}
	current, err := loadIPTablesHostClaim()
	if err != nil || iptablesClaimHash(current) != iptablesClaimHash(&publishing) {
		return errors.New("iptables 宿主机占用变化，禁止覆盖")
	}
	return listenerWrite(iptablesHostClaimPath, &v.NextClaim)
}

func iptablesRegistrationUncertain(dataDir string, v *iptablesRegistrationCheckpoint, cause error) error {
	v.OperationState, v.Error = "recovery_required", "iptables 授权元数据尚未完整核对，请本机恢复原操作；未执行规则变更"
	return errors.Join(cause, saveIPTablesRegistration(dataDir, v))
}
