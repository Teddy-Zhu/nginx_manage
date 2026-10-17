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

type UFWRegistrationStatus struct {
	Registration firewall.RegistrationView `json:"registration"`
}

func ufwRegistrationStatus(ctx context.Context, dataDir string) UFWRegistrationStatus {
	return UFWRegistrationStatus{Registration: ufwRegistrationView(ctx, dataDir, readUFW(ctx))}
}

func inspectUFWRegistration(ctx context.Context, dataDir string, active bool) (ufwConfigurationSnapshot, error) {
	var out ufwConfigurationSnapshot
	if active {
		nftRuntime, err := loadFirewallState(dataDir)
		if err != nil {
			return out, err
		}
		fwRuntime, err := loadFirewalldState(dataDir)
		if err != nil {
			return out, err
		}
		if nftRuntime != nil || fwRuntime != nil {
			return out, errors.New("已有其他防火墙业务恢复材料，禁止 UFW 新授权")
		}
		nft, err := loadNFTRegistration(dataDir)
		if err != nil {
			return out, err
		}
		fw, err := loadFirewalldRegistration(dataDir)
		if err != nil {
			return out, err
		}
		if nft != nil && nft.State != "released" || fw != nil && fw.State != "released" {
			return out, errors.New("其他防火墙登记尚未释放，禁止切换 UFW")
		}
	}
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	observed := (&firewallObserver{scope: "host", dataDir: dataDir}).collect(call)
	if !observed.Available || !observed.UFW.Installed || observed.UFW.Enabled == nil || observed.UFW.Active == nil || observed.UFW.IPv6 == nil || !observed.UFW.RuleInventory.Available {
		return out, errors.New("UFW 工具、固定配置和完整用户规则报告不可核对")
	}
	if active {
		if observed.Manager != "ufw" || observed.Backend == "mixed" || !*observed.UFW.Enabled || !*observed.UFW.Active || !observed.Kernel.Available || observed.Kernel.TableExists || len(observed.Rulesets) != 5 {
			return out, errors.New("须完整确认单一启用的 UFW 且不存在直接 nftables 目标表")
		}
		for _, view := range observed.Rulesets {
			if !view.Available {
				return out, errors.New("部分内核后端视图不完整，禁止 UFW 新授权")
			}
		}
	}
	binary, err := ufwTool()
	if err != nil {
		return out, err
	}
	out, err = readUFWConfiguration(call, binary, *observed.UFW.IPv6)
	if err != nil {
		return out, err
	}
	if out.HasManagedMarkers {
		return out, errors.New("固定 UFW 配置中存在本应用标记但无规则写入回执，禁止接管或释放")
	}
	return out, nil
}

// These commands only manage root metadata for an empty rule namespace. They
// never add/delete rules, enable/reload UFW, or reconstruct manager files.
func ManageUFWRegistration(parent context.Context, dataDir, scope, action string) (UFWRegistrationStatus, error) {
	var out UFWRegistrationStatus
	if !slices.Contains([]string{"init", "status", "recover", "remove"}, action) {
		return out, errors.New("未知 UFW 授权登记操作")
	}
	if os.Geteuid() != 0 || scope != "host" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return out, errors.New("UFW 授权登记须本机 root、规范绝对数据目录及 --firewall-scope=host")
	}
	machine, boot, err := ufwHostIdentity()
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if action == "status" {
		return ufwRegistrationStatus(ctx, dataDir), nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = secure.RootDirectory(filepath.Dir(ufwRegistrationPath(dataDir)), 0700); err != nil {
		return out, err
	}
	if err = secure.RootDirectory(filepath.Dir(ufwHostClaimPath), 0700); err != nil {
		return out, err
	}
	j := ufwRegistrationJournal(dataDir)
	if err = secure.RootDirectory(j.Dir, 0700); err != nil {
		return out, err
	}
	maintenanceUnlock, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer maintenanceUnlock()
	v, err := loadUFWRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if v != nil && v.NextClaim.MachineHash != machine {
		return out, errors.New("UFW root 登记属于其他宿主机，禁止迁移或接管")
	}
	if ufwRestorePending(dataDir) {
		if action != "recover" {
			return out, errors.New("UFW 原重载进程或业务操作尚未完成，禁止初始化或释放授权")
		}
		if err = recoverUFWRestore(ctx, dataDir); err != nil {
			return out, err
		}
	}
	if action == "recover" {
		if v == nil {
			return out, errors.New("没有可恢复的 UFW 授权登记")
		}
		// A checkpoint/receipt publication gap is repaired from the trusted
		// original metadata intent. No UFW command is replayed.
		if err = ufwRegistrationReceipt(dataDir, v); err != nil {
			if err = saveUFWRegistration(dataDir, v); err != nil {
				return out, err
			}
		}
		if v.State != "preparing" {
			if v.State == "released" {
				if err = finishUFWRelease(ctx, dataDir, v); err != nil {
					return out, err
				}
			}
			out = ufwRegistrationStatus(ctx, dataDir)
			if v.State == "registered" && !out.Registration.Verified || v.State == "released" && out.Registration.State != "released" {
				return out, errors.New(out.Registration.Reason)
			}
			return out, nil
		}
		return reconcileUFWRegistration(ctx, dataDir, v)
	}
	if v != nil {
		if err = ufwRegistrationReceipt(dataDir, v); err != nil || v.State == "preparing" {
			return out, errors.New("UFW 原授权操作未完成，请先执行 ufw-recover")
		}
	}
	records, err := (&maintenanceGate{journal: j}).records()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, errors.New("独立维护正在进行，禁止 UFW 新授权或释放")
		}
	}
	if action == "init" && v != nil && v.State == "registered" {
		out = ufwRegistrationStatus(ctx, dataDir)
		if !out.Registration.Verified {
			return out, errors.New(out.Registration.Reason)
		}
		return out, nil
	}
	if action == "remove" && v != nil && v.State == "released" {
		out = ufwRegistrationStatus(ctx, dataDir)
		if out.Registration.State != "released" {
			return out, errors.New("UFW 释放尚未完成，请执行 ufw-recover 核对原操作")
		}
		return out, nil
	}
	claim, err := loadUFWHostClaim()
	if err != nil {
		return out, err
	}
	if claim != nil && claim.MachineHash != machine {
		return out, errors.New("UFW 宿主机占用属于其他机器，禁止接管")
	}
	next := ufwHostClaim{Schema: 1, Owner: secure.ID(), OperationID: secure.ID(), DataDir: dataDir, MachineHash: machine, State: "registered"}
	if action == "init" {
		if err = ufwReleasedClaim(claim); err != nil {
			return out, err
		}
	} else {
		if v == nil || v.State != "registered" || ufwClaimHash(claim) != ufwClaimHash(&v.NextClaim) {
			return out, errors.New("仅可释放原数据目录仍占用的 UFW 空命名空间授权")
		}
		if _, err = ufwRegistrationAuthority(dataDir); err != nil {
			return out, err
		}
		next.Owner, next.State = v.NextClaim.Owner, "released"
	}
	baseline, err := inspectUFWRegistration(ctx, dataDir, action == "init")
	if err != nil {
		return out, err
	}
	intent := &ufwRegistrationCheckpoint{Schema: 1, BootID: boot, Action: action, State: "preparing", OperationState: "running", PreviousClaim: claim, NextClaim: next, ConfigurationHash: baseline.Hash, ToolHash: baseline.ToolHash}
	if v != nil {
		intent.PreviousOperationID = v.NextClaim.OperationID
	}
	intent.RequestHash = ufwRegistrationHash(intent)
	if err = saveUFWRegistration(dataDir, intent); err != nil {
		return out, err
	}
	return reconcileUFWRegistration(ctx, dataDir, intent)
}

func reconcileUFWRegistration(ctx context.Context, dataDir string, v *ufwRegistrationCheckpoint) (UFWRegistrationStatus, error) {
	var out UFWRegistrationStatus
	before, err := inspectUFWRegistration(ctx, dataDir, v.Action == "init")
	if err != nil {
		return out, ufwRegistrationUncertain(dataDir, v, err)
	}
	claim, err := loadUFWHostClaim()
	if err != nil {
		return out, ufwRegistrationUncertain(dataDir, v, err)
	}
	publishing := ufwPublishingClaim(v)
	if ufwClaimHash(claim) != ufwClaimHash(&publishing) && ufwClaimHash(claim) != ufwClaimHash(&v.NextClaim) {
		if ufwClaimHash(claim) != ufwClaimHash(v.PreviousClaim) {
			return out, ufwRegistrationUncertain(dataDir, v, errors.New("UFW 宿主机占用已变化，拒绝覆盖其他授权"))
		}
		if v.Action == "init" {
			if err = ufwReleasedClaim(claim); err != nil {
				return out, ufwRegistrationUncertain(dataDir, v, err)
			}
		}
		// The host lock is held across the metadata compare and rename. A
		// crash after this write is reconciled against the exact next claim.
		if err = listenerWrite(ufwHostClaimPath, &publishing); err != nil {
			return out, ufwRegistrationUncertain(dataDir, v, err)
		}
	}
	after, err := inspectUFWRegistration(ctx, dataDir, v.Action == "init")
	if err != nil {
		return out, ufwRegistrationUncertain(dataDir, v, err)
	}
	if before.Hash != after.Hash {
		return out, ufwRegistrationUncertain(dataDir, v, errors.New("UFW 源配置在授权核对期间变化，请恢复原操作重新核对"))
	}
	current, err := loadUFWHostClaim()
	if err != nil || ufwClaimHash(current) != ufwClaimHash(&publishing) && ufwClaimHash(current) != ufwClaimHash(&v.NextClaim) {
		return out, ufwRegistrationUncertain(dataDir, v, errors.New("UFW 宿主机占用在核对期间变化"))
	}
	v.State, v.OperationState, v.VerifiedConfigurationHash, v.Error = v.NextClaim.State, "succeeded", after.Hash, ""
	if err = saveUFWRegistration(dataDir, v); err != nil {
		return out, err
	}
	if v.Action == "remove" {
		if err = listenerWrite(ufwHostClaimPath, &v.NextClaim); err != nil {
			return out, err
		}
	}
	out.Registration = firewall.RegistrationView{State: v.State, Verified: v.State == "registered", OperationID: v.NextClaim.OperationID, ObservedAt: time.Now().Unix()}
	if out.Registration.Verified {
		out.Registration.Reason = "UFW 本机授权已核对；尚无已确认规则，未开放业务写入"
	}
	return out, nil
}

func finishUFWRelease(ctx context.Context, dataDir string, v *ufwRegistrationCheckpoint) error {
	claim, err := loadUFWHostClaim()
	if err != nil {
		return err
	}
	publishing := ufwPublishingClaim(v)
	if ufwClaimHash(claim) != ufwClaimHash(&publishing) {
		if claim != nil && claim.OperationID == v.NextClaim.OperationID && ufwClaimHash(claim) != ufwClaimHash(&v.NextClaim) {
			return errors.New("UFW 原释放记录变化，禁止覆盖")
		}
		return nil
	}
	before, err := inspectUFWRegistration(ctx, dataDir, false)
	if err != nil {
		return err
	}
	after, err := inspectUFWRegistration(ctx, dataDir, false)
	if err != nil {
		return err
	}
	if before.Hash != after.Hash {
		return errors.New("UFW 源配置变化，尚未发布宿主机释放结果")
	}
	current, err := loadUFWHostClaim()
	if err != nil || ufwClaimHash(current) != ufwClaimHash(&publishing) {
		return errors.New("UFW 宿主机占用变化，禁止覆盖")
	}
	return listenerWrite(ufwHostClaimPath, &v.NextClaim)
}
func ufwRegistrationUncertain(dataDir string, v *ufwRegistrationCheckpoint, cause error) error {
	v.OperationState, v.Error = "recovery_required", "UFW 授权元数据尚未完整核对，请本机恢复原操作；未执行规则变更"
	return errors.Join(cause, saveUFWRegistration(dataDir, v))
}
