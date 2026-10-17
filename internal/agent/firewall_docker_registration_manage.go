package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type DockerFirewallRegistrationStatus struct {
	Grant   firewall.DockerRegistrationView `json:"grant"`
	Runtime firewall.DockerRuntime          `json:"runtime"`
}

func dockerRegistrationStatus(ctx context.Context, dataDir string) DockerFirewallRegistrationStatus {
	observed := (&firewallObserver{scope: "host", dataDir: dataDir, dockerInventory: true}).collect(ctx)
	return DockerFirewallRegistrationStatus{Grant: observed.Docker.Registration, Runtime: observed.Docker.Runtime}
}

func checkedDockerRegistrationStatus(ctx context.Context, dataDir, state string) (DockerFirewallRegistrationStatus, error) {
	out := dockerRegistrationStatus(ctx, dataDir)
	if out.Grant.Registration.State != state || state == "registered" && !out.Grant.Registration.Verified {
		return out, errors.New("Docker 授权状态尚未核对：" + out.Grant.Registration.Reason)
	}
	return out, nil
}

// Both local registrations use the same persistent host claim. Releasing or
// replacing that parent is fenced until this additional grant is released.
// Metadata publication performs no iptables writes or Docker mutations.
func ManageDockerFirewallRegistration(parent context.Context, dataDir, scope, engineHash, action string) (DockerFirewallRegistrationStatus, error) {
	var out DockerFirewallRegistrationStatus
	if !slices.Contains([]string{"init", "status", "recover", "remove"}, action) || action == "init" && !firewalldDigest(engineHash) || action != "init" && engineHash != "" {
		return out, errors.New("Docker 初始化须明确 --firewall-docker-engine；状态、恢复与释放沿用原实例")
	}
	if os.Geteuid() != 0 || scope != "host" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return out, errors.New("Docker 转发授权须真实宿主机 root、规范绝对数据目录及 --firewall-scope=host")
	}
	machine, boot, err := iptablesHostIdentity()
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if action == "status" {
		return dockerRegistrationStatus(ctx, dataDir), nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-business.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	registryUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return out, err
	}
	defer registryUnlock()
	if iptablesRegistrationPending(dataDir) {
		return out, errors.New("请先恢复原 iptables 宿主机授权或业务操作")
	}
	if err = secure.RootDirectory(filepath.Dir(dockerRegistrationPath(dataDir)), 0700); err != nil {
		return out, err
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
	if action != "recover" {
		records, err := (&maintenanceGate{journal: j}).records()
		if err != nil {
			return out, err
		}
		for _, record := range records {
			if record.Kind == "maintenance.lock" && record.State != "succeeded" {
				return out, errors.New("独立维护正在进行，禁止新建或释放 Docker 转发授权")
			}
		}
	}
	v, err := loadDockerRegistration(dataDir)
	if err != nil {
		return out, err
	}
	if v != nil && v.MachineHash != machine {
		return out, errors.New("Docker root 授权属于其他宿主机，禁止迁移或接管")
	}
	if action == "recover" {
		if v == nil {
			return out, errors.New("没有可恢复的 Docker 授权意图")
		}
		if err = dockerRegistrationReceipt(dataDir, v); err != nil {
			if err = saveDockerRegistration(dataDir, v); err != nil {
				return out, err
			}
			if err = dockerRegistrationReceipt(dataDir, v); err != nil {
				return out, err
			}
		}
		if v.State == "preparing" {
			return reconcileDockerRegistration(ctx, dataDir, v)
		}
		return checkedDockerRegistrationStatus(ctx, dataDir, v.State)
	}
	if action == "remove" && v != nil && v.State == "preparing" {
		if v.Action == "remove" {
			return reconcileDockerRegistration(ctx, dataDir, v)
		}
		// Explicit local release can cancel the original init even if the daemon
		// is now offline. Preserve the original operation as a failed terminal.
		baseline, _, err := inspectDockerRegistration(ctx, dataDir, v, false)
		if err != nil {
			return out, dockerRegistrationUncertain(dataDir, v, err)
		}
		v.State, v.OperationState, v.Error, v.VerifiedConfigurationHash, v.UpdatedAt = "released", "failed", "原 Docker 授权意图已由本机 root 撤回", baseline.Hash, time.Now().Unix()
		if err = saveDockerRegistration(dataDir, v); err != nil {
			return out, err
		}
		return checkedDockerRegistrationStatus(ctx, dataDir, "released")
	}
	if v != nil && (v.State == "preparing" || dockerRegistrationReceipt(dataDir, v) != nil) {
		return out, errors.New("Docker 原授权操作未完成，请先执行 docker-firewall-recover")
	}
	if action == "remove" && v != nil && v.State == "released" {
		return checkedDockerRegistrationStatus(ctx, dataDir, "released")
	}
	if action == "remove" && v == nil {
		return out, errors.New("没有可释放的 Docker 转发授权")
	}
	if action == "init" && v != nil && v.State == "registered" {
		if engineHash != v.EngineHash {
			return out, errors.New("已有其他 Docker 实例授权，须先显式释放原授权")
		}
		return checkedDockerRegistrationStatus(ctx, dataDir, "registered")
	}
	registration, err := iptablesRegistrationAuthority(dataDir)
	if err != nil {
		return out, err
	}
	intent := &dockerRegistrationCheckpoint{Schema: 1, DataDir: dataDir, MachineHash: machine, BootID: boot, Owner: secure.ID(), ParentOwner: registration.NextClaim.Owner, ParentOperationID: registration.NextClaim.OperationID, ParentRequestHash: registration.RequestHash, Backend: registration.NextClaim.Backend, EngineHash: engineHash, OperationID: secure.ID(), Action: action, State: "preparing", OperationState: "running"}
	if v != nil {
		intent.PreviousOperationID, intent.PreviousReceiptHash = v.OperationID, dockerRegistrationReceiptHash(v)
	}
	if action == "remove" {
		if !dockerRegistrationParent(v, registration) {
			return out, errors.New("Docker 原宿主机授权已变化，不能释放其他登记")
		}
		intent.Owner, intent.EngineHash = v.Owner, v.EngineHash
	}
	baseline, _, err := inspectDockerRegistration(ctx, dataDir, intent, action == "init")
	if err != nil {
		return out, err
	}
	intent.ConfigurationHash, intent.ToolHash = baseline.Hash, baseline.ToolHash
	intent.RequestHash = dockerRegistrationHash(intent)
	if err = saveDockerRegistration(dataDir, intent); err != nil {
		return out, err
	}
	return reconcileDockerRegistration(ctx, dataDir, intent)
}

func inspectDockerRegistration(ctx context.Context, dataDir string, v *dockerRegistrationCheckpoint, daemon bool) (iptablesRegistrationSnapshot, firewall.DockerRuntime, error) {
	var baseline iptablesRegistrationSnapshot
	runtime := firewall.EmptyDockerRuntime("释放授权不要求 Docker 在线")
	registration, err := iptablesRegistrationAuthority(dataDir)
	if err != nil {
		return baseline, runtime, err
	}
	if !dockerRegistrationParent(v, registration) || iptablesRegistrationPending(dataDir) {
		return baseline, runtime, errors.New("Docker 授权绑定的宿主机占用或原业务无法核对")
	}
	business, err := loadIPTablesChange(dataDir)
	if err != nil {
		return baseline, runtime, err
	}
	var inspectErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		source := iptablesPlanPrevious(business, registration.NextClaim.Owner, registration.NextClaim.OperationID)
		if source != nil {
			baseline, inspectErr = inspectIPTablesSource(ctx, dataDir, source, false)
		} else {
			baseline, inspectErr = inspectIPTablesRegistration(ctx, dataDir, registration.NextClaim.Backend, false)
		}
	}()
	if daemon {
		wg.Add(1)
		go func() { defer wg.Done(); runtime = readDockerFirewallRuntime(ctx) }()
	}
	wg.Wait()
	if inspectErr != nil {
		return baseline, runtime, inspectErr
	}
	if daemon {
		if !runtime.Available || runtime.Rootless || runtime.Swarm != "inactive" || runtime.EngineHash != v.EngineHash || baseline.Observed.Docker.BackendHint != "iptables" {
			return baseline, runtime, errors.New("所选 Docker 实例、rootful/Swarm 状态或 iptables 转发后端无法核对")
		}
		if !slices.ContainsFunc(baseline.Images, func(image iptablesImage) bool { return observeDockerFirewallHook(image).Observed }) {
			return baseline, runtime, errors.New("未观察到对应后端的完整 DOCKER-USER 挂接")
		}
	}
	return baseline, runtime, ctx.Err()
}

func dockerRegistrationUncertain(dataDir string, v *dockerRegistrationCheckpoint, cause error) error {
	v.State, v.OperationState, v.Error, v.UpdatedAt = "preparing", "recovery_required", boundedIPTablesError(cause), time.Now().Unix()
	if err := saveDockerRegistration(dataDir, v); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func reconcileDockerRegistration(ctx context.Context, dataDir string, v *dockerRegistrationCheckpoint) (DockerFirewallRegistrationStatus, error) {
	var out DockerFirewallRegistrationStatus
	baseline, _, err := inspectDockerRegistration(ctx, dataDir, v, v.Action == "init")
	if err != nil {
		return out, dockerRegistrationUncertain(dataDir, v, err)
	}
	// Recovery rechecks the original parent, engine and empty namespace. Foreign
	// rule changes are not replayed or treated as permission to install rules.
	v.State = "registered"
	if v.Action == "remove" {
		v.State = "released"
	}
	v.OperationState, v.Error, v.VerifiedConfigurationHash, v.UpdatedAt = "succeeded", "", baseline.Hash, time.Now().Unix()
	if err = saveDockerRegistration(dataDir, v); err != nil {
		return out, err
	}
	return checkedDockerRegistrationStatus(ctx, dataDir, v.State)
}
