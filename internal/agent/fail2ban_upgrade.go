package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type Fail2banUpgradeOptions struct {
	DataDir, Scope, PlanID, AssetID, TrustPath string
	Prerelease                                 bool
}

type Fail2banUpgradeComponent struct {
	Version        string `json:"version"`
	PlanID         string `json:"plan_id"`
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TrustSHA256    string `json:"trust_sha256"`
	EngineKey      string `json:"engine_key"`
}

type Fail2banUpgradeBans struct {
	ObservedAt int64  `json:"observed_at"`
	Count      int    `json:"count"`
	SHA256     string `json:"sha256"`
}

// This is a diagnostic result, not an installation or execution grant. A
// stopped engine has no live ban observation; nil must not be reported as zero.
type Fail2banUpgradePlan struct {
	At                    int64                    `json:"at"`
	Target                string                   `json:"target"`
	InstallationID        string                   `json:"installation_id"`
	EventID               string                   `json:"event_id"`
	JailSelection         string                   `json:"jail_selection"`
	Current               Fail2banUpgradeComponent `json:"current"`
	Candidate             Fail2banUpgradeComponent `json:"candidate"`
	Service               fail2ban.Service         `json:"service"`
	Running               bool                     `json:"running"`
	Jails                 []string                 `json:"jails"`
	Templates             []fail2ban.TemplateCheck `json:"templates"`
	Bans                  *Fail2banUpgradeBans     `json:"bans"`
	NginxGrants           int                      `json:"nginx_grants"`
	HostSourcesID         string                   `json:"host_sources_id"`
	HostSourcesActive     bool                     `json:"host_sources_active"`
	HostProtectionID      string                   `json:"host_protection_id"`
	HostProtectionActive  bool                     `json:"host_protection_active"`
	HostSyncID            string                   `json:"host_sync_id"`
	HostSyncActive        bool                     `json:"host_sync_active"`
	StateSnapshotRequired bool                     `json:"state_snapshot_required"`
	RestartRequired       bool                     `json:"restart_required"`
	Impacts               []string                 `json:"impacts"`
}

func fail2banUpgradeComponent(r *fail2banManagedRecord) Fail2banUpgradeComponent {
	return Fail2banUpgradeComponent{Version: r.Version, PlanID: r.PlanID, AssetID: r.AssetID, ManifestSHA256: r.ManifestSHA256, TrustSHA256: r.TrustSHA256, EngineKey: fail2banNginxEngineKey(r.binding())}
}

type fail2banUpgradeBasis struct {
	Current        fail2banManagedRecord
	Candidate      fail2banManagedRecord
	Bundle         *fail2banJailBundle
	Registry       fail2banNginxRegistry
	HostSources    *fail2banHostSourcesEvent
	HostProtection *fail2banHostProtectionEvent
	HostSync       *fail2banHostSyncEvent
	Service        fail2ban.Service
	Invocation     string
}

func (b fail2banUpgradeBasis) hash() string {
	// Admission time is not code identity. Ban observations are deliberately
	// separate: normal ban expiry must not change the configuration identity.
	b.Candidate.ApprovedAt = 0
	raw, _ := json.Marshal(b)
	return secure.Hash(append([]byte("fail2ban:upgrade-check:v1:\x00"), raw...))
}

func readFail2banUpgradeBasis(ctx context.Context, data string, candidate *fail2banManagedRecord) (fail2banUpgradeBasis, error) {
	var out fail2banUpgradeBasis
	r, err := loadFail2banManaged(data)
	if err != nil || r == nil || r.State != "installed" || r.ActionState != "completed" {
		return out, errors.Join(errors.New("升级检查须选择已完成操作的受管实例"), err)
	}
	out.Current, out.Candidate = *r, *candidate
	_, out.Bundle, err = selectedFail2banJails(r)
	if err != nil {
		return out, err
	}
	out.Registry, err = loadFail2banNginxRegistry(data)
	if err != nil {
		return out, err
	}
	out.HostSources, err = loadFail2banHostSources(data)
	if err != nil {
		return out, err
	}
	out.HostProtection, err = loadFail2banHostProtection(data)
	if err != nil {
		return out, err
	}
	out.HostSync, err = loadFail2banHostSync(data)
	if err != nil {
		return out, err
	}
	out.Service, out.Invocation, err = lifecycleService(ctx)
	if err != nil {
		return out, err
	}
	service := out.Service
	if service.Load != "loaded" || service.MainPID == nil || !(service.Active == "active" && *service.MainPID > 0 || (service.Active == "inactive" || service.Active == "failed") && *service.MainPID == 0) {
		return out, errors.New("受管服务须处于可核对的运行或停止状态")
	}
	return out, nil
}

func fail2banUpgradeIdle(j *Journal) error {
	if err := fail2banStateRestoreIdle(filepath.Dir(filepath.Dir(j.Dir)), ""); err != nil {
		return err
	}
	if err := fail2banHostRetirementIdle(filepath.Dir(filepath.Dir(j.Dir))); err != nil {
		return err
	}
	records, err := j.List()
	if err != nil {
		return err
	}
	for _, r := range records {
		if pendingNginxRecord(r) || r.Kind == "maintenance.lock" && r.State != "succeeded" {
			return errors.New("实例变更、Nginx 变更或独立维护尚未结束，不能检查升级候选")
		}
	}
	return nil
}

// PlanFail2banUpgrade authenticates and runs the unselected signed code only
// through fixed version, config-test and regex diagnostics. It never selects
// code, changes grants, stops the engine or writes its configuration/database.
func PlanFail2banUpgrade(parent context.Context, in Fail2banUpgradeOptions) (Fail2banUpgradePlan, error) {
	var out Fail2banUpgradePlan
	if err := fail2banManagedRoot(in.DataDir, in.Scope); err != nil {
		return out, err
	}
	input := fail2ban.LifecyclePreviewInput{EngineOwner: "managed", Action: "install", PlanID: in.PlanID, AssetID: in.AssetID, Prerelease: in.Prerelease}
	if err := input.Validate(); err != nil {
		return out, err
	}
	if !filepath.IsAbs(in.TrustPath) || filepath.Clean(in.TrustPath) != in.TrustPath || len(in.TrustPath) > 512 {
		return out, errors.New("升级检查须指定规范绝对路径的本机发行信任文件")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	unlock, err := (&Journal{Dir: fail2banBindingDir(in.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	j := &Journal{Dir: filepath.Join(in.DataDir, "agent", "operations")}
	access, err := j.maintenanceLock()
	if err != nil {
		return out, err
	}
	defer access()
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	binding, err := selectFail2banBinding(in.DataDir)
	if err != nil || binding == nil || binding.managed == nil {
		return out, errors.Join(errors.New("只能检查独立受管实例的签名升级候选，已有系统实例由包管理器维护"), err)
	}
	current := binding.managed
	if current.ActionState != "completed" {
		return out, errors.New("原实例操作尚未完成核对")
	}
	if err = verifyFail2banManaged(ctx, current, true); err != nil {
		return out, err
	}
	if err = fail2banManagedNoOther(ctx, in.DataDir, false); err != nil {
		return out, err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return out, err
	}
	candidate, err := admitFail2banManaged(ctx, Fail2banInstallOptions{DataDir: in.DataDir, Scope: in.Scope, OperationID: current.OperationID, PlanID: in.PlanID, AssetID: in.AssetID, TrustPath: in.TrustPath, Prerelease: in.Prerelease})
	if err != nil {
		return out, err
	}
	if candidate.PlanID == current.PlanID && candidate.AssetID == current.AssetID {
		return out, errors.New("候选与当前签名代码资产相同，无需升级")
	}
	if candidate.PythonPath != current.PythonPath || candidate.PythonSHA256 != current.PythonSHA256 || candidate.PythonVersion != current.PythonVersion || candidate.ManagerPath != current.ManagerPath || candidate.ManagerSHA256 != current.ManagerSHA256 {
		return out, errors.New("候选须复用原已登记解释器和管理程序，不能混入解释器或面板替换")
	}
	basis, err := readFail2banUpgradeBasis(ctx, in.DataDir, candidate)
	if err != nil {
		return out, err
	}
	if basis.Current.EventID != current.EventID {
		return out, ErrExternalChange
	}
	for _, client := range []bool{false, true} {
		raw, e := candidate.run(ctx, client, "--version")
		if e != nil || strings.TrimSpace(string(raw)) != "Fail2Ban v"+candidate.Version {
			return out, errors.Join(errors.New("候选官方服务端或客户端版本无法核对"), e)
		}
	}
	if _, err = fail2banManagedExec(ctx, candidate.python(), candidate.args(true, "-c", filepath.Join(current.work(), "config"), "-s", fail2banManagedSocket, "-t"), 8*time.Second, 16384); err != nil {
		return out, errors.Join(errors.New("候选官方客户端未通过完整当前配置校验"), err)
	}
	templateIDs := []string{}
	if basis.Bundle != nil {
		seen := map[string]bool{}
		for _, jail := range basis.Bundle.Policy.Jails {
			if jail.Enabled && !seen[jail.Template] {
				templateIDs = append(templateIDs, jail.Template)
				seen[jail.Template] = true
			}
		}
	}
	sort.Strings(templateIDs)
	checks := []fail2ban.TemplateCheck{}
	if len(templateIDs) != 0 {
		reader := &fail2banTemplateReader{data: in.DataDir, scope: "host"}
		checks = reader.collect(ctx, fail2ban.TemplateCheckInput{Templates: templateIDs}, fail2banProgram{kind: "fail2ban-regex", managed: candidate, unselected: true})
		if len(checks) != len(templateIDs) {
			return out, errors.New("候选过滤器样例检查不完整")
		}
		for _, check := range checks {
			if !check.Available || !check.Passed || check.Engine != candidate.engine() {
				return out, errors.New("候选官方过滤器样例未通过：" + check.Template)
			}
		}
	}
	var bans *Fail2banUpgradeBans
	if basis.Service.Active == "active" {
		proof, e := readFail2banJailRuntime(ctx, current, basis.Bundle)
		if e != nil {
			return out, e
		}
		raw, _ := json.Marshal(proof)
		if len(raw) > fail2banBanProofLimit {
			return out, errors.New("当前封禁证明超过升级检查预算")
		}
		bans = &Fail2banUpgradeBans{ObservedAt: time.Now().Unix(), SHA256: secure.Hash(raw)}
		for _, jail := range proof {
			bans.Count += len(jail)
		}
	}
	if err = verifyFail2banManaged(ctx, current, true); err != nil {
		return out, err
	}
	if err = verifyFail2banManaged(ctx, candidate, false); err != nil {
		return out, err
	}
	if err = fail2banManagedNoOther(ctx, in.DataDir, false); err != nil {
		return out, err
	}
	if err = fail2banManagedEffective(ctx); err != nil {
		return out, err
	}
	after, err := readFail2banUpgradeBasis(ctx, in.DataDir, candidate)
	if err != nil || after.hash() != basis.hash() {
		return out, errors.Join(errors.New("候选检查期间实例、配置、服务或动作授权已变化"), err)
	}
	if err = fail2banUpgradeIdle(j); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out = Fail2banUpgradePlan{At: time.Now().Unix(), Target: basis.hash(), InstallationID: current.OperationID, EventID: current.EventID, JailSelection: current.jailSelection, Current: fail2banUpgradeComponent(current), Candidate: fail2banUpgradeComponent(candidate), Service: basis.Service, Running: basis.Service.Active == "active", Jails: fail2banJailNames(basis.Bundle), Templates: checks, Bans: bans, StateSnapshotRequired: true, RestartRequired: basis.Service.Active == "active", Impacts: []string{"须在停止后保存匹配版本的加密状态快照；候选启动后核对官方恢复的未过期封禁", "原代码、配置和封禁恢复证明须保留至切换成功或完整补偿；不执行 pip 或安装系统包"}}
	if out.Running {
		out.Impacts = append(out.Impacts, "切换须单独授权停止及重启独立实例，封禁保护可能短暂中断")
	}
	for _, grant := range basis.Registry.Grants {
		if grant.EngineKey == out.Current.EngineKey {
			out.NginxGrants++
		}
	}
	if basis.HostSources != nil {
		out.HostSourcesID = basis.HostSources.ID
		out.HostSourcesActive = basis.HostSources.Action == "approve"
	}
	if basis.HostProtection != nil {
		out.HostProtectionID = basis.HostProtection.ID
		out.HostProtectionActive = basis.HostProtection.Action == "approve"
	}
	if basis.HostSync != nil {
		out.HostSyncID, out.HostSyncActive = basis.HostSync.ID, basis.HostSync.Action == "enable"
	}
	if out.NginxGrants != 0 || out.HostSourcesActive || out.HostProtectionActive || out.HostSyncActive {
		out.Impacts = append(out.Impacts, "代码身份变化后须核对并迁移 Nginx/宿主机动作批准及持续同步授权，不能沿用旧引擎身份")
	}
	if bans == nil {
		out.Impacts = append(out.Impacts, "当前实例已停止，不能因代码切换擅自启动；未观测运行封禁，状态库保留内容须在独立快照及后续授权启动时核对")
	}
	return out, nil
}
