package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"nginxpanel/internal/secure"
)

const fail2banUpgradePreparationKind = "fail2ban_upgrade_preparation"
const fail2banUpgradePreparationLimit = 4 << 20

type Fail2banUpgradePreparationOptions struct {
	Fail2banUpgradeOptions
	OperationID string
	Target      string
}

func (in Fail2banUpgradePreparationOptions) hash() string {
	return fail2banUpgradeGrantHash("prepare-request", in)
}

type fail2banUpgradeMaterialIDs struct {
	Jails, Nginx, Sources, Stop, Sync, Clear string
}

type fail2banUpgradeMaterial struct {
	IDs     fail2banUpgradeMaterialIDs
	Bundle  *fail2banJailBundle
	Nginx   *fail2banNginxRegistry
	Sources *fail2banHostSourcesEvent
	Stop    *fail2banHostSyncEvent
	Sync    *fail2banHostSyncEvent
}

// Only the complete preparation directory publishes these materials. Events
// here are not active grants: none of the live authorization pointers change.
type fail2banUpgradePreparation struct {
	Schema    int
	CreatedAt int64
	Request   Fail2banUpgradePreparationOptions
	Basis     fail2banUpgradeBasis
	Grants    Fail2banUpgradeGrants
	Recovery  fail2banUpgradeHostRecovery
	Material  fail2banUpgradeMaterial
}

type fail2banUpgradePreparationReceipt struct {
	Schema              int    `json:"schema"`
	ID                  string `json:"id"`
	IntentSHA256        string `json:"intent_sha256"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	UnitSHA256          string `json:"unit_sha256"`
}

type Fail2banUpgradePreparation struct {
	State                  string                   `json:"state"`
	ID                     string                   `json:"id"`
	CreatedAt              int64                    `json:"created_at"`
	Target                 string                   `json:"target"`
	InstallationID         string                   `json:"installation_id"`
	EventID                string                   `json:"event_id"`
	Source                 Fail2banUpgradeComponent `json:"source"`
	Candidate              Fail2banUpgradeComponent `json:"candidate"`
	IntentSHA256           string                   `json:"intent_sha256"`
	ConfigurationSHA256    string                   `json:"configuration_sha256"`
	UnitSHA256             string                   `json:"unit_sha256"`
	CandidateJailSelection string                   `json:"candidate_jail_selection"`
	NginxRegistryID        string                   `json:"candidate_nginx_registry_id"`
	HostSourcesID          string                   `json:"candidate_host_sources_id"`
	HostStopID             string                   `json:"host_stop_id"`
	HostSyncID             string                   `json:"candidate_host_sync_id"`
	HostClearID            string                   `json:"host_clear_id"`
	ScopeCurrent           *bool                    `json:"scope_current"`
	CheckpointCurrent      *bool                    `json:"checkpoint_current"`
}

func fail2banUpgradePreparations(data string) string {
	return filepath.Join(fail2banBindingDir(data), "upgrade-preparations")
}

func (i fail2banUpgradePreparation) hash() string {
	return fail2banUpgradeGrantHash("preparation", i)
}

func (i fail2banUpgradePreparation) dir() string {
	return filepath.Join(fail2banUpgradePreparations(i.Request.DataDir), i.Request.OperationID)
}

func (i fail2banUpgradePreparation) receipt() (fail2banUpgradePreparationReceipt, error) {
	files, err := fail2banJailConfig(&i.Basis.Candidate, i.Material.Bundle)
	if err != nil {
		return fail2banUpgradePreparationReceipt{}, err
	}
	return fail2banUpgradePreparationReceipt{Schema: 1, ID: i.Request.OperationID, IntentSHA256: i.hash(), ConfigurationSHA256: fail2banUpgradeGrantHash("prepared-config", files), UnitSHA256: secure.Hash([]byte(i.Basis.Candidate.unit()))}, nil
}

func (i fail2banUpgradePreparation) record(r fail2banUpgradePreparationReceipt) Record {
	return Record{Kind: fail2banUpgradePreparationKind, OperationID: i.Request.OperationID, RequestHash: i.Request.hash(), RelatedOperationID: i.Basis.Current.OperationID, BeforeRevision: i.Basis.Current.EventID, AfterRevision: i.Material.IDs.Jails, CandidateHash: i.hash(), ObservedRevision: fail2banUpgradeGrantHash("preparation-receipt", r), State: "succeeded", Stage: "prepared"}
}

func newFail2banUpgradeMaterialIDs(b fail2banUpgradeBasis, p Fail2banUpgradeGrants, r fail2banUpgradeHostRecovery) fail2banUpgradeMaterialIDs {
	var ids fail2banUpgradeMaterialIDs
	if b.Bundle != nil {
		ids.Jails = secure.ID()
	}
	if len(p.NginxMoves) != 0 {
		ids.Nginx = secure.ID()
	}
	if p.MigrateHostSources {
		ids.Sources = secure.ID()
	}
	if p.MigrateHostSync {
		ids.Stop, ids.Sync = secure.ID(), secure.ID()
	}
	if r.Runtime != nil && r.Runtime.effective().Set != nil {
		ids.Clear = secure.ID()
	}
	return ids
}

func fail2banUpgradeOriginalIDs(b fail2banUpgradeBasis, r fail2banUpgradeHostRecovery) []string {
	old := []string{b.Current.OperationID, b.Current.EventID, b.Current.PreviousEvent, b.Current.JailSelection, b.Registry.ID}
	if b.HostSources != nil {
		old = append(old, b.HostSources.ID, b.HostSources.PreviousID)
	}
	if b.HostProtection != nil {
		old = append(old, b.HostProtection.ID)
	}
	if b.HostSync != nil {
		old = append(old, b.HostSync.ID, b.HostSync.PreviousID, b.HostSync.SessionID, b.HostSync.RuntimeBaseID)
	}
	if b.HostRegistration != nil {
		old = append(old, b.HostRegistration.Owner, b.HostRegistration.OperationID)
	}
	if r.Runtime != nil {
		old = append(old, r.Runtime.Intent.OperationID, r.Runtime.Intent.BaseOperationID)
	}
	return old
}

// Material reconstruction also validates disk reads. It cannot expand a
// policy, import a grant from another engine, or change the protection scope.
func buildFail2banUpgradeMaterial(b fail2banUpgradeBasis, p Fail2banUpgradeGrants, r fail2banUpgradeHostRecovery, ids fail2banUpgradeMaterialIDs, at int64) (out fail2banUpgradeMaterial, err error) {
	out.IDs = ids
	moves, retained, blockers := fail2banUpgradeNginxScope(b)
	if !p.ScopeVerified || len(p.Blockers) != 0 || len(blockers) != 0 || p.ScopeSHA256 != fail2banUpgradeGrantScopeHash(b) || p.NginxRegistryID != b.Registry.ID || p.NginxRegistrySHA256 != fail2banUpgradeGrantHash("nginx", b.Registry) || p.NginxRetained != retained || fail2banUpgradeGrantHash("moves", p.NginxMoves) != fail2banUpgradeGrantHash("moves", moves) {
		return out, errors.New("升级候选批准不符合原 Nginx 范围预检")
	}
	from := fail2banNginxEngineKey(b.Current.binding())
	migrateSources := b.HostSources != nil && b.HostSources.Action == "approve" && b.HostSources.EngineKey == from
	migrateSync := b.HostSync != nil && b.HostSync.Action == "enable" && b.HostSync.EngineKey == from
	if p.MigrateHostSources != migrateSources || p.MigrateHostSync != migrateSync || r.Stopping != nil || b.HostSources != nil && !b.HostSources.valid() || b.HostSync != nil && !b.HostSync.valid() || b.HostProtection != nil && !b.HostProtection.valid() || r.Runtime != nil && (!r.Runtime.valid() || r.Runtime.State != "succeeded" && r.Runtime.State != "failed") {
		return out, errors.New("升级候选批准不符合原宿主机范围或原事务尚未终结")
	}
	checks := []struct {
		id       string
		required bool
	}{{ids.Jails, b.Bundle != nil}, {ids.Nginx, len(p.NginxMoves) != 0}, {ids.Sources, p.MigrateHostSources}, {ids.Stop, p.MigrateHostSync}, {ids.Sync, p.MigrateHostSync}, {ids.Clear, r.Runtime != nil && r.Runtime.effective().Set != nil}}
	seen := map[string]bool{}
	for _, check := range checks {
		if check.required != (check.id != "") || check.id != "" && (!validID(check.id) || seen[check.id]) {
			return out, errors.New("升级准备的新事件标识缺失、多余或重复")
		}
		if check.id != "" {
			seen[check.id] = true
		}
	}
	for _, id := range fail2banUpgradeOriginalIDs(b, r) {
		if id != "" && seen[id] {
			return out, errors.New("升级准备不得复用原事件或资源标识")
		}
	}
	to := fail2banNginxEngineKey(b.Candidate.binding())
	if b.Bundle != nil {
		next := *b.Bundle
		next.ID, next.EngineKey = ids.Jails, to
		if err = next.valid(&b.Candidate); err != nil {
			return out, err
		}
		out.Bundle = &next
	}
	if ids.Nginx != "" {
		grants, e := fail2banJailGrants(b.Registry, b.Bundle, out.Bundle)
		if e != nil {
			return out, e
		}
		out.Nginx = &fail2banNginxRegistry{Schema: 1, ID: ids.Nginx, PreviousID: b.Registry.ID, ApprovedAt: at, RequestHash: fail2banUpgradeGrantHash("prepared-nginx", struct {
			Before, After string
			Grants        []fail2banNginxGrant
		}{b.Registry.ID, ids.Nginx, grants}), Grants: grants}
		if err = validFail2banNginxRegistry(*out.Nginx, false); err != nil {
			return out, err
		}
	}
	if ids.Sources != "" {
		if b.HostSources == nil || b.HostSources.Action != "approve" {
			return out, errors.New("升级来源材料缺少原批准")
		}
		next := *b.HostSources
		next.ID, next.PreviousID, next.EngineKey, next.ApprovedAt = ids.Sources, next.ID, to, at
		next.RequestHash = next.requestHash()
		if !next.valid() {
			return out, errors.New("升级来源候选材料无效")
		}
		out.Sources = &next
	}
	if ids.Sync != "" {
		if b.HostSync == nil || b.HostSync.Action != "enable" || out.Sources == nil {
			return out, errors.New("升级同步材料缺少原会话或候选来源")
		}
		stop := *b.HostSync
		stop.ID, stop.PreviousID, stop.Action, stop.ApprovedAt = ids.Stop, stop.ID, "disable", at
		stop.RequestHash = stop.requestHash()
		next := *b.HostSync
		next.ID, next.PreviousID, next.SessionID, next.EngineKey, next.SourcesID, next.RecoveryID, next.ApprovedAt = ids.Sync, ids.Stop, ids.Sync, to, ids.Sources, "", at
		next.RuntimeBaseID = ids.Clear
		if next.RuntimeBaseID == "" && r.Runtime != nil {
			next.RuntimeBaseID = r.Runtime.Intent.OperationID
		}
		next.RequestHash = next.requestHash()
		if !stop.valid() || !next.valid() {
			return out, errors.New("升级同步候选材料无效")
		}
		out.Stop, out.Sync = &stop, &next
	}
	return out, nil
}

func (i fail2banUpgradePreparation) validate(data, id string) error {
	b, in := i.Basis, i.Request
	if i.Schema != 1 || in.DataDir != data || in.Scope != "host" || in.OperationID != id || !validID(id) || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || in.Target != b.hash() || !i.Grants.ScopeVerified || len(i.Grants.Blockers) != 0 || in.PlanID != b.Candidate.PlanID || in.AssetID != b.Candidate.AssetID || in.TrustPath != b.Candidate.TrustPath || in.Prerelease != b.Candidate.Prerelease {
		return errors.New("升级准备意图或原预览身份无效")
	}
	if err := validateFail2banManagedRecord(b.Current, data); err != nil {
		return err
	}
	for _, original := range fail2banUpgradeOriginalIDs(b, i.Recovery) {
		if original == id {
			return errors.New("升级准备不能复用原操作或资源标识")
		}
	}
	if b.Current.State != "installed" || b.Current.ActionState != "completed" || b.Current.JailSelection != "" && (b.Bundle == nil || b.Bundle.ID != b.Current.JailSelection) || b.Current.JailSelection == "" && b.Bundle != nil {
		return errors.New("升级准备的原安装和配置选择不匹配")
	}
	if b.Bundle != nil {
		if err := b.Bundle.valid(&b.Current); err != nil {
			return err
		}
	}
	if err := validFail2banNginxRegistry(b.Registry, true); err != nil {
		return err
	}
	c := b.Candidate
	if c.OperationID != b.Current.OperationID || c.DataDir != data || c.EventID != "" || c.PreviousEvent != "" || c.At != 0 || c.State != "" || c.JailSelection != "" || c.Action != "install" || c.ActionState != "pending" || c.Reason != "" || c.Start || c.Enable || c.PlanID == b.Current.PlanID && c.AssetID == b.Current.AssetID || c.PythonPath != b.Current.PythonPath || c.PythonSHA256 != b.Current.PythonSHA256 || c.PythonVersion != b.Current.PythonVersion || c.ManagerPath != b.Current.ManagerPath || c.ManagerSHA256 != b.Current.ManagerSHA256 {
		return errors.New("升级准备候选不是原解释器和管理程序上的独立签名资产")
	}
	c.EventID, c.At, c.State = id, i.CreatedAt, "reserved"
	if err := validateFail2banManagedRecord(c, data); err != nil {
		return err
	}
	if i.Grants.ScopeSHA256 != fail2banUpgradeGrantScopeHash(b) {
		return errors.New("升级准备的原动作范围摘要不匹配")
	}
	if i.Grants.HostCheckpoint != nil {
		if i.Grants.HostCheckpoint.SHA256 != i.Recovery.hash() {
			return errors.New("升级准备遗漏原宿主机恢复检查点")
		}
	} else if i.Recovery.Runtime != nil || b.HostSync != nil || i.Recovery.Stopping != nil {
		return errors.New("升级准备缺少宿主机检查点摘要")
	}
	if i.Grants.HostRegistration != nil && i.Grants.HostRegistration.ReceiptSHA256 != fail2banUpgradeGrantHash("registration-receipt", i.Recovery.RegistrationReceipt) {
		return errors.New("升级准备登记回执不匹配")
	}
	expected, err := buildFail2banUpgradeMaterial(b, i.Grants, i.Recovery, i.Material.IDs, i.CreatedAt)
	if err != nil {
		return err
	}
	if fail2banUpgradeGrantHash("material", expected) != fail2banUpgradeGrantHash("material", i.Material) {
		return errors.New("升级准备的候选配置或批准超出原范围")
	}
	for _, next := range []string{i.Material.IDs.Jails, i.Material.IDs.Nginx, i.Material.IDs.Sources, i.Material.IDs.Stop, i.Material.IDs.Sync, i.Material.IDs.Clear} {
		if next == id {
			return errors.New("升级准备标识不能兼作候选动作标识")
		}
	}
	return nil
}

func sameFail2banUpgradePreparationRecord(actual, expected Record) bool {
	actual.UpdatedAt, expected.UpdatedAt = 0, 0
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(expected)
	return bytes.Equal(a, b)
}
