package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"nginxpanel/internal/secure"
)

type Fail2banUpgradeGrantReference struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	SHA256 string `json:"sha256"`
}

type Fail2banUpgradeNginxGrant struct {
	Jail          string `json:"jail"`
	ResourceID    string `json:"resource_id"`
	FromEngineKey string `json:"from_engine_key"`
	ToEngineKey   string `json:"to_engine_key"`
}

type Fail2banUpgradeHostRegistration struct {
	ID              string `json:"id"`
	Owner           string `json:"owner"`
	NamespaceID     string `json:"namespace_id"`
	State           string `json:"state"`
	SHA256          string `json:"sha256"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	ReceiptVerified bool   `json:"receipt_verified"`
}

// These hashes identify the original recovery material without returning ban
// addresses or protection policy text. They do not prove kernel enforcement.
type Fail2banUpgradeHostCheckpoint struct {
	SHA256             string                         `json:"sha256"`
	RuntimeID          string                         `json:"runtime_id"`
	RuntimeState       string                         `json:"runtime_state"`
	ControllerID       string                         `json:"controller_id"`
	IntentSHA256       string                         `json:"intent_sha256"`
	TransactionSHA256  string                         `json:"transaction_sha256"`
	RulesPresent       *bool                          `json:"rules_present"`
	ReceiptVerified    bool                           `json:"receipt_verified"`
	SyncParentID       string                         `json:"sync_parent_id"`
	SyncParentState    string                         `json:"sync_parent_state"`
	SyncParentSHA256   string                         `json:"sync_parent_sha256"`
	SyncParentVerified bool                           `json:"sync_parent_verified"`
	Stopping           *Fail2banUpgradeGrantReference `json:"stopping"`
}

// ScopeVerified concerns the recorded grant scope and recovery provenance,
// not permission to execute an upgrade. New approval IDs are allocated only
// by a future durable upgrade operation; this preview never reuses old IDs.
type Fail2banUpgradeGrants struct {
	ScopeSHA256          string                           `json:"scope_sha256"`
	ScopeVerified        bool                             `json:"scope_verified"`
	JailBundleSHA256     string                           `json:"jail_bundle_sha256"`
	NginxRegistryID      string                           `json:"nginx_registry_id"`
	NginxRegistrySHA256  string                           `json:"nginx_registry_sha256"`
	NginxMoves           []Fail2banUpgradeNginxGrant      `json:"nginx_moves"`
	NginxRetained        int                              `json:"nginx_retained"`
	HostRegistration     *Fail2banUpgradeHostRegistration `json:"host_registration"`
	HostSources          *Fail2banUpgradeGrantReference   `json:"host_sources"`
	HostSourceJails      []string                         `json:"host_source_jails"`
	MigrateHostSources   bool                             `json:"migrate_host_sources"`
	HostProtection       *Fail2banUpgradeGrantReference   `json:"host_protection"`
	RetainHostProtection bool                             `json:"retain_host_protection"`
	HostSync             *Fail2banUpgradeGrantReference   `json:"host_sync"`
	MigrateHostSync      bool                             `json:"migrate_host_sync"`
	HostCheckpoint       *Fail2banUpgradeHostCheckpoint   `json:"host_checkpoint"`
	Blockers             []string                         `json:"blockers"`
}

func fail2banUpgradeGrantHash(domain string, value any) string {
	// All callers pass fixed JSON records containing no unsupported values.
	raw, _ := json.Marshal(value)
	return secure.Hash(append([]byte("fail2ban:upgrade-grants:v1:"+domain+":\x00"), raw...))
}

func (p Fail2banUpgradeGrants) hash() string { return fail2banUpgradeGrantHash("plan", p) }

// Caller holds host -> binding -> maintenance locks. Live runtime checkpoints
// are hashed separately from the configuration scope: ordinary ban changes
// must not redefine the approval being requested.
func planFail2banUpgradeGrants(data string, b fail2banUpgradeBasis) (Fail2banUpgradeGrants, error) {
	out := Fail2banUpgradeGrants{NginxRegistryID: b.Registry.ID, NginxRegistrySHA256: fail2banUpgradeGrantHash("nginx", b.Registry), NginxMoves: []Fail2banUpgradeNginxGrant{}, HostSourceJails: []string{}, Blockers: []string{}}
	from, to := fail2banNginxEngineKey(b.Current.binding()), fail2banNginxEngineKey(b.Candidate.binding())
	out.ScopeSHA256 = fail2banUpgradeGrantHash("scope", struct {
		From, To     string
		Bundle       *fail2banJailBundle
		Registry     fail2banNginxRegistry
		Sources      *fail2banHostSourcesEvent
		Protection   *fail2banHostProtectionEvent
		Sync         *fail2banHostSyncEvent
		Registration *fail2banHostRegistration
	}{from, to, b.Bundle, b.Registry, b.HostSources, b.HostProtection, b.HostSync, b.HostRegistration})
	expected := map[string]string{}
	hostJails := []string{}
	if b.Bundle != nil {
		projected := *b.Bundle
		projected.EngineKey = to
		if err := projected.valid(&b.Candidate); err != nil {
			return out, err
		}
		// This identifies config content, not a materialized immutable bundle.
		projected.ID = ""
		out.JailBundleSHA256 = fail2banUpgradeGrantHash("candidate-jails", projected)
		for _, jail := range b.Bundle.Policy.Jails {
			if !jail.Enabled {
				continue
			}
			name := fail2banJailNameFor(jail.ID)
			if jail.Action == "nginx-client" {
				expected[name] = jail.ResourceID
			} else if jail.Action == "host-input" {
				hostJails = append(hostJails, name)
			}
		}
	}
	sort.Strings(hostJails)
	seen := map[string]bool{}
	for _, grant := range b.Registry.Grants {
		resource, selected := expected[grant.Jail]
		if grant.EngineKey != from {
			out.NginxRetained++
			if selected {
				out.Blockers = append(out.Blockers, "Nginx jail 的批准属于其他引擎："+grant.Jail)
			}
			continue
		}
		if !selected || resource != grant.ResourceID {
			out.Blockers = append(out.Blockers, "原引擎存在配置范围外或资源不匹配的 Nginx 批准："+grant.Jail)
			continue
		}
		seen[grant.Jail] = true
		out.NginxMoves = append(out.NginxMoves, Fail2banUpgradeNginxGrant{grant.Jail, grant.ResourceID, from, to})
	}
	for jail := range expected {
		if !seen[jail] {
			out.Blockers = append(out.Blockers, "缺少当前 jail 和资源对应的原引擎 Nginx 批准："+jail)
		}
	}
	root := b.HostRegistration
	registered := root != nil && root.State == "registered" && fail2banHostRegistrationReceipt(data, root)
	if root != nil {
		receipt, err := readFail2banUpgradeReceipt(data, root.OperationID)
		if err != nil {
			return out, err
		}
		out.HostRegistration = &Fail2banUpgradeHostRegistration{ID: root.OperationID, Owner: root.Owner, NamespaceID: root.Confirmed.NamespaceID, State: root.State, SHA256: fail2banUpgradeGrantHash("registration", root), ReceiptSHA256: fail2banUpgradeGrantHash("registration-receipt", receipt), ReceiptVerified: fail2banHostRegistrationReceipt(data, root)}
		if !out.HostRegistration.ReceiptVerified || root.State != "registered" && root.State != "released" {
			out.Blockers = append(out.Blockers, "宿主机登记原操作或审计回执尚未完成核对")
		}
	}
	belongs := func(owner, registration, namespace string) bool {
		return registered && owner == root.Owner && registration == root.OperationID && namespace == root.Confirmed.NamespaceID
	}
	protection := b.HostProtection
	if protection != nil {
		out.HostProtection = &Fail2banUpgradeGrantReference{protection.ID, protection.Action, fail2banUpgradeGrantHash("protection", protection)}
		if protection.Action == "approve" {
			out.RetainHostProtection = belongs(protection.Owner, protection.RegistrationID, protection.NamespaceID)
			if !out.RetainHostProtection {
				out.Blockers = append(out.Blockers, "宿主机保护批准不属于当前已确认登记")
			}
		}
	}
	sources := b.HostSources
	if sources != nil {
		out.HostSources = &Fail2banUpgradeGrantReference{sources.ID, sources.Action, fail2banUpgradeGrantHash("sources", sources)}
		if sources.Action == "approve" && sources.EngineKey == from {
			out.MigrateHostSources = true
			if !belongs(sources.Owner, sources.RegistrationID, sources.NamespaceID) || !out.RetainHostProtection {
				out.Blockers = append(out.Blockers, "宿主机来源批准缺少匹配的登记或保护批准")
			}
			out.HostSourceJails = append(out.HostSourceJails, sources.Policy.Jails...)
			if sources.Policy.Managed {
				out.HostSourceJails = append([]string{}, hostJails...)
			}
			selected := map[string]bool{}
			for _, jail := range fail2banJailNames(b.Bundle) {
				selected[jail] = true
			}
			for _, jail := range out.HostSourceJails {
				if !selected[jail] {
					out.Blockers = append(out.Blockers, "宿主机显式来源不在当前受管 jail 中："+jail)
				}
			}
		}
	}
	sync := b.HostSync
	if sync != nil {
		out.HostSync = &Fail2banUpgradeGrantReference{sync.ID, sync.Action, fail2banUpgradeGrantHash("sync", sync)}
		if sync.Action == "enable" {
			out.MigrateHostSync = sync.EngineKey == from
			if !out.MigrateHostSync || !out.MigrateHostSources || !out.RetainHostProtection || !belongs(sync.Owner, sync.RegistrationID, sync.NamespaceID) || sources.ID != sync.SourcesID || protection.ID != sync.ProtectionID {
				out.Blockers = append(out.Blockers, "持续同步会话的引擎、来源、保护或登记范围不匹配")
			}
			if err := fail2banHostBootSyncAuthority(data, sync); err != nil {
				out.Blockers = append(out.Blockers, "持续同步原会话的本机重启授权尚未核对")
			}
		}
	}
	if len(hostJails) != 0 && (!out.MigrateHostSync || !out.MigrateHostSources || !sources.Policy.Managed || !out.RetainHostProtection || b.Bundle.HostProtectionID != protection.ID) {
		out.Blockers = append(out.Blockers, "当前宿主机 jail 缺少同范围的受管来源、保护或持续同步批准")
	}
	checkpoint, blockers, err := readFail2banUpgradeHostCheckpoint(data, b)
	if err != nil {
		return out, err
	}
	out.HostCheckpoint = checkpoint
	out.Blockers = append(out.Blockers, blockers...)
	sort.Strings(out.Blockers)
	out.ScopeVerified = len(out.Blockers) == 0
	return out, nil
}

func readFail2banUpgradeReceipt(data, id string) (*Record, error) {
	r, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(id)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func readFail2banUpgradeHostCheckpoint(data string, b fail2banUpgradeBasis) (*Fail2banUpgradeHostCheckpoint, []string, error) {
	runtime, err := loadFail2banHostRuntime(data)
	if err != nil {
		return nil, nil, err
	}
	stopping, err := loadFail2banHostSyncStop(data, b.HostSync)
	if err != nil {
		return nil, nil, err
	}
	if runtime == nil && b.HostSync == nil && stopping == nil {
		return nil, nil, nil
	}
	out, blockers := &Fail2banUpgradeHostCheckpoint{}, []string{}
	var runtimeReceipt, parent *Record
	if runtime != nil {
		out.RuntimeID, out.RuntimeState, out.ControllerID = runtime.Intent.OperationID, runtime.State, runtime.Intent.ControllerID
		out.IntentSHA256, out.TransactionSHA256 = runtime.Intent.hash(), runtime.Intent.TransactionHash
		terminal := runtime.State == "succeeded" || runtime.State == "failed"
		if terminal {
			present := runtime.effective().Set != nil
			out.RulesPresent = &present
		}
		out.ReceiptVerified = fail2banHostRuntimeReceipt(data, runtime)
		id := runtime.Intent.OperationID
		if out.ControllerID != "" {
			id = out.ControllerID
		}
		runtimeReceipt, err = readFail2banUpgradeReceipt(data, id)
		if err != nil {
			return nil, nil, err
		}
		if !terminal || !out.ReceiptVerified || !fail2banHostRuntimeMatches(runtime, b.HostRegistration) {
			blockers = append(blockers, "宿主机原运行事务、登记或审计回执尚未完成核对")
		}
	}
	if sync := b.HostSync; sync != nil {
		event, err := loadFail2banHostSyncEvent(data, sync.SessionID)
		if err != nil {
			return nil, nil, err
		}
		parent, err = readFail2banUpgradeReceipt(data, event.ID)
		if err != nil {
			return nil, nil, err
		}
		out.SyncParentID, out.SyncParentSHA256 = event.ID, fail2banUpgradeGrantHash("sync-parent", parent)
		if parent != nil {
			out.SyncParentState = parent.State
			out.SyncParentVerified = event.Action == "enable" && fail2banHostSyncParentMatches(*parent, event)
			if sync.Action == "disable" {
				stopped := *event
				stopped.ID, stopped.PreviousID, stopped.Action, stopped.RetirementID = sync.ID, event.ID, "disable", sync.RetirementID
				out.SyncParentVerified = out.SyncParentVerified && stopped.requestHash() == sync.RequestHash
			}
			if sync.RetirementID != "" {
				retired, err := fail2banHostRetiredParent(data, *parent, event)
				if err != nil {
					return nil, nil, err
				}
				out.SyncParentVerified = out.SyncParentVerified && parent.Fail2banHostRetirementID == sync.RetirementID && retired
			} else if runtime != nil && runtime.Intent.ControllerID == event.ID {
				out.SyncParentVerified = out.SyncParentVerified && out.ReceiptVerified
			} else {
				out.SyncParentVerified = out.SyncParentVerified && parent.BeforeRevision == event.RuntimeBaseID && parent.AfterRevision == "" && parent.CandidateHash == "" && parent.ObservedRevision == "" && parent.Error == "" && (parent.Stage == "approved" || sync.Action == "disable" && parent.Stage == "disabled-empty")
			}
			if sync.Action == "enable" {
				out.SyncParentVerified = out.SyncParentVerified && parent.State == "running" && (runtime == nil && event.RuntimeBaseID == "" || runtime != nil && (runtime.Intent.ControllerID == event.ID || runtime.Intent.OperationID == event.RuntimeBaseID))
			} else {
				out.SyncParentVerified = out.SyncParentVerified && parent.State == "succeeded" && (runtime == nil || out.RulesPresent != nil && !*out.RulesPresent)
			}
		}
		if !out.SyncParentVerified {
			blockers = append(blockers, "持续同步原父操作、初始基础或终结回执不完整")
		}
	}
	if stopping != nil {
		out.Stopping = &Fail2banUpgradeGrantReference{stopping.ID, stopping.Action, fail2banUpgradeGrantHash("stopping", stopping)}
		blockers = append(blockers, "持续同步仍有尚未完成的显式停用意图")
	}
	out.SHA256 = fail2banUpgradeGrantHash("checkpoint", struct {
		Runtime         *fail2banHostRuntime
		Receipt, Parent *Record
		Stopping        *fail2banHostSyncEvent
	}{runtime, runtimeReceipt, parent, stopping})
	return out, blockers, nil
}
