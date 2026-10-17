package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const firewallOperationKind = "firewall.change"
const firewallRuntimeSchema = 3
const firewallCheckpointBytes = 1 << 20

type firewallProtectionBasis struct {
	SSHProfile     string   `json:"ssh_profile"`
	SSHListeners   []string `json:"ssh_listeners"`
	Listener       string   `json:"listener"`
	AllowedSources []string `json:"allowed_sources"`
	ControlSource  string   `json:"control_source"`
}
type firewallPolicyRecord struct {
	ProtectionBasis firewallProtectionBasis `json:"protection_basis"`
	OperationID     string                  `json:"operation_id"`
	Action          string                  `json:"action"`
	PlanID          string                  `json:"plan_id"`
	Version         int64                   `json:"version"`
	Policy          firewall.Policy         `json:"policy"`
	PolicyHash      string                  `json:"policy_hash"`
	ProgramHash     string                  `json:"program_hash"`
	Protections     []firewall.Protection   `json:"protections"`
	Marker          string                  `json:"marker"`
}
type firewallCheckpoint struct {
	Schema          int                   `json:"schema"`
	Owner           string                `json:"owner"`
	Confirmed       *firewallPolicyRecord `json:"confirmed"`
	Candidate       *firewallPolicyRecord `json:"candidate"`
	Operation       *firewall.Operation   `json:"operation"`
	RequestHash     string                `json:"request_hash"`
	CurrentKernel   firewall.KernelView   `json:"current_kernel"`
	BeforeKernel    firewall.KernelView   `json:"before_kernel"`
	CandidateKernel firewall.KernelView   `json:"candidate_kernel"`
	Rollback        bool                  `json:"rollback"`
	LastRescue      string                `json:"last_rescue"`
	RestoreIntent   *firewall.KernelView  `json:"restore_intent"`
}
type firewallPrivatePlan struct {
	view   firewall.Plan
	record *firewallPolicyRecord
}
type hostFirewall struct {
	mu                    sync.Mutex
	dataDir, sshMode      string
	owner                 string
	firewalldRegistration *firewalldRegistrationCheckpoint
	firewalldState        *firewalldCheckpoint
	available             bool
	recovering            bool
	policyUncertain       bool
	journal               *Journal
	remote                *remoteListener
	dns                   *HostDNS
	state                 firewallCheckpoint
	plans                 map[string]firewallPrivatePlan
	unlock                func()
	deadline              time.Time
	proofListener         *net.TCPListener
	problem               string
	retryAt               time.Time
	protectionObservation firewall.ProtectionObservation
	protectionObservedAt  time.Time
}

func firewallStatePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "runtime.json")
}
func loadFirewallState(dataDir string) (*firewallCheckpoint, error) {
	raw, err := listenerRead(firewallStatePath(dataDir), firewallCheckpointBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value firewallCheckpoint
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("防火墙恢复记录包含多余内容")
	}
	if value.Schema != firewallRuntimeSchema || !validID(value.Owner) {
		return nil, errors.New("防火墙独立所有者无效")
	}
	for _, r := range []*firewallPolicyRecord{value.Confirmed, value.Candidate} {
		if r == nil {
			continue
		}
		if err := validateFirewallProtectionBasis(r.ProtectionBasis); err != nil {
			return nil, err
		}
		hash, err := firewall.PolicyDigest(r.Policy)
		if err != nil {
			return nil, err
		}
		program, err := firewall.CompileRuntime(r.Policy, r.Protections, r.Action)
		if err != nil {
			return nil, err
		}
		if !validID(r.OperationID) || r.Version < 1 || hash != r.PolicyHash || firewall.RuntimeProgramHash(program) != r.ProgramHash || !validID(r.PlanID) || r.Marker != "nginxpanel:policy:v2:"+value.Owner+":"+r.PlanID+":"+r.ProgramHash {
			return nil, errors.New("防火墙独立策略摘要无效")
		}
	}
	if value.Candidate != nil && value.Operation == nil {
		return nil, errors.New("防火墙候选缺少独立操作")
	}
	if op := value.Operation; op != nil {
		if !validID(op.ID) || !validID(op.PlanID) || (op.Action != "apply" && op.Action != "remove") || value.RequestHash != firewallRequestHash(op.PlanID, op.Action) || op.UpdatedAt <= 0 || op.Deadline <= 0 {
			return nil, errors.New("防火墙操作身份无效")
		}
		switch op.State {
		case "running", "waiting_confirmation", "compensating", "recovery_required":
			if value.Candidate == nil {
				return nil, errors.New("防火墙活动操作缺少候选")
			}
		case "succeeded", "rolled_back", "failed":
			if value.Candidate != nil {
				return nil, errors.New("防火墙终态残留候选")
			}
		default:
			return nil, errors.New("防火墙操作状态未知")
		}
	}
	if r := value.Candidate; r != nil {
		op := value.Operation
		if op.ID != r.OperationID || op.PlanID != r.PlanID || op.Version != r.Version || op.PolicyHash != r.PolicyHash || op.ProgramHash != r.ProgramHash || op.Action != r.Action {
			return nil, errors.New("防火墙候选与操作身份不一致")
		}
	}
	validKernel := func(k firewall.KernelView) bool {
		return k.Available && k.Generation != 0 && len(k.NamespaceID) == 64 && len(k.Fingerprint) == 64 && k.ObservedAt > 0 && k.Bytes >= 0 && k.Bytes <= nftReadBytes && k.Chains >= 0 && k.Chains <= 128 && k.Rules >= 0 && k.Rules <= firewall.MaxEntries
	}
	if !validKernel(value.CurrentKernel) || value.Candidate != nil && (!validKernel(value.BeforeKernel) || !value.BeforeKernel.TableExists) || value.CandidateKernel.Available && !validKernel(value.CandidateKernel) {
		return nil, errors.New("防火墙恢复快照无效")
	}
	if value.Operation != nil && value.Operation.State == "succeeded" && (value.Confirmed == nil || value.Confirmed.OperationID != value.Operation.ID || value.Confirmed.PlanID != value.Operation.PlanID || value.Confirmed.Action != value.Operation.Action || value.Confirmed.Version != value.Operation.Version || value.Confirmed.PolicyHash != value.Operation.PolicyHash || value.Confirmed.ProgramHash != value.Operation.ProgramHash) {
		return nil, errors.New("防火墙确认策略缺失")
	}
	if value.RestoreIntent != nil && (value.Candidate != nil || !validKernel(*value.RestoreIntent) || value.RestoreIntent.TableExists) {
		return nil, errors.New("防火墙恢复意图无效")
	}
	return &value, nil
}
func (f *hostFirewall) save() error { _, err := f.persist(); return err }
func (f *hostFirewall) persist() (bool, error) {
	if f.state.Operation != nil && f.state.Operation.UpdatedAt == 0 {
		f.state.Operation.UpdatedAt = time.Now().Unix()
	}
	if err := rootJSONWrite(firewallStatePath(f.dataDir), f.state, firewallCheckpointBytes); err != nil {
		f.problem = "防火墙独立恢复记录无法持久保存"
		return false, err
	}
	if op := f.state.Operation; op != nil {
		if err := f.journal.Put(Record{OperationID: op.ID, RequestHash: f.state.RequestHash, Kind: firewallOperationKind, State: op.State, Stage: op.Stage, Deadline: op.Deadline, Error: op.Error, Firewall: op}); err != nil {
			f.problem = "防火墙独立操作回执无法持久保存"
			return true, err
		}
	}
	return true, nil
}
func (f *hostFirewall) activeLocked() bool {
	if f.firewalldState != nil {
		return f.firewalldState.Candidate != nil
	}
	return f.state.Candidate != nil
}
func (f *hostFirewall) currentOperation() *firewall.Operation {
	if f.firewalldState != nil {
		return f.firewalldState.Operation
	}
	return f.state.Operation
}
func (f *hostFirewall) confirmedRecord() *firewallPolicyRecord {
	if f.firewalldState != nil {
		return f.firewalldState.Confirmed
	}
	return f.state.Confirmed
}
func (f *hostFirewall) pending() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.activeLocked() || f.problem != "" || f.firewalldState != nil && f.firewalldState.Call != nil
}
func (f *hostFirewall) emptyMarker() string { return nftRegistrationPrefix + f.state.Owner }
func (f *hostFirewall) program(record *firewallPolicyRecord) (*firewall.NFTProgram, string, error) {
	if record == nil {
		return nil, f.emptyMarker(), nil
	}
	p, err := firewall.CompileRuntime(record.Policy, record.Protections, record.Action)
	if err != nil {
		return nil, "", err
	}
	if firewall.RuntimeProgramHash(p) != record.ProgramHash {
		return nil, "", errors.New("root 防火墙程序摘要变化")
	}
	return p, record.Marker, nil
}
func (f *hostFirewall) snapshot(record *firewallPolicyRecord) (firewall.KernelView, error) {
	return f.snapshotContext(context.Background(), record)
}
func (f *hostFirewall) snapshotContext(ctx context.Context, record *firewallPolicyRecord) (firewall.KernelView, error) {
	p, marker, err := f.program(record)
	if err != nil {
		return firewall.KernelView{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return snapshotNFTProgram(ctx, p, marker)
}
func (f *hostFirewall) Open() error {
	f.plans = map[string]firewallPrivatePlan{}
	value, err := loadFirewallState(f.dataDir)
	f.policyUncertain = err != nil || value != nil
	if err != nil {
		f.problem = "防火墙独立恢复记录无效，须本机处理"
		return nil
	}
	managed, err := loadFirewalldState(f.dataDir)
	if err != nil || managed != nil && value != nil {
		f.policyUncertain, f.problem = true, "firewalld 恢复记录无效或与 nftables 恢复材料冲突，须本机处理"
		return nil
	}
	if managed != nil {
		f.available = f.available && f.owner == "firewalld"
		f.owner = "firewalld"
		return f.openFirewalldExecutor(managed)
	}
	if f.owner == "firewalld" {
		if value == nil {
			return f.openFirewalldExecutor(nil)
		}
		// A new owner selection never revokes an admitted NFT recovery.
		// Continue only that stored executor; grant no new direct-NFT writes.
		f.owner, f.available = "direct-nftables", false
	}
	if !f.available && value == nil {
		return nil
	}
	if os.Geteuid() != 0 || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		f.problem = "防火墙恢复须在真实宿主机 root 范围执行"
		return nil
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	f.unlock = unlock
	if err := forbidFirewalldRegistration(f.dataDir); err != nil {
		f.problem = err.Error()
		return nil
	}
	if err = secure.RootDirectory(filepath.Dir(firewallStatePath(f.dataDir)), 0700); err != nil {
		return err
	}
	if value == nil {
		registered, err := loadNFTRegistration(f.dataDir)
		if err != nil || registered == nil || registered.State != "registered" {
			f.problem = "须先停止 Agent 并由本机 root 完成空表登记"
			return nil
		}
		f.state = firewallCheckpoint{Schema: firewallRuntimeSchema, Owner: registered.Owner, CurrentKernel: registered.Confirmed}
	} else {
		f.state = *value
	}
	f.policyUncertain = false
	f.recovering = true
	// Startup never resumes an unconfirmed policy. Its recovery direction is
	// persisted and completed before the Agent accepts any new operation.
	if f.activeLocked() {
		if err := f.rollbackLocked("Agent 重启，恢复最后确认策略"); err != nil {
			f.problem = "防火墙启动恢复未完成"
		}
		return nil
	}
	if err := f.reconcileConfirmedLocked(); err != nil {
		f.problem = "防火墙已确认状态无法核对或恢复"
	}
	return nil
}
func (f *hostFirewall) Close() {
	if f.unlock != nil {
		f.unlock()
		f.unlock = nil
	}
}
func (f *hostFirewall) operationLocked(id string) (firewall.Operation, error) {
	if op := f.currentOperation(); op != nil && op.ID == id {
		return *op, nil
	}
	r, err := f.journal.Get(id)
	if err != nil {
		return firewall.Operation{}, err
	}
	if r.Kind != firewallOperationKind || r.Firewall == nil || r.Firewall.ID != id || r.State != r.Firewall.State || r.RequestHash != firewallRequestHash(r.Firewall.PlanID, r.Firewall.Action) {
		return firewall.Operation{}, fault.Conflict("操作标识已用于其他业务")
	}
	return *r.Firewall, nil
}
func (f *hostFirewall) Operation(id string) (firewall.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.operationLocked(id)
}
func (f *hostFirewall) View() firewall.RuntimeView {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.firewalldState != nil {
		return f.firewalldViewLocked()
	}
	out := firewall.RuntimeView{Backend: f.owner, Available: f.available && f.problem == "" && f.state.Schema == firewallRuntimeSchema, Reason: f.problem, Kernel: f.state.CurrentKernel, Protections: []firewall.Protection{}, ConfirmedAction: "none"}
	if f.state.Schema == firewallRuntimeSchema {
		out.Backend = "direct-nftables"
	}
	if out.Backend != "firewalld" && out.Backend != "direct-nftables" {
		out.Backend = "unconfirmed"
	}
	if f.state.Candidate != nil {
		out.Available = false
		if out.Reason == "" {
			out.Reason = "存在待确认或待恢复的防火墙操作"
		}
	}
	if !f.available && out.Reason == "" {
		out.Reason = "须由本机 root 确认防火墙所有者、宿主机范围及 SSH 保护配置"
	}
	if r := f.state.Confirmed; r != nil {
		out.ConfirmedAction, out.ConfirmedPlanID, out.ConfirmedOperationID = r.Action, r.PlanID, r.OperationID
		out.ConfirmedVersion = r.Version
		out.ConfirmedPolicyHash = r.PolicyHash
		if r.Action == "apply" {
			out.Protections = append(out.Protections, r.Protections...)
		}
	}
	if f.state.Operation != nil {
		copy := *f.state.Operation
		out.Operation = &copy
	}
	out.ProtectionObservation = f.protectionObservationLocked()
	out.CanPlan = out.CanPlan || out.Available
	return out
}
func (f *hostFirewall) Plan(ctx context.Context, in firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	// All mutations take DNS -> listener -> firewall locks. Recovery takes only
	// listener -> firewall; no callback from the latter acquires an earlier lock.
	f.dns.mu.Lock()
	defer f.dns.mu.Unlock()
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.owner == "firewalld" {
		return f.planFirewalldLocked(ctx, in, connection)
	}
	var out firewall.Plan
	if !f.available || f.problem != "" || f.state.Schema != firewallRuntimeSchema {
		return out, fault.Unavailable("宿主机防火墙执行尚未由本机确认或需恢复")
	}
	if f.activeLocked() || f.dns.checkpoint != nil && dnsActive(f.dns.checkpoint.Status.State) {
		return out, fault.Conflict("存在未完成的可达性变更")
	}
	if in.Version < 1 || (in.Action != "apply" && in.Action != "remove") {
		return out, fault.Invalid("须明确提供防火墙动作和有效版本")
	}

	normalized, err := in.Policy.Normalize()
	if err != nil {
		return out, err
	}
	if normalized.Backend != "direct-nftables" {
		return out, fault.Unavailable("当前执行器仅支持 direct-nftables")
	}
	effect := normalized
	if in.Action == "remove" {
		if normalized.Hash() != firewall.DefaultPolicy().Hash() {
			return out, fault.Invalid("移除计划不能附带新的期望策略")
		}
		if f.state.Confirmed == nil || f.state.Confirmed.Action != "apply" || f.state.Confirmed.Version != in.Version {
			return out, fault.Conflict("待移除的已确认策略已变化或不存在")
		}
		normalized = f.state.Confirmed.Policy
		effect = firewall.DefaultPolicy()
	}
	protections, listeners, source, err := firewallProtections(ctx, effect, f.sshMode, f.remote, connection)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	program, err := firewall.CompileRuntime(normalized, protections, in.Action)
	if err != nil {
		return out, err
	}
	programHash := firewall.RuntimeProgramHash(program)
	generatedRules := 0
	if program != nil {
		generatedRules = len(program.Rules)
	}
	current, err := f.snapshot(f.state.Confirmed)
	if err != nil {
		return out, fault.Unavailable("无法完整证明当前受管对象")
	}
	if !current.TableExists || current.NamespaceID != f.state.CurrentKernel.NamespaceID || current.Fingerprint != f.state.CurrentKernel.Fingerprint {
		return out, fault.Conflict("受管对象已变化，须先恢复或核对")
	}
	// Manager/legacy checks use a fresh bounded collection, not the HTTP cache.
	observer := firewallObserver{scope: "host", ctx: ctx, dataDir: f.dataDir}
	observed := observer.collect(ctx)
	if err := checkFirewallManagers(observed); err != nil {
		return out, err
	}
	for _, r := range effect.Rules {
		if r.Enabled && r.Interface != "" {
			found := false
			for _, name := range observed.Interfaces {
				if name == r.Interface {
					found = true
				}
			}
			if !found {
				return out, fault.Conflict("策略绑定的接口未观察到")
			}
		}
	}
	id := secure.ID()
	policyHash, err := firewall.PolicyDigest(normalized)
	if err != nil {
		return out, err
	}
	record := &firewallPolicyRecord{Action: in.Action, PlanID: id, Version: in.Version, Policy: normalized, PolicyHash: policyHash, ProgramHash: programHash, Protections: protections, ProtectionBasis: firewallProtectionBasis{SSHProfile: f.sshMode, SSHListeners: append([]string{}, listeners...), Listener: f.remote.state.Confirmed.Listen, AllowedSources: append([]string{}, f.remote.state.Confirmed.AllowedSources...), ControlSource: source}, Marker: "nginxpanel:policy:v2:" + f.state.Owner + ":" + id + ":" + programHash}
	batch, err := firewall.PrepareNFTManaged(program, current, record.Marker)
	if err != nil {
		return out, err
	}
	if current.Bytes+len(batch.Wire)+generatedRules*64+4096 > nftReadBytes {
		return out, fault.Unavailable("现有快照与候选规模超过完整后读预算")
	}
	out = firewall.Plan{Backend: "direct-nftables", CanApply: true, Action: in.Action, ID: id, Version: in.Version, PolicyHash: policyHash, ProgramHash: programHash, Baseline: current, Protections: protections, SSHProfile: f.sshMode, SSHListeners: listeners, ListenerVersion: f.remote.state.Version, Listener: f.remote.state.Confirmed.Listen, ControlSource: source, ConfirmationSeconds: firewall.ConfirmationSeconds, ExpiresAt: time.Now().Unix() + 300, TransactionHash: batch.Hash, TransactionBytes: len(batch.Wire), GeneratedRules: generatedRules}
	return out, f.storePlanLocked(out, record)
}

func (f *hostFirewall) storePlanLocked(view firewall.Plan, record *firewallPolicyRecord) error {
	for key, p := range f.plans {
		if time.Now().Unix() >= p.view.ExpiresAt {
			delete(f.plans, key)
		}
	}
	if len(f.plans) >= 8 {
		return fault.New(429, "FIREWALL_PLAN_LIMIT", "待执行计划已达 8 份，请等待过期")
	}
	f.plans[view.ID] = firewallPrivatePlan{view: view, record: record}
	return nil
}
