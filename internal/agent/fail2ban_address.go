package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banAddressKind = "nginx.fail2ban-address"

type fail2banAddressIntent struct {
	Request      fail2ban.AddressRequest `json:"request"`
	Installation string                  `json:"installation"`
	Selection    string                  `json:"selection"`
	Engine       string                  `json:"engine"`
	Invocation   string                  `json:"invocation"`
	SocketInode  string                  `json:"socket_inode"`
	Sent         bool                    `json:"sent"`
	Receipt      *int                    `json:"receipt"`
	Submission   string                  `json:"submission"`
	EngineState  string                  `json:"engine_state"`
	ObservedAt   int64                   `json:"observed_at"`
	ExpiresAt    int64                   `json:"expires_at"`
	Permanent    bool                    `json:"permanent"`
}

type fail2banAddressContext struct {
	existing     *fail2banExistingRuntimeEvidence
	installation string
	selection    string
	engine       string
	backend      string
	banTime      int64
	r            *fail2banManagedRecord
	bundle       *fail2banJailBundle
	jail         fail2ban.DesiredJail
	live         fail2banLiveService
	target       string
	bans         map[string]fail2banBanTime
	protected    bool
	canBan       bool
	reason       string
	action       string
	generation   string
}

func fail2banAddressView(record Record) fail2ban.AddressOperation {
	i := record.Fail2banAddress
	return fail2ban.AddressOperation{ID: record.OperationID, RequestHash: record.RequestHash, Input: i.Request.Input, State: record.State, Stage: record.Stage, Submission: i.Submission, EngineState: i.EngineState, ObservedAt: i.ObservedAt, ExpiresAt: i.ExpiresAt, Permanent: i.Permanent, Error: record.Error}
}

// The caller holds Nginx (when present), host and installation locks in order.
// Jail ownership and its live fixed action never come from executable API input.
func (f *fail2banJailsExecutor) addressContext(ctx context.Context, in fail2ban.AddressQuery) (fail2banAddressContext, error) {
	if in.EngineOwner == "existing" {
		return f.existingAddressContext(ctx, in)
	}
	return f.managedAddressContext(ctx, in.Jail, in.IP)
}

func (f *fail2banJailsExecutor) managedAddressContext(ctx context.Context, name, address string) (fail2banAddressContext, error) {
	var out fail2banAddressContext
	dataDir := f.server.DataDir
	binding, err := selectFail2banBinding(dataDir)
	if err != nil {
		return out, err
	}
	if binding == nil || binding.managed == nil {
		return out, fault.Conflict("手动操作仅允许独立受管实例的 jail")
	}
	out.r = binding.managed
	selected, bundle, err := selectedFail2banJails(out.r)
	if err != nil {
		return out, err
	}
	if bundle == nil {
		return out, fault.Conflict("尚未应用受管 jail 配置")
	}
	out.bundle = bundle
	for _, jail := range bundle.Policy.Jails {
		if jail.Enabled && fail2banJailNameFor(jail.ID) == name {
			out.jail = jail
			break
		}
	}
	if out.jail.ID == "" || !(out.jail.Action == "nginx-client" || out.jail.Action == "host-input" && out.jail.Template == fail2ban.PanelLoginTemplate) {
		return out, fault.Conflict("该 jail 未由本应用管理，不能执行手动操作")
	}
	if err = verifyFail2banManaged(ctx, out.r, true); err != nil {
		return out, err
	}
	if err = verifyFail2banManagedLive(ctx, out.r); err != nil {
		return out, err
	}
	before, err := readFail2banLiveService(ctx, binding)
	if err != nil {
		return out, err
	}
	ignore, err := fail2banIgnoreSet(out.jail, bundle)
	if err != nil {
		return out, err
	}
	var dir, registryID, hostHash string
	var m manifest
	n := f.server.Nginx
	out.canBan = true
	if out.jail.Action == "nginx-client" {
		if n == nil {
			return out, ErrRuntimeUnavailable
		}
		dir, m, err = n.active()
		if err != nil {
			return out, err
		}
		if len(m.ClientDeny[out.jail.ResourceID]) == 0 {
			return out, fault.Conflict("目标站点未发布客户端拒绝入口")
		}
		matched := 0
		for _, source := range m.Logs {
			if source.Source.Active && source.Source.ResourceID == out.jail.ResourceID && source.Source.Category == "http_access" && source.Source.Format == "nginxpanel_http" && source.Source.AuthPresence && source.Path == bundle.Sources[out.jail.ID] {
				matched++
			}
		}
		if matched != 1 {
			return out, fault.Conflict("当前站点日志与受管 jail 来源不匹配")
		}
		registry, e := loadFail2banNginxRegistry(dataDir)
		if e != nil {
			return out, e
		}
		granted := false
		for _, grant := range registry.Grants {
			if grant.Jail == name && grant.ResourceID == out.jail.ResourceID && grant.EngineKey == bundle.EngineKey {
				granted = true
			}
		}
		if !granted {
			return out, fault.Conflict("当前 jail 缺少对应站点的 Nginx 动作授权")
		}
		registryID = registry.ID
		ignore = append(ignore, m.ClientDeny[out.jail.ResourceID]...)
	} else {
		host := f.hostScope(ctx, out.r)
		hostHash, out.canBan, out.reason = host.hash, host.ready, host.reason
		ignore = append(ignore, host.protected...)
		out.action, out.generation, err = fail2banHostAddressState(ctx, dataDir, address)
		if err != nil {
			out.canBan = false
			out.reason = strings.TrimSpace(out.reason + " " + err.Error())
		}
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return out, err
	}
	out.protected = ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || out.jail.Action == "host-input" && !ip.IsGlobalUnicast()
	if out.jail.Action == "nginx-client" {
		local, err := net.InterfaceAddrs()
		if err != nil {
			return out, err
		}
		for _, address := range local {
			prefix, parseErr := netip.ParsePrefix(address.String())
			if parseErr != nil {
				return out, errors.New("本机接口地址无法核对")
			}
			out.protected = out.protected || prefix.Addr().Unmap() == ip
		}
	}
	for _, value := range ignore {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			out.protected = out.protected || prefix.Contains(ip)
		} else if exact, err := netip.ParseAddr(value); err == nil {
			out.protected = out.protected || exact.Unmap() == ip
		}
	}
	out.canBan = out.canBan && !out.protected
	out.bans, err = readFail2banJailDetails(ctx, out.r, bundle, out.jail)
	if err != nil {
		return out, err
	}
	if out.jail.Action == "host-input" && len(out.bans) >= firewall.NFTBanLimit {
		if _, exists := out.bans[address]; !exists {
			out.canBan = false
			out.reason = strings.TrimSpace(out.reason + " 当前 jail 已达到宿主机封禁数量上限，仅允许解封")
		}
	}
	if err = verifyFail2banManaged(ctx, out.r, true); err != nil {
		return out, err
	}
	out.live, err = readFail2banLiveService(ctx, binding)
	if err != nil || !sameFail2banLive(before, out.live) {
		return out, errors.New("读取期间 Fail2ban 服务身份变化")
	}
	if out.jail.Action == "nginx-client" {
		snapshot, generation, e := n.readClientDenySnapshot()
		if e != nil {
			return out, e
		}
		if err = n.observe(ctx, m); err != nil {
			return out, err
		}
		_, after, e := n.readClientDenySnapshot()
		if e != nil {
			return out, e
		}
		if after != generation {
			return out, ErrExternalChange
		}
		out.action, out.generation = "clear", generation
		values := snapshot.Entries[out.jail.ResourceID]
		index := sort.SearchStrings(values, address)
		if index < len(values) && values[index] == address {
			out.action = "denied"
		}
	}
	nginxHash := ""
	if dir != "" {
		nginxHash = manifestHash(m)
	}
	out.target = fail2ban.JailTarget(bundle.EngineKey, selected, dir, nginxHash, registryID, out.live.invocation, hostHash)
	out.installation, out.selection, out.engine = out.r.OperationID, out.bundle.ID, out.bundle.EngineKey
	out.backend, out.banTime = out.jail.Action, out.jail.BanTime
	return out, ctx.Err()
}

// Observe only the currently owned object. Missing or uncertain rules never
// become a successful clear observation, and this path cannot mutate rules.
func fail2banHostAddressState(ctx context.Context, dataDir, address string) (string, string, error) {
	unknown := func(err error) (string, string, error) { return "unknown", "", err }
	root, err := loadFail2banHostRegistration(dataDir)
	if err != nil || root == nil || root.State != "registered" || !fail2banHostRegistrationReceipt(dataDir, root) {
		return unknown(errors.New("宿主机动作登记无法核对"))
	}
	marker, err := nftTargetRegistrationMarker(firewall.NFTFail2banInput, root.Owner)
	if err != nil {
		return unknown(err)
	}
	p := fail2banHostProgram{Marker: marker}
	expected := root.Confirmed
	runtime, err := loadFail2banHostRuntime(dataDir)
	if err != nil {
		return unknown(err)
	}
	if runtime != nil {
		if runtime.State == "running" || runtime.State == "recovery_required" || !fail2banHostRuntimeReceipt(dataDir, runtime) {
			return unknown(errors.New("宿主机动作事务尚未核对"))
		}
		if fail2banHostRuntimeMatches(runtime, root) {
			p, expected = runtime.effective(), runtime.Confirmed
		}
	}
	kernel, err := p.snapshot(ctx)
	if err != nil || !fail2banHostProgramShape(p, kernel) || kernel.NamespaceID != expected.NamespaceID || kernel.Fingerprint != expected.Fingerprint {
		return unknown(errors.New("当前宿主机动作对象无法完整证明"))
	}
	state := "clear"
	if p.Set != nil {
		index := sort.SearchStrings(p.Set.Addresses, address)
		if index < len(p.Set.Addresses) && p.Set.Addresses[index] == address {
			state = "denied"
		}
	}
	generation := secure.Hash([]byte("nginxpanel:fail2ban-host-address:v1:" + kernel.NamespaceID + ":" + strconv.FormatUint(uint64(kernel.Generation), 10) + ":" + kernel.Fingerprint))
	return state, generation, nil
}

func (f *fail2banJailsExecutor) addressStatus(ctx context.Context, in fail2ban.AddressQuery) (fail2ban.AddressStatus, error) {
	out := fail2ban.AddressStatus{At: time.Now().Unix(), EngineOwner: in.EngineOwner, AdoptionID: in.AdoptionID, Jail: in.Jail, IP: in.IP, EngineState: "unknown", ActionState: "unknown"}
	if err := in.Validate(); err != nil {
		return out, err
	}
	leave, err := f.lock(false)
	if errors.Is(err, ErrBusy) {
		out.Reason = "维护或共享实例操作期间暂不可查询"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer leave()
	if err = f.addressIdle(); err != nil {
		if !errors.Is(err, ErrBusy) {
			return out, err
		}
		out.Reason = "共享实例或 jail 操作尚未完成"
		return out, nil
	}
	current, err := f.addressContext(ctx, in)
	if err != nil {
		return out, err
	}
	out.At, out.Available, out.Target, out.CanBan = time.Now().Unix(), true, current.target, current.canBan
	out.Backend, out.Reason = current.backend, current.reason
	out.EngineState, out.ExpiresAt, out.Permanent = fail2banAddressState(current.bans, in.IP)
	out.ActionState, out.Generation, out.BanTime = current.action, current.generation, current.banTime
	if current.protected {
		out.Reason = strings.TrimSpace(out.Reason + " 该地址属于保护或忽略来源，仅允许解封")
	}
	return out, nil
}
func fail2banAddressState(bans map[string]fail2banBanTime, ip string) (string, int64, bool) {
	if ticket, exists := bans[ip]; exists {
		return "banned", ticket.Expires, ticket.Duration == -1
	}
	return "clear", 0, false
}
func (f *fail2banJailsExecutor) addressIdle() error {
	n := f.server.Nginx
	if n != nil && (n.disasterBusy != "" || n.http01 != nil && n.http01.busy()) {
		return ErrBusy
	}
	records, err := f.journal().List()
	if err != nil {
		return err
	}
	for _, record := range records {
		if pendingNginxRecord(record) {
			return ErrBusy
		}
	}
	return nil
}
func (f *fail2banJailsExecutor) submitAddress(ctx context.Context, in fail2ban.AddressRequest) (fail2ban.AddressOperation, error) {
	var out fail2ban.AddressOperation
	if !in.Valid() {
		return out, fault.Invalid("手动封禁合同无效")
	}
	leave, err := f.lock(false)
	if err != nil {
		return out, err
	}
	defer leave()
	if old, err := f.journal().Get(in.OperationID); err == nil {
		if old.Kind != fail2banAddressKind || !validFail2banAddressIntent(old) || old.RequestHash != in.Hash() {
			return out, fault.Conflict("手动封禁操作 ID 冲突")
		}
		return fail2banAddressView(old), nil
	} else if !os.IsNotExist(err) {
		return out, err
	}
	if err := f.addressIdle(); err != nil {
		return out, err
	}
	admit, err := f.journal().maintenanceLock()
	if err != nil {
		return out, err
	}
	defer admit()
	records, err := f.journal().List()
	if err != nil {
		return out, err
	}
	for _, record := range records {
		if record.Kind == "maintenance.lock" && record.State != "succeeded" {
			return out, ErrBusy
		}
	}
	var intent *fail2banAddressIntent
	if in.Input.EngineOwner == "existing" {
		intent, err = f.existingAddressIntent(in)
		if err != nil {
			return out, err
		}
	} else {
		current, err := f.addressContext(ctx, in.Input.Query())
		if err != nil {
			return out, err
		}
		if current.target != in.Input.Target {
			return out, fault.Conflict("目标服务、配置或 jail 动作授权已变化，请重新核对地址状态")
		}
		if in.Input.Action == "ban" && !current.canBan {
			return out, fault.Conflict("该地址受保护或动作执行依据不可用，禁止新增封禁")
		}
		intent = &fail2banAddressIntent{Request: in, Installation: current.installation, Selection: current.selection, Engine: current.engine, Invocation: current.live.invocation, SocketInode: current.live.inode, Submission: "not_sent", EngineState: "unknown"}
	}
	record := Record{OperationID: in.OperationID, RequestHash: in.Hash(), Kind: fail2banAddressKind, State: "running", Stage: "queued", Deadline: time.Now().Add(5 * time.Minute).Unix(), Fail2banAddress: intent}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = f.persist(record); err != nil {
		return out, err
	}
	f.enqueue()
	return fail2banAddressView(record), nil
}

func (f *fail2banJailsExecutor) addressOperation(id string) (fail2ban.AddressOperation, error) {
	if !validID(id) {
		return fail2ban.AddressOperation{}, fault.Invalid("操作 UUID 无效")
	}
	record, err := f.journal().Get(id)
	if os.IsNotExist(err) {
		return fail2ban.AddressOperation{}, fault.New(404, "FAIL2BAN_ADDRESS_OPERATION_MISSING", "手动封禁操作记录不存在")
	}
	if err != nil {
		return fail2ban.AddressOperation{}, err
	}
	if record.Kind != fail2banAddressKind || record.Fail2banAddress == nil {
		return fail2ban.AddressOperation{}, fault.Conflict("该 UUID 不属于手动封禁操作")
	}
	if !validFail2banAddressIntent(record) {
		return fail2ban.AddressOperation{}, errors.New("手动封禁持久合同损坏")
	}
	return fail2banAddressView(record), nil
}
