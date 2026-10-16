package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
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
	r          *fail2banManagedRecord
	bundle     *fail2banJailBundle
	jail       fail2ban.DesiredJail
	live       fail2banLiveService
	target     string
	bans       map[string]fail2banBanTime
	protected  bool
	action     string
	generation string
}

func fail2banAddressView(record Record) fail2ban.AddressOperation {
	i := record.Fail2banAddress
	return fail2ban.AddressOperation{ID: record.OperationID, RequestHash: record.RequestHash, Input: i.Request.Input, State: record.State, Stage: record.Stage, Submission: i.Submission, EngineState: i.EngineState, ObservedAt: i.ObservedAt, ExpiresAt: i.ExpiresAt, Permanent: i.Permanent, Error: record.Error}
}

// The caller holds the Nginx and installation locks. This proves both the jail
// ownership and its live fixed action; API input never supplies an executable.
func (f *fail2banNginxExecutor) addressContext(ctx context.Context, name, address string) (fail2banAddressContext, error) {
	var out fail2banAddressContext
	n := f.nginx
	binding, err := selectFail2banBinding(n.DataDir)
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
	if out.jail.ID == "" || out.jail.Action != "nginx-client" {
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
	dir, m, err := n.active()
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
	registry, err := loadFail2banNginxRegistry(n.DataDir)
	if err != nil {
		return out, err
	}
	out.protected = false
	granted := false
	for _, grant := range registry.Grants {
		if grant.Jail == name && grant.ResourceID == out.jail.ResourceID && grant.EngineKey == bundle.EngineKey {
			granted = true
		}
	}
	if !granted {
		return out, fault.Conflict("当前 jail 缺少对应站点的 Nginx 动作授权")
	}
	ignore, err := fail2banIgnoreSet(out.jail, bundle)
	if err != nil {
		return out, err
	}
	ignore = append(ignore, m.ClientDeny[out.jail.ResourceID]...)
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return out, err
	}
	out.protected = ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast()
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
	for _, value := range ignore {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			out.protected = out.protected || prefix.Contains(ip)
		} else if exact, err := netip.ParseAddr(value); err == nil {
			out.protected = out.protected || exact.Unmap() == ip
		}
	}
	out.bans, err = readFail2banJailDetails(ctx, out.r, bundle, out.jail)
	if err != nil {
		return out, err
	}
	if err = verifyFail2banManaged(ctx, out.r, true); err != nil {
		return out, err
	}
	out.live, err = readFail2banLiveService(ctx, binding)
	if err != nil || !sameFail2banLive(before, out.live) {
		return out, errors.New("读取期间 Fail2ban 服务身份变化")
	}
	snapshot, generation, err := n.readClientDenySnapshot()
	if err != nil {
		return out, err
	}
	if err = n.observe(ctx, m); err != nil {
		return out, err
	}
	_, after, err := n.readClientDenySnapshot()
	if err != nil {
		return out, err
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
	out.target = fail2ban.JailTarget(bundle.EngineKey, selected, dir, manifestHash(m), registry.ID, out.live.invocation)
	return out, ctx.Err()
}

func (f *fail2banNginxExecutor) addressStatus(ctx context.Context, name, address string) (fail2ban.AddressStatus, error) {
	ip, err := fail2ban.Address(address)
	out := fail2ban.AddressStatus{At: time.Now().Unix(), Jail: name, IP: ip, EngineState: "unknown", ActionState: "unknown"}
	if err != nil || !fail2ban.ManagedJailName(name) {
		return out, fault.Invalid("手动操作须选择本应用的 jail 和单个数值地址")
	}
	n := f.nginx
	leave, ok := n.maintenance.enter(false)
	if !ok {
		out.Reason = "宿主机处于维护状态"
		return out, nil
	}
	defer leave()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil {
		return out, ErrRuntimeUnavailable
	}
	if err = f.addressIdle(); err != nil {
		if !errors.Is(err, ErrBusy) {
			return out, err
		}
		out.Reason = "Nginx 或 jail 操作尚未完成"
		return out, nil
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(n.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	current, err := f.addressContext(ctx, name, ip)
	if err != nil {
		return out, err
	}
	out.At, out.Available, out.Target, out.CanBan = time.Now().Unix(), true, current.target, !current.protected
	out.EngineState, out.ExpiresAt, out.Permanent = fail2banAddressState(current.bans, ip)
	out.ActionState, out.Generation, out.BanTime = current.action, current.generation, current.jail.BanTime
	if current.protected {
		out.Reason = "该地址属于本机、可信代理或忽略列表，仅允许解封"
	}
	return out, nil
}
func fail2banAddressState(bans map[string]fail2banBanTime, ip string) (string, int64, bool) {
	if ticket, exists := bans[ip]; exists {
		return "banned", ticket.Expires, ticket.Duration == -1
	}
	return "clear", 0, false
}
func (f *fail2banNginxExecutor) addressIdle() error {
	n := f.nginx
	if n.disasterBusy != "" || n.http01 != nil && n.http01.busy() {
		return ErrBusy
	}
	records, err := n.Journal.List()
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
func (f *fail2banNginxExecutor) submitAddress(ctx context.Context, in fail2ban.AddressRequest) (fail2ban.AddressOperation, error) {
	var out fail2ban.AddressOperation
	if !in.Valid() {
		return out, fault.Invalid("手动封禁合同无效")
	}
	n := f.nginx
	leave, ok := n.maintenance.enter(false)
	if !ok {
		return out, ErrBusy
	}
	defer leave()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil {
		return out, ErrRuntimeUnavailable
	}
	if old, err := n.Journal.Get(in.OperationID); err == nil {
		if old.Kind != fail2banAddressKind || old.Fail2banAddress == nil || old.RequestHash != in.Hash() {
			return out, fault.Conflict("手动封禁操作 ID 冲突")
		}
		return fail2banAddressView(old), nil
	} else if !os.IsNotExist(err) {
		return out, err
	}
	if err := f.addressIdle(); err != nil {
		return out, err
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(n.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	current, err := f.addressContext(ctx, in.Input.Jail, in.Input.IP)
	if err != nil {
		return out, err
	}
	if current.target != in.Input.Target {
		return out, fault.Conflict("目标服务、Nginx 修订或 jail 授权已变化，请重新核对地址状态")
	}
	if in.Input.Action == "ban" && current.protected {
		return out, fault.Invalid("不能手动封禁本机、可信代理或忽略地址")
	}
	intent := &fail2banAddressIntent{Request: in, Installation: current.r.OperationID, Selection: current.bundle.ID, Engine: current.bundle.EngineKey, Invocation: current.live.invocation, SocketInode: current.live.inode, Submission: "not_sent", EngineState: "unknown"}
	record := Record{OperationID: in.OperationID, RequestHash: in.Hash(), Kind: fail2banAddressKind, State: "running", Stage: "queued", Deadline: time.Now().Add(5 * time.Minute).Unix(), Fail2banAddress: intent}
	if err = n.persist(record); err != nil {
		return out, err
	}
	f.enqueue()
	return fail2banAddressView(record), nil
}

func (f *fail2banNginxExecutor) addressOperation(id string) (fail2ban.AddressOperation, error) {
	if !validID(id) {
		return fail2ban.AddressOperation{}, fault.Invalid("操作 UUID 无效")
	}
	record, err := f.nginx.Journal.Get(id)
	if os.IsNotExist(err) {
		return fail2ban.AddressOperation{}, fault.New(404, "FAIL2BAN_ADDRESS_OPERATION_MISSING", "手动封禁操作记录不存在")
	}
	if err != nil {
		return fail2ban.AddressOperation{}, err
	}
	if record.Kind != fail2banAddressKind || record.Fail2banAddress == nil {
		return fail2ban.AddressOperation{}, fault.Conflict("该 UUID 不属于手动封禁操作")
	}
	if !record.Fail2banAddress.Request.Valid() || record.Fail2banAddress.Request.OperationID != id || record.RequestHash != record.Fail2banAddress.Request.Hash() {
		return fail2ban.AddressOperation{}, errors.New("手动封禁持久合同损坏")
	}
	return fail2banAddressView(record), nil
}
