package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
)

type networkdProcess struct {
	Boot  string `json:"boot"`
	PID   uint32 `json:"pid"`
	Start string `json:"start"`
}
type networkdCheckpoint struct {
	Boot      string           `json:"boot"`
	Base      string           `json:"base"`
	File      string           `json:"file"`
	Index     int32            `json:"index"`
	OtherHash string           `json:"other_hash"`
	Before    hostdns.LinkDNS  `json:"before"`
	After     hostdns.LinkDNS  `json:"after"`
	Routes    []string         `json:"routes"`
	Pending   *networkdProcess `json:"pending"`
}

var errNetworkdCallPending = errors.New("networkd call outcome is unknown; original daemon must exit before recovery")

func networkProcRead(name string, limit int64) ([]byte, error) {
	f, e := os.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, errors.New("networkd process metadata unavailable")
	}
	return raw, nil
}
func networkProcess(pid uint32) (networkdProcess, error) {
	out := networkdProcess{PID: pid}
	boot, e := networkProcRead("/proc/sys/kernel/random/boot_id", 64)
	if e != nil {
		return out, e
	}
	out.Boot = strings.TrimSpace(string(boot))
	if !validID(out.Boot) || pid < 2 {
		return out, errors.New("invalid networkd process identity")
	}
	raw, e := networkProcRead("/proc/"+strconv.FormatUint(uint64(pid), 10)+"/stat", 4096)
	if e != nil {
		return out, e
	}
	at := strings.LastIndex(string(raw), ") ")
	if at < 0 {
		return out, errors.New("invalid networkd process stat")
	}
	fields := strings.Fields(string(raw)[at+2:])
	if len(fields) < 20 {
		return out, errors.New("incomplete networkd process stat")
	}
	if start, e := strconv.ParseUint(fields[19], 10, 64); e != nil || start == 0 {
		return out, errors.New("invalid networkd start identity")
	}
	out.Start = fields[19]
	return out, nil
}
func (b *dnsBus) networkdProcess() (networkdProcess, error) {
	var pid uint32
	if e := b.conn.BusObject().CallWithContext(b.ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", dbus.FlagNoAutoStart, b.owner).Store(&pid); e != nil {
		return networkdProcess{}, e
	}
	out, e := networkProcess(pid)
	if e != nil {
		return out, e
	}
	return out, b.unchangedOwner()
}
func networkdCallEnded(p networkdProcess) bool {
	boot, e := networkProcRead("/proc/sys/kernel/random/boot_id", 64)
	if e != nil || !validID(strings.TrimSpace(string(boot))) {
		return false
	}
	if strings.TrimSpace(string(boot)) != p.Boot {
		return true
	}
	now, e := networkProcess(p.PID)
	return os.IsNotExist(e) || e == nil && now != p
}

func openNetworkd(ctx context.Context) (*dnsBus, *dnsBus, error) {
	b, e := openDNSService(ctx, networkdName)
	if e != nil {
		return nil, nil, e
	}
	r, e := openDNSService(ctx, resolvedName)
	if e != nil {
		b.close()
		return nil, nil, e
	}
	return b, r, nil
}

func (d *HostDNS) networkdPlan(input hostdns.PlanInput) (hostdns.Plan, error) {
	if d.Owner != "networkd" || d.hostScopeReason() != "" {
		return hostdns.Plan{}, fault.Unavailable("须由本机确认 networkd 所有者及宿主机范围")
	}
	if d.problem != "" || d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) {
		return hostdns.Plan{}, fault.Conflict("存在待处理的 DNS 恢复记录")
	}
	if reason := networkdResolverReason(); reason != "" {
		return hostdns.Plan{}, fault.Unavailable(reason)
	}
	b, r, e := openNetworkd(context.Background())
	if e != nil {
		return hostdns.Plan{}, fault.Unavailable("无法连接宿主机 networkd/resolved")
	}
	defer b.close()
	defer r.close()
	if e = networkdSupported(b); e != nil {
		return hostdns.Plan{}, fault.Unavailable("缺少已确认的 networkd DNS 局部写入接口")
	}
	t, e := findNetworkd(b, r, input.Target)
	if e != nil {
		return hostdns.Plan{}, fault.Unavailable("无法完整核对 networkd 链路与配置源")
	}
	if !t.View.Writable {
		return hostdns.Plan{}, fault.Unavailable(t.View.Reason)
	}
	if input.SourceHash != t.View.SourceHash {
		return hostdns.Plan{}, fault.Conflict("networkd 配置或解析状态已变化，请刷新")
	}
	before := networkConfig(t.View.Persistent)
	for _, search := range input.Config.Search {
		for _, route := range t.View.Persistent.RoutingDomains {
			if strings.EqualFold(search, strings.TrimSuffix(strings.TrimPrefix(route, "~"), ".")) {
				return hostdns.Plan{}, fault.Invalid("搜索域与保留的路由域冲突")
			}
		}
	}
	after := networkConfigState(input.Config, t.View.Persistent.RoutingDomains)
	if networkSame(t.View.Loaded, &after) {
		return hostdns.Plan{}, fault.Invalid("DNS 设置与当前状态相同，无需应用")
	}
	last := t.Sources[len(t.Sources)-1]
	if _, e = renderNetworkDNS(last.File.Data, input.Config, t.View.Persistent.RoutingDomains); e != nil {
		return hostdns.Plan{}, fault.Invalid("DNS 候选超过持久源容量限制")
	}
	now := time.Now().Unix()
	p := hostdns.Plan{Owner: "networkd", Input: input, Before: before, CreatedAt: now, ExpiresAt: now + 300, Impact: "临时修改所选静态链路的 DNS 与搜索域，保留路由域和自动获取策略；确认后保存持久配置。未确认将恢复运行与持久 DNS。地址、网关、路由及其他链路不重载。"}
	p.ID = p.Hash()
	return p, nil
}

func (d *HostDNS) networkdApply(id string, plan hostdns.Plan) (hostdns.Status, error) {
	fresh, e := d.networkdPlan(plan.Input)
	if e != nil {
		return hostdns.Status{}, e
	}
	if fresh.Owner != plan.Owner || !reflect.DeepEqual(fresh.Before, plan.Before) {
		return hostdns.Status{}, fault.Conflict("networkd 计划与源状态不一致")
	}
	b, r, e := openNetworkd(context.Background())
	if e != nil {
		return hostdns.Status{}, e
	}
	defer b.close()
	defer r.close()
	t, e := findNetworkd(b, r, plan.Input.Target)
	if e != nil {
		return hostdns.Status{}, e
	}
	if !t.View.Writable || t.View.SourceHash != plan.Input.SourceHash {
		return hostdns.Status{}, fault.Conflict("networkd 源已变化")
	}
	last := t.Sources[len(t.Sources)-1]
	before, e := networkCanonical(t.View.Loaded)
	if e != nil {
		return hostdns.Status{}, e
	}
	afterConfig := networkConfigState(plan.Input.Config, t.View.Persistent.RoutingDomains)
	after, e := networkCanonical(&afterConfig)
	if e != nil {
		return hostdns.Status{}, e
	}
	fileAfter := last.File
	fileAfter.Data, e = renderNetworkDNS(last.File.Data, plan.Input.Config, t.View.Persistent.RoutingDomains)
	if e != nil {
		return hostdns.Status{}, e
	}
	peer, e := b.networkdProcess()
	if e != nil {
		return hostdns.Status{}, e
	}
	n := &networkdCheckpoint{Boot: peer.Boot, Base: t.Sources[0].Path, File: last.Path, Index: t.Ref.Index, OtherHash: networkOtherHash(t.Sources, last.Path), Before: before, After: after, Routes: append([]string{}, t.View.Persistent.RoutingDomains...)}
	now := time.Now().Unix()
	if now >= plan.ExpiresAt {
		return hostdns.Status{}, fault.Conflict("DNS 计划已过期")
	}
	d.checkpoint = &dnsCheckpoint{Kind: "host.dns.apply", Plan: plan, Before: last.File, After: fileAfter, Networkd: n, VerifyAfter: now + 6, Status: hostdns.Status{OperationID: id, PlanID: plan.ID, State: "running", Stage: "applying", Deadline: now + plan.Input.TimeoutSeconds}}
	d.expiry = time.Now().Add(time.Duration(plan.Input.TimeoutSeconds) * time.Second)
	if e = d.persist(); e != nil {
		return d.checkpoint.Status, e
	}
	if e = d.networkdWrite(b, t.Ref.Index, "SetLinkDNSEx", n.After); e == nil {
		// Re-read through a new bounded session between the two DNS fields.
		b.close()
		r.close()
		b, r, t, e = d.networkdSession(context.Background())
		if e == nil {
			defer b.close()
			defer r.close()
			e = d.networkdLoaded(t, true, false)
		}
		if e == nil {
			e = d.networkdWrite(b, t.Ref.Index, "SetLinkDomains", n.After)
		}
	}
	if e != nil {
		e = d.rollback("networkd DNS 应用未确认，恢复原设置")
		return d.checkpoint.Status, e
	}
	d.checkpoint.Status.State = "waiting_confirmation"
	d.checkpoint.Status.Stage = "verification_pending"
	return d.checkpoint.Status, d.persist()
}

func (d *HostDNS) networkdSession(ctx context.Context) (*dnsBus, *dnsBus, *networkdTarget, error) {
	if d.hostScopeReason() != "" {
		return nil, nil, nil, errors.New("host DNS scope is unconfirmed")
	}
	b, r, e := openNetworkd(ctx)
	if e != nil {
		return nil, nil, nil, e
	}
	t, e := findNetworkd(b, r, d.checkpoint.Plan.Input.Target)
	n := d.checkpoint.Networkd
	boot, bootErr := networkProcRead("/proc/sys/kernel/random/boot_id", 64)
	if bootErr == nil && !validID(strings.TrimSpace(string(boot))) {
		bootErr = errors.New("invalid host boot identity")
	}
	if e == nil && bootErr != nil {
		e = bootErr
	}
	if e == nil && (t.Ref.Index != n.Index && strings.TrimSpace(string(boot)) == n.Boot || len(t.Sources) == 0 || t.Sources[0].Path != n.Base || t.Sources[len(t.Sources)-1].Path != n.File || networkOtherHash(t.Sources, n.File) != n.OtherHash) {
		e = errors.New("networkd target or unrelated source changed")
	}
	if e == nil && !sameDNSFile(t.Sources[len(t.Sources)-1].File, d.checkpoint.Before) && !sameDNSFile(t.Sources[len(t.Sources)-1].File, d.checkpoint.After) {
		e = errors.New("networkd persistent DNS source changed externally")
	}
	if e == nil {
		e = d.netplanSourceEither()
	}
	if e != nil {
		b.close()
		r.close()
		return nil, nil, nil, e
	}
	return b, r, t, nil
}

func (d *HostDNS) networkdWrite(b *dnsBus, index int32, method string, want hostdns.LinkDNS) error {
	if method != "SetLinkDNSEx" && method != "SetLinkDomains" {
		return errors.New("invalid networkd DNS mutation")
	}
	n := d.checkpoint.Networkd
	if n.Pending != nil {
		return errors.New("unfenced networkd DNS call")
	}
	peer, e := b.networkdProcess()
	if e != nil {
		return e
	}
	n.Pending = &peer
	if e = d.persist(); e != nil {
		return e
	}
	switch method {
	case "SetLinkDNSEx":
		e = b.call(networkdRoot, networkdName+".Manager."+method, index, networkDNSWire(want)).Err
	case "SetLinkDomains":
		e = b.call(networkdRoot, networkdName+".Manager."+method, index, networkDomainsWire(want)).Err
	default:
		return errors.New("invalid networkd DNS mutation")
	}
	if e != nil && !knownNetworkdRejection(e) {
		return e
	}
	n.Pending = nil
	if saveErr := d.persist(); saveErr != nil {
		n.Pending = &peer
		return saveErr
	}
	return e
}

func (d *HostDNS) networkdLoaded(t *networkdTarget, afterServers, afterDomains bool) error {
	n := d.checkpoint.Networkd
	servers, domains := n.Before.Servers, n.Before.Domains
	if afterServers {
		servers = n.After.Servers
	}
	if afterDomains {
		domains = n.After.Domains
	}
	want := hostdns.LinkDNS{Servers: servers, Domains: domains}
	if !networkSame(&want, t.View.Loaded) {
		return errors.New("networkd DNS differs from the approved state")
	}
	return nil
}

func (d *HostDNS) networkdRuntime(t *networkdTarget, afterServers, afterDomains bool) error {
	if e := d.networkdLoaded(t, afterServers, afterDomains); e != nil {
		return e
	}
	if !networkSame(t.View.Loaded, t.View.Effective) {
		return errors.New("resolved DNS has not converged to networkd")
	}
	return nil
}

func (d *HostDNS) networkdCheck(ctx context.Context, persistent bool) (string, error) {
	if reason := networkdResolverReason(); reason != "" {
		return "", errors.New(reason)
	}
	b, r, t, e := d.networkdSession(ctx)
	if e != nil {
		return "", e
	}
	defer b.close()
	defer r.close()
	c, n := d.checkpoint, d.checkpoint.Networkd
	want := c.Before
	if persistent {
		want = c.After
	}
	if n.Pending != nil || !sameDNSFile(t.Sources[len(t.Sources)-1].File, want) {
		return "", errors.New("networkd persistent source or pending call changed")
	}
	if e = d.networkdRuntime(t, true, true); e != nil {
		return "", e
	}
	if c.Netplan != nil {
		s, err := d.netplanSourcesCheck(persistent)
		if err != nil {
			return "", err
		}
		return netplanViewHash(s, t.View.SourceHash), b.unchangedOwner()
	}
	return t.View.SourceHash, b.unchangedOwner()
}

func (d *HostDNS) networkdConfirm(ctx context.Context) error {
	if _, e := d.networkdCheck(ctx, false); e != nil {
		return e
	}
	b, r, t, e := d.networkdSession(ctx)
	if e != nil {
		return e
	}
	defer b.close()
	defer r.close()
	c, n := d.checkpoint, d.checkpoint.Networkd
	if e = d.networkdRuntime(t, true, true); e != nil {
		return e
	}
	c.Status.Stage = "persisting"
	if e = d.persist(); e != nil {
		return e
	}
	if c.Netplan != nil {
		if e = d.netplanPersistSource(); e != nil {
			return e
		}
		if d.expired() {
			return errors.New("netplan confirmation deadline elapsed")
		}
	}
	if e = writeHostDNSFile(n.File, t.Sources[len(t.Sources)-1].File, c.After, c.Status.OperationID); e != nil {
		return e
	}
	// Saving DNS does not reload networkd or renew a lease. The live DNS-only
	// override stays active; the persistent source supplies it on the next boot.
	hash, e := d.networkdCheck(ctx, true)
	if e == nil {
		c.Status.SourceHash = hash
	}
	return e
}

func (d *HostDNS) networkdRollback() (string, error) {
	c, n := d.checkpoint, d.checkpoint.Networkd
	if d.hostScopeReason() != "" {
		return "", errors.New("host DNS scope is unconfirmed")
	}
	if c.Netplan != nil {
		if e := d.netplanRestoreSource(); e != nil {
			return "", e
		}
	}
	if _, e := networkDirectoryState(filepath.Dir(n.File)); e != nil {
		return "", e
	}
	file, e := readDNSFile(n.File)
	if e != nil {
		return "", e
	}
	// Restore an unconfirmed persistent write even when an RPC still needs a
	// process-death fence. Such a write must never become the next boot's DNS.
	if !sameDNSFile(file, c.Before) {
		if !sameDNSFile(file, c.After) {
			return "", errors.New("external networkd source change prevents rollback")
		}
		if e = writeHostDNSFile(n.File, file, c.Before, c.Status.OperationID); e != nil {
			return "", e
		}
	}
	if n.Pending != nil {
		if !networkdCallEnded(*n.Pending) {
			return "", errNetworkdCallPending
		}
		pending := n.Pending
		n.Pending = nil
		if e = d.persist(); e != nil {
			n.Pending = pending
			return "", e
		}
	}
	var b, r *dnsBus
	var t *networkdTarget
	for _, field := range []string{"SetLinkDNSEx", "SetLinkDomains"} {
		if b != nil {
			b.close()
			r.close()
		}
		b, r, t, e = d.networkdSession(context.Background())
		if e != nil {
			return "", e
		}
		defer b.close()
		defer r.close()
		observed, e := networkCanonical(t.View.Loaded)
		if e != nil {
			return "", e
		}
		current, before, after := any(observed.Servers), any(n.Before.Servers), any(n.After.Servers)
		if field == "SetLinkDomains" {
			current, before, after = observed.Domains, n.Before.Domains, n.After.Domains
		}
		if reflect.DeepEqual(current, before) {
			continue
		}
		if !reflect.DeepEqual(current, after) {
			return "", errors.New("external networkd runtime change prevents rollback")
		}
		if e = d.networkdWrite(b, t.Ref.Index, field, n.Before); e != nil {
			return "", e
		}
	}
	b.close()
	r.close()
	// resolved follows networkd asynchronously. Bound the recovery observation
	// without retrying mutations or claiming success from networkd alone.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		b, r, t, e = d.networkdSession(ctx)
		if e != nil {
			return "", e
		}
		e = d.networkdLoaded(t, false, false)
		if e == nil && !sameDNSFile(t.Sources[len(t.Sources)-1].File, c.Before) {
			e = errors.New("networkd source rollback is unconfirmed")
		}
		converged := networkSame(t.View.Loaded, t.View.Effective)
		b.close()
		r.close()
		if e != nil {
			return "", e
		}
		if converged {
			if e = cleanDNSFileTemp(n.File, c.Status.OperationID); e != nil {
				return "", e
			}
			if c.Netplan != nil {
				if e = cleanDNSFileTemp(c.Netplan.File, c.Status.OperationID); e != nil {
					return "", e
				}
				s, err := d.netplanSourcesCheck(false)
				if err != nil {
					return "", err
				}
				return netplanViewHash(s, t.View.SourceHash), nil
			}
			return t.View.SourceHash, nil
		}
		select {
		case <-ctx.Done():
			return "", errors.New("resolved DNS rollback is unconfirmed")
		case <-tick.C:
		}
	}
}

func (c *dnsCheckpoint) validateNetworkd() error {
	n := c.Networkd
	if n == nil || c.NM != nil || !(c.Plan.Owner == "networkd" && c.Netplan == nil || c.Plan.Owner == "netplan" && c.Netplan != nil) || !hostdns.NetworkdTarget(c.Plan.Input.Target) || c.Netplan == nil && !networkWritableSource(n.File) || c.Netplan != nil && n.File != n.Base || !networkSourcePath(n.Base, filepath.Base(n.Base), false) || n.File != n.Base && !networkSourcePath(n.File, filepath.Base(n.Base), true) || n.Index <= 0 || !validID(n.Boot) || len(n.OtherHash) != 64 || len(n.Routes) > 128 {
		return errors.New("invalid networkd recovery identity")
	}
	for _, f := range []dnsFile{c.Before, c.After} {
		if f.UID != 0 || f.Mode&^uint32(0777) != 0 || f.Mode&0022 != 0 || len(f.Data) > hostdns.SourceLimit {
			return errors.New("invalid networkd source snapshot")
		}
	}
	var expected []byte
	var e error
	if c.Netplan != nil {
		e = c.validateNetplan()
		expected = c.After.Data
	} else {
		expected, e = renderNetworkDNS(c.Before.Data, c.Plan.Input.Config, n.Routes)
	}
	file := c.Before
	file.Data = expected
	before := networkConfigState(c.Plan.Before, n.Routes)
	after := networkConfigState(c.Plan.Input.Config, n.Routes)
	if e != nil || !sameDNSFile(file, c.After) || !networkSame(&before, &n.Before) || !networkSame(&after, &n.After) {
		return errors.New("networkd snapshots do not match the approved plan")
	}
	if n.Pending != nil {
		if !validID(n.Pending.Boot) || n.Pending.PID < 2 || len(n.Pending.Start) > 20 {
			return errors.New("invalid pending networkd process")
		}
		if v, e := strconv.ParseUint(n.Pending.Start, 10, 64); e != nil || v == 0 {
			return errors.New("invalid pending networkd process start")
		}
	}
	return nil
}
