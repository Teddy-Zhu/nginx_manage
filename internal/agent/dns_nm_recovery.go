package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type nmPending struct {
	Persistent bool   `json:"persistent"`
	Version    uint64 `json:"version"`
	Path       string `json:"path"`
	Active     string `json:"active"`
}
type nmCheckpoint struct {
	BusID            string     `json:"bus_id"`
	Owner            string     `json:"owner"`
	Filename         string     `json:"filename"`
	Method4          string     `json:"method4"`
	Method6          string     `json:"method6"`
	SnapshotHash     string     `json:"snapshot_hash"`
	BeforeApplied    nmDNS      `json:"before_applied"`
	AfterApplied     nmDNS      `json:"after_applied"`
	BeforePersistent nmDNS      `json:"before_persistent"`
	AfterPersistent  nmDNS      `json:"after_persistent"`
	Pending          *nmPending `json:"pending"`
}

func (d *HostDNS) nmPlan(input hostdns.PlanInput) (hostdns.Plan, error) {
	if d.Owner != "networkmanager" || d.hostScopeReason() != "" {
		return hostdns.Plan{}, fault.Unavailable("须由本机确认 NetworkManager 所有者及宿主机范围")
	}
	if d.problem != "" || d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) {
		return hostdns.Plan{}, fault.Conflict("存在待处理的 DNS 恢复记录")
	}
	b, e := openDNSBus(context.Background())
	if e != nil {
		return hostdns.Plan{}, fault.Unavailable("无法连接 NetworkManager")
	}
	defer b.close()
	if nmSupported(b) != nil {
		return hostdns.Plan{}, fault.Unavailable("缺少 NetworkManager 版本检查能力")
	}
	t, e := nmFind(b, input.Target)
	if e != nil {
		return hostdns.Plan{}, fault.Unavailable("连接不可接管，请刷新并检查只读原因")
	}
	if t.View.SourceHash != input.SourceHash {
		return hostdns.Plan{}, fault.Conflict("连接配置已变化，请刷新")
	}
	before, e := nmCapture(t.Applied)
	if e != nil {
		return hostdns.Plan{}, e
	}
	// Both families must be explicit, including an unsupported family's absence.
	if (input.Config.IPv4 == nil) != (t.View.Applied.IPv4 == nil) || (input.Config.IPv6 == nil) != (t.View.Applied.IPv6 == nil) {
		return hostdns.Plan{}, fault.Invalid("须提供该连接所有受支持地址族的 DNS 设置")
	}
	if e = nmModify(t.Applied, input.Config); e != nil {
		return hostdns.Plan{}, fault.Invalid("DNS 设置与连接 IP 方法不兼容")
	}
	after, e := nmCapture(t.Applied)
	if e != nil {
		return hostdns.Plan{}, e
	}
	if nmSame(before, after) {
		return hostdns.Plan{}, fault.Invalid("DNS 设置与当前运行状态相同，无需应用")
	}
	if e = nmModify(t.Persistent, input.Config); e != nil {
		return hostdns.Plan{}, fault.Invalid("DNS 设置与持久连接不兼容")
	}
	now := time.Now().Unix()
	p := hostdns.Plan{Owner: "networkmanager", Input: input, Before: *t.View.Applied, CreatedAt: now, ExpiresAt: now + 300, Impact: "临时修改所选连接的 DNS；确认后保存至 NetworkManager。自动 DNS 可与手动地址合并，路由域和其他连接保留。未确认将恢复运行及持久 DNS；可能影响证书、通知及远程连接。"}
	p.ID = p.Hash()
	return p, nil
}
func (d *HostDNS) nmApply(id string, plan hostdns.Plan) (hostdns.Status, error) {
	fresh, e := d.nmPlan(plan.Input)
	if e != nil {
		return hostdns.Status{}, e
	}
	if fresh.Owner != plan.Owner || !reflect.DeepEqual(fresh.Before, plan.Before) {
		return hostdns.Status{}, fault.Conflict("连接计划与运行状态不一致")
	}
	b, e := openDNSBus(context.Background())
	if e != nil {
		return hostdns.Status{}, fault.Unavailable("无法连接 NetworkManager")
	}
	defer b.close()
	t, e := nmFind(b, plan.Input.Target)
	if e != nil || t.View.SourceHash != plan.Input.SourceHash {
		return hostdns.Status{}, fault.Conflict("连接源已变化")
	}
	n := &nmCheckpoint{BusID: b.busID, Owner: b.owner, Filename: t.Filename, Method4: t.View.Method4, Method6: t.View.Method6}
	n.BeforeApplied, e = nmCapture(t.Applied)
	if e != nil {
		return hostdns.Status{}, e
	}
	n.BeforePersistent, e = nmCapture(t.Persistent)
	if e != nil {
		return hostdns.Status{}, e
	}
	if e = nmModify(t.Applied, plan.Input.Config); e != nil {
		return hostdns.Status{}, e
	}
	if e = nmModify(t.Persistent, plan.Input.Config); e != nil {
		return hostdns.Status{}, e
	}
	n.AfterApplied, e = nmCapture(t.Applied)
	if e != nil {
		return hostdns.Status{}, e
	}
	n.AfterPersistent, e = nmCapture(t.Persistent)
	if e != nil {
		return hostdns.Status{}, e
	}
	n.SnapshotHash = n.hash()
	now := time.Now().Unix()
	if now >= plan.ExpiresAt {
		return hostdns.Status{}, fault.Conflict("DNS 计划已过期")
	}
	d.checkpoint = &dnsCheckpoint{Kind: "host.dns.apply", Plan: plan, NM: n, VerifyAfter: now + 6, Status: hostdns.Status{OperationID: id, PlanID: plan.ID, State: "running", Stage: "applying", Deadline: now + plan.Input.TimeoutSeconds}}
	d.expiry = time.Now().Add(time.Duration(plan.Input.TimeoutSeconds) * time.Second)
	if e = d.persist(); e != nil {
		return hostdns.Status{}, e
	}
	if e = d.nmWrite(b, t, false, n.AfterApplied); e != nil {
		e = d.rollback("连接 DNS 应用未确认，恢复原设置")
		return d.checkpoint.Status, e
	}
	d.checkpoint.Status.State = "waiting_confirmation"
	d.checkpoint.Status.Stage = "verification_pending"
	return d.checkpoint.Status, d.persist()
}
func (d *HostDNS) nmSession(ctx context.Context) (*nmBus, *nmTarget, error) {
	b, e := openDNSBus(ctx)
	if e != nil {
		return nil, nil, e
	}
	t, e := nmFind(b, d.checkpoint.Plan.Input.Target)
	if e == nil && t.Filename != d.checkpoint.NM.Filename {
		e = errors.New("persistent source changed")
	}
	if e != nil {
		b.close()
		return nil, nil, e
	}
	return b, t, nil
}

// The durable pending version is retained on any unknown RPC result. A later
// compensating write must advance that same daemon's version before success;
// observing the old DNS alone does not fence an asynchronously authorized call.
func (d *HostDNS) nmWrite(b *nmBus, t *nmTarget, persistent bool, want nmDNS) error {
	n := d.checkpoint.NM
	if n.Pending != nil {
		return errors.New("unfenced NetworkManager call")
	}
	s := nmSettingsTarget(t, persistent)
	if e := want.restore(s); e != nil {
		return e
	}
	n.BusID = b.busID
	n.Owner = b.owner
	pending := &nmPending{Persistent: persistent, Version: nmVersion(t, persistent), Path: string(t.Device), Active: string(t.Active)}
	if persistent {
		pending.Path = string(t.Profile)
	}
	n.Pending = pending
	if e := d.persist(); e != nil {
		return e
	}
	if e := nmUpdate(b, t, persistent, s); e != nil {
		if e == errNMSourceChanged {
			n.Pending = nil
			if saveErr := d.persist(); saveErr != nil {
				n.Pending = pending
				return saveErr
			}
		}
		return e
	}
	// A reply proves completion; persisting its consumption precedes any other
	// mutation. A crash before consumption is handled by the version fence.
	n.Pending = nil
	if e := d.persist(); e != nil {
		n.Pending = pending
		return e
	}
	return nil
}
func (d *HostDNS) nmCheck(ctx context.Context, persistent bool) (string, error) {
	b, t, e := d.nmSession(ctx)
	if e != nil {
		return "", nmReadError()
	}
	defer b.close()
	n := d.checkpoint.NM
	a, e := nmCapture(t.Applied)
	if e != nil || !nmSame(a, n.AfterApplied) {
		return "", nmReadError()
	}
	p, e := nmCapture(t.Persistent)
	if e != nil {
		return "", e
	}
	expected := n.BeforePersistent
	if persistent {
		expected = n.AfterPersistent
	}
	if !nmSame(p, expected) || n.Pending != nil {
		return "", nmReadError()
	}
	return t.View.SourceHash, b.unchangedOwner()
}
func (d *HostDNS) nmConfirm(ctx context.Context) error {
	n := d.checkpoint.NM
	b, t, e := d.nmSession(ctx)
	if e != nil {
		return e
	}
	defer b.close()
	a, e := nmCapture(t.Applied)
	if e != nil || !nmSame(a, n.AfterApplied) {
		return nmReadError()
	}
	p, e := nmCapture(t.Persistent)
	if e != nil || !nmSame(p, n.BeforePersistent) {
		return nmReadError()
	}
	d.checkpoint.Status.Stage = "persisting"
	if e = d.persist(); e != nil {
		return e
	}
	if !nmSame(n.BeforePersistent, n.AfterPersistent) {
		if e = d.nmWrite(b, t, true, n.AfterPersistent); e != nil {
			return e
		}
	}
	hash, e := d.nmCheck(ctx, true)
	if e != nil {
		return e
	}
	d.checkpoint.Status.SourceHash = hash
	return nil
}
func (d *HostDNS) nmRestoreOne(ctx context.Context, persistent bool) error {
	n := d.checkpoint.NM
	before, after := n.BeforeApplied, n.AfterApplied
	if persistent {
		before, after = n.BeforePersistent, n.AfterPersistent
	}
	b, t, e := d.nmSession(ctx)
	if e != nil {
		return e
	}
	defer b.close()
	current, e := nmSnapshotTarget(t, persistent)
	if e != nil {
		return e
	}
	if !nmSame(current, before) && !nmSame(current, after) {
		return errors.New("external DNS change prevents rollback")
	}
	pending := n.Pending
	if pending != nil {
		if pending.Persistent != persistent {
			return errors.New("another DNS phase is still pending")
		}
		path := string(t.Device)
		if persistent {
			path = string(t.Profile)
		}
		if n.BusID != b.busID || n.Owner != b.owner || pending.Path != path || !persistent && pending.Active != string(t.Active) {
			return errors.New("daemon identity changed with an unresolved RPC")
		}
		if nmVersion(t, persistent) <= pending.Version {
			// Reapply does not advance its version on a no-op. If the old value is
			// still visible, first use the already approved DNS to fence a late call,
			// then restore. No addresses, routes or non-DNS settings are changed.
			fence := before
			if nmSame(current, before) && !persistent {
				fence = after
			}
			s := nmSettingsTarget(t, persistent)
			if e = fence.restore(s); e != nil {
				return e
			}
			if e = nmUpdate(b, t, persistent, s); e != nil {
				return e
			}
			b.close()
			next, nt, err := d.nmSession(ctx)
			if err != nil {
				return err
			}
			defer next.close()
			if next.busID != n.BusID || next.owner != n.Owner || nmVersion(nt, persistent) <= pending.Version {
				return errors.New("pending DNS call could not be fenced")
			}
			got, err := nmSnapshotTarget(nt, persistent)
			if err != nil || !nmSame(got, fence) {
				return errors.New("DNS fence was not observed")
			}
			b, t = next, nt
			current = got
		}
		n.Pending = nil
		if e = d.persist(); e != nil {
			n.Pending = pending
			return e
		}
	}
	if nmSame(current, before) {
		return b.unchangedOwner()
	}
	return d.nmWrite(b, t, persistent, before)
}
func (d *HostDNS) nmRollback() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	n := d.checkpoint.NM
	// Fence the outstanding phase first. Never overwrite its durable identity
	// with a compensating call for the other address state.
	first := true
	if n.Pending != nil {
		first = n.Pending.Persistent
	}
	if e := d.nmRestoreOne(ctx, first); e != nil {
		return "", e
	}
	if e := d.nmRestoreOne(ctx, !first); e != nil {
		return "", e
	}
	b, t, e := d.nmSession(ctx)
	if e != nil {
		return "", e
	}
	defer b.close()
	a, e := nmCapture(t.Applied)
	if e != nil || !nmSame(a, n.BeforeApplied) {
		return "", nmReadError()
	}
	p, e := nmCapture(t.Persistent)
	if e != nil || !nmSame(p, n.BeforePersistent) || n.Pending != nil {
		return "", nmReadError()
	}
	return t.View.SourceHash, b.unchangedOwner()
}
func (c *dnsCheckpoint) validateNM() error {
	if c.NM == nil || c.Plan.Owner != "networkmanager" || c.Plan.Input.Target == "" {
		return errors.New("invalid NetworkManager recovery target")
	}
	n := c.NM
	if n.BusID == "" || n.Owner == "" || len(n.BusID) > 128 || len(n.Owner) > 128 {
		return errors.New("invalid bus identity")
	}
	if n.Pending != nil && (n.Pending.Version == 0 || !strings.HasPrefix(n.Pending.Path, "/org/freedesktop/NetworkManager/") || len(n.Pending.Path) > 256 || len(n.Pending.Active) > 256) {
		return errors.New("invalid pending DNS version")
	}
	if filepath.Dir(n.Filename) != "/etc/NetworkManager/system-connections" || !strings.HasSuffix(n.Filename, ".nmconnection") || n.SnapshotHash != n.hash() {
		return errors.New("invalid DNS snapshot identity")
	}
	for i, snapshot := range []nmDNS{n.BeforeApplied, n.AfterApplied, n.BeforePersistent, n.AfterPersistent} {
		if len(snapshot) > 2 {
			return errors.New("invalid DNS snapshot")
		}
		s := nmSettings{}
		for family := range snapshot {
			if family != "ipv4" && family != "ipv6" {
				return errors.New("invalid IP family snapshot")
			}
			method := n.Method4
			if family == "ipv6" {
				method = n.Method6
			}
			s[family] = map[string]dbus.Variant{"method": dbus.MakeVariant(method)}
		}
		if e := snapshot.restore(s); e != nil {
			return e
		}
		if _, e := nmCapture(s); e != nil {
			return e
		}
		if i == 0 {
			before, _, e := nmConfig(s)
			if e != nil || !reflect.DeepEqual(before, c.Plan.Before) {
				return errors.New("DNS original settings differ from plan")
			}
		}
		if i == 0 || i == 2 {
			if e := nmModify(s, c.Plan.Input.Config); e != nil {
				return e
			}
			after, e := nmCapture(s)
			if e != nil {
				return e
			}
			expected := n.AfterApplied
			if i == 2 {
				expected = n.AfterPersistent
			}
			// Snapshots carry only the four approved DNS properties.
			x, _ := json.Marshal(after)
			y, _ := json.Marshal(expected)
			if string(x) != string(y) {
				return errors.New("DNS snapshot differs from approved settings")
			}
		}
	}
	return nil
}

func (n *nmCheckpoint) hash() string {
	raw, _ := json.Marshal([]any{n.Filename, n.Method4, n.Method6, n.BeforeApplied, n.AfterApplied, n.BeforePersistent, n.AfterPersistent})
	return secure.Hash(raw)
}
