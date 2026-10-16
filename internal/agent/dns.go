package agent

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type dnsCheckpoint struct {
	Kind        string              `json:"kind"`
	Status      hostdns.Status      `json:"status"`
	Plan        hostdns.Plan        `json:"plan"`
	Before      dnsFile             `json:"before"`
	After       dnsFile             `json:"after"`
	NM          *nmCheckpoint       `json:"networkmanager"`
	Networkd    *networkdCheckpoint `json:"networkd"`
	VerifyAfter int64               `json:"verify_after"`
}

// HostDNS never accepts a file path or an executable from the Web process.
// The root checkpoint is outside all business backup/import state.
type HostDNS struct {
	ReachabilityBlocked func() bool
	Dir                 string
	Owner               string
	Scope               string
	Dev                 bool
	Journal             *Journal
	mu                  sync.Mutex
	checkpoint          *dnsCheckpoint
	expiry              time.Time
	problem             string
	locks               []*os.File
}

func dnsActive(state string) bool {
	return state == "running" || state == "waiting_confirmation" || state == "compensating" || state == "recovery_required"
}
func (d *HostDNS) path() string { return filepath.Join(d.Dir, "reachability.json") }
func (d *HostDNS) save() error {
	data, err := json.Marshal(d.checkpoint)
	if err != nil {
		return err
	}
	if len(data) > 128<<10 {
		return errors.New("DNS checkpoint exceeds budget")
	}
	tmp := d.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, d.path()); err != nil {
		return err
	}
	dir, err := os.Open(d.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (d *HostDNS) publish() error {
	s := d.checkpoint.Status
	return d.Journal.Put(Record{OperationID: s.OperationID, Kind: "host.dns.apply", RequestHash: d.checkpoint.Plan.ID, State: s.State, Stage: s.Stage, Deadline: s.Deadline, ObservedRevision: s.SourceHash, AfterRevision: d.checkpoint.Plan.ID, Error: s.Error})
}
func (d *HostDNS) persist() error {
	err := d.save()
	if err == nil {
		err = d.publish()
	}
	d.workerError(err)
	return err
}
func (d *HostDNS) Open() error {
	if d.Dev {
		return nil
	}
	if err := secure.RootDirectory(d.Dir, 0700); err != nil {
		return err
	}
	if err := d.lock(filepath.Join(d.Dir, "lock")); err != nil {
		return err
	}
	if (d.Owner == "regular-file" || d.Owner == "networkmanager" || d.Owner == "networkd") && d.Scope == "host" {
		if err := d.lockHost(); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(d.path(), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
		return errors.New("unsafe reachability checkpoint")
	}
	decoder := json.NewDecoder(io.LimitReader(f, (128<<10)+1))
	decoder.DisallowUnknownFields()
	var c dnsCheckpoint
	if err = decoder.Decode(&c); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid reachability checkpoint")
	}
	if c.Kind != "host.dns.apply" || !validID(c.Status.OperationID) || c.Plan.ID != c.Plan.Hash() || c.Plan.Input.Validate() != nil || c.Status.PlanID != c.Plan.ID || c.Status.Deadline <= c.Plan.CreatedAt {
		return errors.New("unrecognized reachability recovery checkpoint")
	}
	if c.Plan.Owner == "networkmanager" {
		if c.Networkd != nil {
			return errors.New("mixed DNS recovery owners")
		}
		if err = c.validateNM(); err != nil {
			return err
		}
	} else if c.Plan.Owner == "networkd" {
		if err = c.validateNetworkd(); err != nil {
			return err
		}
	} else {
		if c.NM != nil || c.Networkd != nil || c.Plan.Owner != "regular-file" || c.Plan.Input.Target != "" || c.Before.UID != 0 || c.Before.Mode&0022 != 0 || len(c.Before.Data) > hostdns.SourceLimit || len(c.After.Data) > hostdns.SourceLimit {
			return errors.New("invalid DNS file snapshot")
		}
		expected := c.Before
		expected.Data, err = renderDNS(c.Before.Data, c.Plan.Input.Config)
		if err != nil || c.Before.Mode&^uint32(0777) != 0 || c.Before.hash() != c.Plan.Input.SourceHash || !sameDNSFile(expected, c.After) {
			return errors.New("DNS recovery snapshot does not match the approved plan")
		}
	}
	d.checkpoint = &c
	if c.Status.State != "running" && c.Status.State != "waiting_confirmation" && c.Status.State != "compensating" && c.Status.State != "recovery_required" && c.Status.State != "succeeded" && c.Status.State != "rolled_back" {
		return errors.New("invalid reachability recovery state")
	}
	if dnsActive(c.Status.State) {
		if len(d.locks) < 2 {
			if err = d.lockHost(); err != nil {
				return err
			}
		}
		return d.rollback("Agent 重启，恢复未确认的 DNS 设置")
	}
	return d.publish()
}
func (d *HostDNS) lock(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return errors.New("another host DNS owner is active")
	}
	d.locks = append(d.locks, f)
	return nil
}
func (d *HostDNS) lockHost() error {
	if err := secure.RootDirectory("/run/nginxpanel-host", 0700); err != nil {
		return err
	}
	return d.lock("/run/nginxpanel-host/dns.lock")
}
func (d *HostDNS) Close() {
	for _, f := range d.locks {
		f.Close()
	}
	d.locks = nil
}
func (d *HostDNS) observe() hostdns.Observation {
	if d.Owner == "networkd" {
		return d.observeNetworkd()
	}
	if d.Owner == "networkmanager" {
		return d.observeNM()
	}
	out := hostdns.Observation{Owner: "unknown", Source: dnsSource, Current: hostdns.Config{Servers: []string{}, Search: []string{}}, Reason: "尚未确认持久配置所有者"}
	path := dnsSource
	if target, err := os.Readlink(path); err == nil {
		out.LinkTarget = target
		if !filepath.IsAbs(target) {
			target = filepath.Join("/etc", target)
		}
		target = filepath.Clean(target)
		switch target {
		case "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf":
			out.Owner = "resolved"
		case "/run/NetworkManager/resolv.conf":
			out.Owner = "NetworkManager"
		case "/run/resolvconf/resolv.conf":
			out.Owner = "resolvconf"
		default:
			out.Owner = "external"
			out.Reason = "resolv.conf 链接由外部所有者管理"
			return d.withPending(out)
		}
		path = target
	} else if !os.IsNotExist(err) {
		if info, e := os.Lstat(path); e == nil && info.Mode().IsRegular() {
			out.Owner = "regular-file"
		}
	}
	f, err := readDNSFile(path)
	if err != nil {
		out.Reason = "DNS 源不存在、权限不安全或无法完整读取"
		return d.withPending(out)
	}
	out.Current = parseDNS(f.Data)
	out.SourceHash = f.hash()
	if entries, e := os.ReadDir("/etc/netplan"); e == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
				out.Owner = "netplan"
				out.Reason = "netplan 源配置尚未适配，保持只读"
				return d.withPending(out)
			}
		}
	} else if !os.IsNotExist(e) {
		out.Reason = "无法核实 netplan 配置源"
		return d.withPending(out)
	}
	if out.Owner != "regular-file" {
		out.Reason = "当前值来自解析器入口；上游持久所有者尚未适配，保持只读"
		return d.withPending(out)
	}
	config := out.Current
	out.Persistent = &config
	for _, marker := range []string{"generated", "do not edit", "networkmanager", "resolvconf", "cloud-init", "dhclient", "dhcpcd", "netconfig", "docker", "podman", "wsl"} {
		if strings.Contains(strings.ToLower(string(f.Data)), marker) {
			out.Owner = "external"
			out.Reason = "检测到自动生成或外部管理标记，不能接管普通文件"
			return d.withPending(out)
		}
	}
	for _, p := range []struct{ path, owner string }{{"/run/NetworkManager", "NetworkManager"}, {"/run/systemd/netif/state", "networkd"}, {"/run/systemd/resolve", "resolved"}, {"/run/resolvconf", "resolvconf"}, {"/run/dhcpcd", "dhcpcd"}, {"/run/netconfig", "netconfig"}} {
		if _, e := os.Stat(p.path); e == nil {
			out.Owner = p.owner
			out.Persistent = nil
			out.Reason = "发现网络管理器状态，不能把普通文件视为独立配置源"
			return d.withPending(out)
		} else if !os.IsNotExist(e) {
			out.Reason = "网络管理器状态无法核实"
			return d.withPending(out)
		}
	}
	if strings.Contains(string(f.Data), "no-reload") {
		out.Reason = "解析器禁止自动重载，不能安全应用 DNS"
		return d.withPending(out)
	}
	if reason := d.hostScopeReason(); reason != "" {
		out.Reason = reason
		return d.withPending(out)
	}
	if d.Owner != "regular-file" {
		out.Reason = "须先由本机确认无外部管理器，并设置 --dns-owner=regular-file"
		return d.withPending(out)
	}
	out.Writable = true
	out.Reason = ""
	return d.withPending(out)
}
func (d *HostDNS) hostScopeReason() string {
	if d.Dev || d.Scope != "host" {
		return "开发模式或未由本机确认宿主机范围，禁止 DNS 写入"
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, e := os.Stat(p); e == nil {
			return "容器 Agent 不允许修改宿主机 DNS"
		}
	}
	if raw, e := dnsCgroup(); e != nil {
		return "无法核实宿主机控制组"
	} else {
		for _, marker := range []string{"docker", "kubepods", "libpod", "lxc"} {
			if strings.Contains(string(raw), marker) {
				return "容器控制组不允许修改宿主机 DNS"
			}
		}
	}
	return ""
}
func dnsCgroup() ([]byte, error) {
	f, err := os.Open("/proc/1/cgroup")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if len(b) > 64<<10 {
		return nil, errors.New("cgroup source exceeds budget")
	}
	return b, err
}
func (d *HostDNS) withPending(out hostdns.Observation) hostdns.Observation {
	if out.Links == nil {
		out.Links = []hostdns.NetworkLink{}
	}
	if out.Connections == nil {
		out.Connections = []hostdns.Connection{}
	}
	if out.Owner == "networkd" && len(out.Links) == 0 {
		out.Writable = false
	}
	if d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) {
		copy := d.checkpoint.Status
		out.Pending = &copy
		out.Writable = false
		out.Reason = "存在未完成的可达性变更，须先确认或恢复"
	}
	if d.problem != "" {
		out.Writable = false
		out.Reason = d.problem
	}
	return out
}
func (d *HostDNS) Read() hostdns.Observation { d.mu.Lock(); defer d.mu.Unlock(); return d.observe() }
func (d *HostDNS) Plan(input hostdns.PlanInput) (hostdns.Plan, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := input.Validate(); err != nil {
		return hostdns.Plan{}, err
	}
	input = input.Normalize()
	if hostdns.NetworkdTarget(input.Target) {
		return d.networkdPlan(input)
	}
	if input.Target != "" {
		return d.nmPlan(input)
	}
	view := d.observe()
	if !view.Writable {
		return hostdns.Plan{}, fault.Unavailable(view.Reason)
	}
	if view.SourceHash != input.SourceHash {
		return hostdns.Plan{}, fault.Conflict("DNS 源已变化，请刷新")
	}
	if input.Config.Search == nil {
		input.Config.Search = []string{}
	}
	now := time.Now().Unix()
	plan := hostdns.Plan{Owner: "regular-file", Input: input, Before: view.Current, CreatedAt: now, ExpiresAt: now + 300, Impact: "变更主机解析器，可能影响 ACME、更新、通知及远程节点连接；未确认将在期限到达或 Agent 重启时恢复"}
	plan.ID = plan.Hash()
	return plan, nil
}
func (d *HostDNS) Status(id string) (hostdns.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status(id)
}
func (d *HostDNS) status(id string) (hostdns.Status, error) {
	if d.checkpoint != nil && d.checkpoint.Status.OperationID == id {
		return d.checkpoint.Status, nil
	}
	r, err := d.Journal.Get(id)
	if err != nil {
		return hostdns.Status{}, err
	}
	if r.Kind != "host.dns.apply" {
		return hostdns.Status{}, fault.Conflict("操作类型不匹配")
	}
	return hostdns.Status{OperationID: id, PlanID: r.RequestHash, State: r.State, Stage: r.Stage, Deadline: r.Deadline, SourceHash: r.ObservedRevision, Error: r.Error}, nil
}
func (d *HostDNS) Apply(id string, plan hostdns.Plan) (hostdns.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !validID(id) || plan.ID != plan.Hash() || (plan.Owner != "regular-file" && plan.Owner != "networkmanager" && plan.Owner != "networkd") {
		return hostdns.Status{}, fault.Invalid("DNS 计划无效")
	}
	if err := plan.Input.Validate(); err != nil {
		return hostdns.Status{}, err
	}
	if old, err := d.status(id); err == nil {
		r, e := d.Journal.Get(id)
		if e == nil && r.RequestHash != plan.ID {
			return old, fault.Conflict("操作计划不匹配")
		}
		if d.checkpoint != nil && d.checkpoint.Status.OperationID == id && d.checkpoint.Plan.ID != plan.ID {
			return old, fault.Conflict("操作计划不匹配")
		}
		return old, nil
	} else if !os.IsNotExist(err) {
		return hostdns.Status{}, err
	}
	now := time.Now().Unix()
	if now >= plan.ExpiresAt || plan.ExpiresAt-plan.CreatedAt != 300 || plan.CreatedAt > now {
		return hostdns.Status{}, fault.Conflict("DNS 计划已过期")
	}
	if d.ReachabilityBlocked != nil && d.ReachabilityBlocked() {
		return hostdns.Status{}, fault.Conflict("管理监听存在待确认或待恢复的变更")
	}
	if plan.Owner == "networkmanager" {
		return d.nmApply(id, plan)
	}
	if plan.Owner == "networkd" {
		return d.networkdApply(id, plan)
	}
	if plan.Input.Target != "" {
		return hostdns.Status{}, fault.Invalid("普通文件计划不能包含连接目标")
	}
	view := d.observe()
	if !view.Writable || view.Owner != "regular-file" {
		return hostdns.Status{}, fault.Unavailable("普通文件源不可接管")
	}
	if view.SourceHash != plan.Input.SourceHash {
		return hostdns.Status{}, fault.Conflict("DNS 源已变化")
	}
	before, err := readDNSFile(dnsSource)
	if err != nil {
		return hostdns.Status{}, err
	}
	if before.hash() != plan.Input.SourceHash {
		return hostdns.Status{}, fault.Conflict("DNS 源已变化")
	}
	after := before
	after.Data, err = renderDNS(before.Data, plan.Input.Config)
	if err != nil {
		return hostdns.Status{}, err
	}
	// Persist both snapshots and the rollback deadline before replacing DNS.
	d.checkpoint = &dnsCheckpoint{Kind: "host.dns.apply", Plan: plan, Before: before, After: after, VerifyAfter: now + 6, Status: hostdns.Status{OperationID: id, PlanID: plan.ID, State: "running", Stage: "applying", Deadline: now + plan.Input.TimeoutSeconds}}
	d.expiry = time.Now().Add(time.Duration(plan.Input.TimeoutSeconds) * time.Second)
	if err = d.persist(); err != nil {
		return hostdns.Status{}, err
	}
	if err = writeDNSFile(before, after, id); err != nil {
		if rollbackErr := d.rollback("DNS 写入未完成，已请求恢复"); rollbackErr != nil {
			return d.checkpoint.Status, rollbackErr
		}
		return d.checkpoint.Status, nil
	}
	d.checkpoint.Status.State = "waiting_confirmation"
	d.checkpoint.Status.Stage = "verification_pending"
	if err = d.persist(); err != nil {
		return d.checkpoint.Status, err
	}
	return d.checkpoint.Status, nil
}
func (d *HostDNS) verify(ctx context.Context) error {
	checkSource := func() error {
		if d.checkpoint.NM != nil {
			hash, e := d.nmCheck(ctx, false)
			if e == nil {
				d.checkpoint.Status.SourceHash = hash
			}
			return e
		}
		if d.checkpoint.Networkd != nil {
			hash, e := d.networkdCheck(ctx, false)
			if e == nil {
				d.checkpoint.Status.SourceHash = hash
			}
			return e
		}
		current, e := readDNSFile(dnsSource)
		if e != nil || !sameDNSFile(current, d.checkpoint.After) {
			return fault.Conflict("DNS 文件已被外部修改")
		}
		d.checkpoint.Status.SourceHash = current.hash()
		return nil
	}
	if err := checkSource(); err != nil {
		return err
	}
	resolver := &net.Resolver{PreferGo: false}
	check, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, name := range d.checkpoint.Plan.Input.VerifyNames {
		ips, e := resolver.LookupIPAddr(check, name)
		if e != nil || len(ips) == 0 {
			return fault.Unavailable("配置的验证域名未通过本机解析链核验")
		}
	}
	return checkSource()
}

func (d *HostDNS) rollback(reason string) error {
	c := d.checkpoint
	c.Status.State = "compensating"
	c.Status.Stage = "rolling_back"
	c.Status.Error = reason
	// The original durable intent already authorizes restoration. A full disk
	// must not prevent an attempt to restore merely because this stage cannot
	// be recorded again; persist reports the failure through health and logs.
	_ = d.persist()
	var hash string
	var err error
	if c.NM != nil {
		hash, err = d.nmRollback()
	} else if c.Networkd != nil {
		hash, err = d.networkdRollback()
	} else {
		var current dnsFile
		current, err = readDNSFile(dnsSource)
		if err == nil && !sameDNSFile(current, c.Before) {
			if !sameDNSFile(current, c.After) {
				err = errors.New("external DNS change prevents automatic rollback")
			} else {
				err = writeDNSFile(current, c.Before, c.Status.OperationID)
			}
		}
		if err == nil {
			current, err = readDNSFile(dnsSource)
			if err == nil && !sameDNSFile(current, c.Before) {
				err = errors.New("DNS rollback could not be confirmed")
			}
		}
		if err == nil {
			err = cleanDNSTemp(c.Status.OperationID)
			hash = current.hash()
		}
	}
	if err != nil {
		c.Status.State = "recovery_required"
		c.Status.Stage = "rollback_unconfirmed"
		c.Status.Error = "DNS 恢复未确认；保留快照，须本机处理外部修改、源权限或未决连接调用"
		if errors.Is(err, errNetworkdCallPending) {
			c.Status.Error = "networkd 调用结果不明；保留快照，须本机确认原 networkd 进程已退出后重试恢复"
		}
	} else {
		c.Status.State = "rolled_back"
		c.Status.Stage = "rolled_back"
		c.Status.SourceHash = hash
	}
	if saveErr := d.persist(); saveErr != nil {
		c.Status.State = "compensating"
		c.Status.Stage = "rolling_back"
		return saveErr
	}
	return nil
}
func (d *HostDNS) Decide(ctx context.Context, id, action string) (hostdns.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out, err := d.status(id)
	if err != nil {
		return out, err
	}
	if action != "confirm" && action != "rollback" {
		return out, fault.Invalid("DNS 确认动作无效")
	}
	if !dnsActive(out.State) {
		return out, nil
	}
	if d.checkpoint == nil || d.checkpoint.Status.OperationID != id {
		return out, fault.Conflict("恢复快照与操作不一致")
	}
	if action == "rollback" || d.expired() {
		err = d.rollback("已请求恢复或确认期限已到")
		return d.checkpoint.Status, err
	}
	if out.State != "waiting_confirmation" || out.Stage != "awaiting_confirmation" {
		return out, fault.Conflict("DNS 尚未完成解析核验，不能确认")
	}
	if err = d.verify(ctx); err != nil {
		if rollbackErr := d.rollback("确认时解析核验失败，恢复原设置"); rollbackErr != nil {
			return d.checkpoint.Status, rollbackErr
		}
		return d.checkpoint.Status, nil
	}
	if d.expired() {
		err = d.rollback("解析核验期间确认期限已到")
		return d.checkpoint.Status, err
	}
	if d.checkpoint.NM != nil {
		err = d.nmConfirm(ctx)
	} else if d.checkpoint.Networkd != nil {
		err = d.networkdConfirm(ctx)
	}
	if err != nil {
		err = d.rollback("DNS 持久化未确认，恢复原设置")
		return d.checkpoint.Status, err
	}
	if d.checkpoint.NM != nil || d.checkpoint.Networkd != nil {
		if d.expired() {
			err = d.rollback("保存期间确认期限已到")
			return d.checkpoint.Status, err
		}
	}
	before := d.checkpoint.Status
	d.checkpoint.Status.State = "succeeded"
	d.checkpoint.Status.Stage = "confirmed"
	d.checkpoint.Status.Error = ""
	if err = d.save(); err != nil {
		d.checkpoint.Status = before
		d.workerError(err)
		return before, err
	}
	err = d.publish()
	d.workerError(err)
	return d.checkpoint.Status, err
}
func (d *HostDNS) Run(ctx context.Context) {
	if d.Dev {
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			if d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) && d.checkpoint.Status.State != "recovery_required" {
				d.workerError(d.rollback("Agent 停止，恢复未确认设置"))
			}
			d.mu.Unlock()
			return
		case <-tick.C:
			d.mu.Lock()
			c := d.checkpoint
			if c != nil && dnsActive(c.Status.State) && c.Status.State != "recovery_required" {
				var err error
				if d.expired() || (c.Status.Stage == "applying" || c.Status.Stage == "persisting") || c.Status.State == "compensating" {
					err = d.rollback("DNS 未在期限内确认，恢复原设置")
				} else if c.Status.Stage == "verification_pending" && time.Now().Unix() >= c.VerifyAfter {
					if err = d.verify(ctx); err != nil {
						err = d.rollback("本机解析核验失败，恢复原设置")
					} else if d.expired() {
						err = d.rollback("解析核验期间确认期限已到")
					} else {
						c.Status.Stage = "awaiting_confirmation"
						if err = d.persist(); err != nil {
							c.Status.Stage = "applying"
						}
					}
				}
				if err != nil {
					d.workerError(err)
				}
			}
			d.mu.Unlock()
		}
	}
}
func (d *HostDNS) expired() bool {
	return time.Now().Unix() >= d.checkpoint.Status.Deadline || !d.expiry.IsZero() && !time.Now().Before(d.expiry)
}
func (d *HostDNS) workerError(err error) {
	if err != nil {
		if d.problem == "" {
			slog.Warn("host DNS recovery journal unavailable")
		}
		d.problem = "DNS 独立恢复记录不可用；须本机检查存储，禁止后续写入"
	} else {
		d.problem = ""
	}
}
