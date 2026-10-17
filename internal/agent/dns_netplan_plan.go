package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type netplanSourceProof struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}
type netplanCheckpoint struct {
	File    string               `json:"file"`
	Before  dnsFile              `json:"before"`
	After   dnsFile              `json:"after"`
	Sources []netplanSourceProof `json:"sources"`
	Tool    netplanTool          `json:"tool"`
}
type netplanProposal struct {
	Plan      hostdns.Plan
	Netplan   netplanCheckpoint
	Target    *networkdTarget
	Generated dnsFile
}

func netplanViewHash(s *netplanSnapshot, backend string) string {
	raw, _ := json.Marshal([]string{"netplan-dns-v1", s.hash, backend})
	return secure.Hash(raw)
}

func netplanLinkReason(s *netplanSnapshot, view hostdns.NetworkLink, sources []networkSource) string {
	if s.problem != "" {
		return s.problem
	}
	if len(sources) != 1 || sources[0].Masked || !slices.Equal(view.LoadedSources, []string{sources[0].Path}) || !slices.Equal(view.DiskSources, view.LoadedSources) || !networkExclusive(sources, view.Interface) {
		return "netplan 目标须为单一、按网卡名称独占的生成文件，无额外 drop-in"
	}
	info := s.source("networkd", sources[0].Path)
	if info == nil || info.State != "associated" || info.Definition != view.Interface || info.DeviceType != "ethernets" || info.Settings == nil {
		return "当前仅支持与所选网卡同名、DNS 字段完整的 netplan Ethernet 定义"
	}
	settings := info.Settings
	for _, flag := range []*bool{settings.DHCP4, settings.DHCP6, settings.AcceptRA} {
		if flag == nil || *flag {
			return "netplan 目标须明确关闭 DHCPv4、DHCPv6 和 IPv6 RA，自动来源保持只读"
		}
	}
	if view.State != "configured" || view.Persistent == nil || view.Loaded == nil || view.Effective == nil {
		return "netplan 链路及运行 DNS 状态未完整确认"
	}
	config := networkConfig(view.Persistent)
	if config.Validate(view.Target) != nil {
		return "netplan 当前静态 DNS 超出可写范围"
	}
	expected := networkConfigState(config, view.Persistent.RoutingDomains)
	if !networkSame(&expected, view.Loaded) || !networkSame(view.Loaded, view.Effective) {
		return "netplan 生成文件、networkd 与 resolved DNS 不一致"
	}
	for _, server := range view.Loaded.Servers {
		if server.Source != "static" && server.Source != "runtime" {
			return "netplan 目标仍存在自动获取的运行 DNS"
		}
	}
	for _, domain := range view.Loaded.Domains {
		if domain.Source != "static" && domain.Source != "runtime" {
			return "netplan 目标仍存在自动获取的运行域名"
		}
	}
	if _, _, err := netplanEditedSource(s, view.Interface, config, view.Persistent.RoutingDomains); err != nil {
		return err.Error()
	}
	if _, err := s.generator(); err != nil {
		return err.Error()
	}
	return ""
}

func (s *netplanSnapshot) generator() (netplanTool, error) {
	if !s.toolRead {
		s.tool, s.toolError = readNetplanTool()
		s.toolRead = true
	}
	return s.tool, s.toolError
}

func (d *HostDNS) netplanPrepare(input hostdns.PlanInput) (netplanProposal, error) {
	var out netplanProposal
	if d.Owner != "netplan" || d.hostScopeReason() != "" {
		return out, fault.Unavailable("须由本机确认 netplan 所有者及宿主机范围")
	}
	if d.problem != "" || d.checkpoint != nil && dnsActive(d.checkpoint.Status.State) {
		return out, fault.Conflict("存在待处理的 DNS 恢复记录")
	}
	if reason := networkdResolverReason(); reason != "" {
		return out, fault.Unavailable(reason)
	}
	s := readNetplanSources()
	if s.problem != "" {
		return out, fault.Unavailable(s.problem)
	}
	b, r, err := openNetworkd(context.Background())
	if err != nil {
		return out, fault.Unavailable("无法连接宿主机 networkd/resolved")
	}
	defer b.close()
	defer r.close()
	if err = networkdSupported(b); err != nil {
		return out, fault.Unavailable("缺少已确认的 networkd DNS 局部接口")
	}
	t, err := findNetworkd(b, r, input.Target)
	if err != nil {
		return out, fault.Unavailable("无法完整读取 netplan 目标链路")
	}
	if reason := netplanLinkReason(s, t.View, t.Sources); reason != "" {
		return out, fault.Unavailable(reason)
	}
	if input.SourceHash != netplanViewHash(s, t.View.SourceHash) {
		return out, fault.Conflict("netplan 源或运行状态已变化，请刷新")
	}
	for _, name := range input.Config.Search {
		for _, route := range t.View.Persistent.RoutingDomains {
			if strings.EqualFold(name, strings.TrimSuffix(strings.TrimPrefix(route, "~"), ".")) {
				return out, fault.Invalid("搜索域与保留路由域冲突")
			}
		}
	}
	wanted := networkConfigState(input.Config, t.View.Persistent.RoutingDomains)
	if networkSame(&wanted, t.View.Loaded) {
		return out, fault.Invalid("DNS 设置与当前状态相同，无需应用")
	}
	source, after, err := netplanEditedSource(s, t.Ref.Name, input.Config, t.View.Persistent.RoutingDomains)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	tool, err := s.generator()
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	// Native generation must not consume the lifetime of the D-Bus session.
	b.close()
	r.close()
	call, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	generated, err := d.netplanNativeCandidate(call, s, tool, source, after, t.Sources[0], input.Config, t.View.Persistent.RoutingDomains)
	if err != nil {
		return out, fault.Unavailable(err.Error())
	}
	b2, r2, err := openNetworkd(context.Background())
	if err != nil {
		return out, fault.Unavailable("原生生成后无法复核运行状态")
	}
	defer b2.close()
	defer r2.close()
	fresh, err := findNetworkd(b2, r2, input.Target)
	if err != nil || input.SourceHash != netplanViewHash(s, fresh.View.SourceHash) || !s.stable() {
		return out, fault.Conflict("netplan 生成期间源或运行状态变化")
	}
	proofs := make([]netplanSourceProof, 0, len(s.files))
	for _, file := range s.files {
		proofs = append(proofs, netplanSourceProof{file.Path, file.File.hash()})
	}
	now := time.Now().Unix()
	plan := hostdns.Plan{Owner: "netplan", Input: input, Before: networkConfig(t.View.Persistent), CreatedAt: now, ExpiresAt: now + 300, Impact: "仅临时调整所选静态网卡的 DNS，保留路由域、IP、网关及其他接口。确认后保存原 netplan 源的 DNS 字段及对应生成文件，不重载网络；未确认将独立恢复。"}
	plan.ID = plan.Hash()
	out = netplanProposal{Plan: plan, Netplan: netplanCheckpoint{File: source.Path, Before: source.File, After: after, Sources: proofs, Tool: tool}, Target: fresh, Generated: generated}
	return out, nil
}

func (d *HostDNS) netplanPlan(input hostdns.PlanInput) (hostdns.Plan, error) {
	p, err := d.netplanPrepare(input)
	return p.Plan, err
}

func (d *HostDNS) netplanApply(id string, plan hostdns.Plan) (hostdns.Status, error) {
	p, err := d.netplanPrepare(plan.Input)
	if err != nil {
		return hostdns.Status{}, err
	}
	if !reflect.DeepEqual(p.Plan.Before, plan.Before) || plan.Owner != "netplan" {
		return hostdns.Status{}, fault.Conflict("netplan 计划与源状态不一致")
	}
	b, r, err := openNetworkd(context.Background())
	if err != nil {
		return hostdns.Status{}, err
	}
	defer b.close()
	defer r.close()
	t, err := findNetworkd(b, r, plan.Input.Target)
	if err != nil || t.View.SourceHash != p.Target.View.SourceHash {
		return hostdns.Status{}, fault.Conflict("netplan 执行前运行状态变化")
	}
	before, err := networkCanonical(t.View.Loaded)
	if err != nil {
		return hostdns.Status{}, err
	}
	afterState := networkConfigState(plan.Input.Config, t.View.Persistent.RoutingDomains)
	after, err := networkCanonical(&afterState)
	if err != nil {
		return hostdns.Status{}, err
	}
	peer, err := b.networkdProcess()
	if err != nil {
		return hostdns.Status{}, err
	}
	now := time.Now().Unix()
	if now >= plan.ExpiresAt {
		return hostdns.Status{}, fault.Conflict("DNS 计划已过期")
	}
	n := &networkdCheckpoint{Boot: peer.Boot, Base: t.Sources[0].Path, File: t.Sources[0].Path, Index: t.Ref.Index, OtherHash: networkOtherHash(t.Sources, t.Sources[0].Path), Before: before, After: after, Routes: append([]string{}, t.View.Persistent.RoutingDomains...)}
	d.checkpoint = &dnsCheckpoint{Kind: "host.dns.apply", Plan: plan, Before: t.Sources[0].File, After: p.Generated, Networkd: n, Netplan: &p.Netplan, VerifyAfter: now + 6, Status: hostdns.Status{OperationID: id, PlanID: plan.ID, State: "running", Stage: "applying", Deadline: now + plan.Input.TimeoutSeconds}}
	d.expiry = time.Now().Add(time.Duration(plan.Input.TimeoutSeconds) * time.Second)
	if err = d.persist(); err != nil {
		return d.checkpoint.Status, err
	}
	if _, err = d.netplanSourcesCheck(false); err == nil {
		err = d.networkdWrite(b, t.Ref.Index, "SetLinkDNSEx", n.After)
	}
	if err == nil {
		b.close()
		r.close()
		b, r, t, err = d.networkdSession(context.Background())
		if err == nil {
			defer b.close()
			defer r.close()
			err = d.networkdLoaded(t, true, false)
		}
		if err == nil {
			err = d.networkdWrite(b, t.Ref.Index, "SetLinkDomains", n.After)
		}
	}
	if err != nil {
		err = d.rollback("netplan DNS 临时应用未确认，恢复原设置")
		return d.checkpoint.Status, err
	}
	d.checkpoint.Status.State, d.checkpoint.Status.Stage = "waiting_confirmation", "verification_pending"
	return d.checkpoint.Status, d.persist()
}

func (d *HostDNS) netplanSourcesCheck(persistent bool) (*netplanSnapshot, error) {
	c, n := d.checkpoint, d.checkpoint.Netplan
	if n == nil {
		return nil, errors.New("missing netplan checkpoint")
	}
	s := readNetplanSources()
	if s.problem != "" || len(s.files) != len(n.Sources) {
		return nil, errors.New("netplan source inventory changed")
	}
	for i, file := range s.files {
		if file.Path != n.Sources[i].Path {
			return nil, errors.New("netplan source precedence changed")
		}
		if file.Path == n.File {
			want := n.Before
			if persistent {
				want = n.After
			}
			if !sameDNSFile(file.File, want) {
				return nil, errors.New("netplan DNS source differs from approved state")
			}
		} else if file.File.hash() != n.Sources[i].Hash {
			return nil, errors.New("unrelated netplan source changed")
		}
	}
	if c.Plan.Owner != "netplan" {
		return nil, errors.New("netplan checkpoint owner mismatch")
	}
	return s, nil
}

func (d *HostDNS) netplanSourceEither() error {
	if d.checkpoint.Netplan == nil {
		return nil
	}
	if _, err := d.netplanSourcesCheck(false); err == nil {
		return nil
	}
	_, err := d.netplanSourcesCheck(true)
	return err
}

func netplanSnapshotPath(path string) bool {
	return filepath.Clean(path) == path && strings.HasSuffix(path, ".yaml") && (filepath.Dir(path) == "/etc/netplan" || filepath.Dir(path) == "/run/netplan" || filepath.Dir(path) == "/usr/lib/netplan" || filepath.Dir(path) == "/lib/netplan")
}
