package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/hostdns"
)

const networkdName = "org.freedesktop.network1"
const resolvedName = "org.freedesktop.resolve1"
const networkdRoot = dbus.ObjectPath("/org/freedesktop/network1")
const resolvedRoot = dbus.ObjectPath("/org/freedesktop/resolve1")

type networkdLinkRef struct {
	Index int32
	Name  string
	Path  dbus.ObjectPath
}
type networkdDNSRecord struct {
	Family        int
	Address       []int
	AddressString string
	Port          uint16
	ServerName    string
	ConfigSource  string
}
type networkdDomain struct {
	Domain       string
	ConfigSource string
}
type networkdDescription struct {
	Index               int32
	Name                string
	AdministrativeState string
	NetworkFile         string
	NetworkFileDropins  []string
	DNS                 []networkdDNSRecord
	SearchDomains       []networkdDomain
	RouteDomains        []networkdDomain
}
type resolvedDNSRecord struct {
	Family     int32
	Address    []byte
	Port       uint16
	ServerName string
}
type resolvedDomain struct {
	Name    string
	Routing bool
}

func dnsAddress(family int, data []byte) (string, error) {
	ip, ok := netip.AddrFromSlice(data)
	if !ok || family == 2 && !ip.Is4() || family == 10 && (!ip.Is6() || ip.Is4In6()) || family != 2 && family != 10 {
		return "", errors.New("invalid DNS address family")
	}
	return ip.String(), nil
}
func networkdLoaded(r networkdDescription) (*hostdns.LinkDNS, error) {
	out := &hostdns.LinkDNS{Servers: []hostdns.DNSServer{}, Domains: []hostdns.DNSDomain{}}
	if len(r.DNS) > 64 || len(r.SearchDomains)+len(r.RouteDomains) > 128 {
		return nil, errors.New("networkd DNS state exceeds budget")
	}
	for _, s := range r.DNS {
		if len(s.Address) > 16 {
			return nil, errors.New("invalid networkd DNS address")
		}
		raw := []byte{}
		for _, v := range s.Address {
			if v < 0 || v > 255 {
				return nil, errors.New("invalid networkd address byte")
			}
			raw = append(raw, byte(v))
		}
		address, e := dnsAddress(s.Family, raw)
		if e != nil {
			return nil, e
		}
		if s.AddressString != "" && s.AddressString != address {
			return nil, errors.New("networkd address representations differ")
		}
		if len(s.ConfigSource) > 32 || len(s.ServerName) > 253 {
			return nil, errors.New("networkd DNS metadata exceeds budget")
		}
		out.Servers = append(out.Servers, hostdns.DNSServer{Address: address, Source: s.ConfigSource, Port: s.Port, ServerName: s.ServerName})
	}
	for i, domains := range [][]networkdDomain{r.SearchDomains, r.RouteDomains} {
		for _, d := range domains {
			if len(d.Domain) > 253 || len(d.ConfigSource) > 32 {
				return nil, errors.New("networkd domain metadata exceeds budget")
			}
			out.Domains = append(out.Domains, hostdns.DNSDomain{Domain: d.Domain, Source: d.ConfigSource, Routing: i == 1})
		}
	}
	return out, nil
}
func resolvedLinkDNS(b *dnsBus, index int32) (*hostdns.LinkDNS, error) {
	var path dbus.ObjectPath
	if e := b.call(resolvedRoot, resolvedName+".Manager.GetLink", index).Store(&path); e != nil {
		return nil, e
	}
	if !strings.HasPrefix(string(path), "/org/freedesktop/resolve1/link/") {
		return nil, errors.New("invalid resolved link identity")
	}
	servers, e := dnsProperty[[]resolvedDNSRecord](b, path, resolvedName+".Link", "DNSEx")
	if e != nil {
		return nil, e
	}
	domains, e := dnsProperty[[]resolvedDomain](b, path, resolvedName+".Link", "Domains")
	if e != nil {
		return nil, e
	}
	if len(servers) > 64 || len(domains) > 128 {
		return nil, errors.New("resolved DNS state exceeds budget")
	}
	out := &hostdns.LinkDNS{Servers: []hostdns.DNSServer{}, Domains: []hostdns.DNSDomain{}}
	for _, s := range servers {
		address, e := dnsAddress(int(s.Family), s.Address)
		if e != nil || len(s.ServerName) > 253 {
			return nil, errors.New("resolved DNS metadata is invalid")
		}
		out.Servers = append(out.Servers, hostdns.DNSServer{Address: address, Source: "resolved", Port: s.Port, ServerName: s.ServerName})
	}
	for _, d := range domains {
		if len(d.Name) > 253 {
			return nil, errors.New("resolved domain exceeds budget")
		}
		out.Domains = append(out.Domains, hostdns.DNSDomain{Domain: d.Name, Source: "resolved", Routing: d.Routing})
	}
	return out, b.unchangedOwner()
}
func networkdObserveLink(b, resolved *dnsBus, ref networkdLinkRef) hostdns.NetworkLink {
	out := hostdns.NetworkLink{Target: "networkd:" + ref.Name, Interface: ref.Name, Index: ref.Index, Owner: "unknown", LoadedSources: []string{}, DiskSources: []string{}, Reason: "未确认安全的局部应用与独立恢复能力，当前为只读"}
	var raw string
	if e := b.call(ref.Path, networkdName+".Link.Describe").Store(&raw); e != nil {
		out.Reason = "缺少 networkd 连接描述接口，无法追溯持久源"
		return out
	}
	if len(raw) > 256<<10 {
		out.Reason = "networkd 连接描述超过读取上限"
		return out
	}
	var r networkdDescription
	if e := json.Unmarshal([]byte(raw), &r); e != nil || r.Index != ref.Index || r.Name != ref.Name || len(r.AdministrativeState) > 32 {
		out.Reason = "networkd 连接身份或描述无效"
		return out
	}
	out.State = r.AdministrativeState
	var e error
	out.Loaded, e = networkdLoaded(r)
	if e != nil {
		out.Reason = "无法完整读取 networkd 已加载 DNS 状态"
	}
	if resolved != nil {
		out.Effective, _ = resolvedLinkDNS(resolved, ref.Index)
	}
	if r.NetworkFile == "" {
		out.Reason = "网卡尚未关联 networkd 持久配置"
		return out
	}
	if len(r.NetworkFile) > 512 || len(r.NetworkFileDropins) > 32 {
		out.Reason = "networkd 源引用超过读取上限"
		return out
	}
	base := filepath.Base(r.NetworkFile)
	if !networkSourcePath(r.NetworkFile, base, false) {
		out.Reason = "networkd 加载源不在受支持配置目录"
		return out
	}
	out.LoadedSources = append(out.LoadedSources, r.NetworkFile)
	for _, p := range r.NetworkFileDropins {
		if !networkSourcePath(p, base, true) {
			out.Reason = "networkd drop-in 引用不在受支持配置目录"
			return out
		}
		out.LoadedSources = append(out.LoadedSources, p)
	}
	sources, e := networkSources(r.NetworkFile)
	if e != nil {
		out.Reason = "源文件已变化、被屏蔽、权限不安全或无法完整读取"
		return out
	}
	for _, source := range sources {
		out.DiskSources = append(out.DiskSources, source.Path)
	}
	out.SourceHash = networkViewHash(sources, b, out)
	switch filepath.Dir(sources[0].Path) {
	case "/etc/systemd/network":
		out.Owner = "networkd"
	case "/usr/lib/systemd/network", "/usr/local/lib/systemd/network":
		out.Owner = "vendor"
	case "/run/systemd/network":
		out.Owner = "generated"
		out.Reason = "持久源来自运行时生成目录，需追溯 netplan、cloud-init 等上游所有者"
	}
	out.Persistent, e = networkDNSProjection(sources)
	if e != nil {
		out.Persistent = nil
		out.Reason = "磁盘源包含尚未完整识别的 DNS 语法或继承规则，配置值保持未知"
		return out
	}
	if out.Owner != "generated" {
		out.Reason = networkWriteReason(out, sources)
		out.Writable = out.Reason == ""
	}
	return out
}
func (d *HostDNS) observeNetworkd(netplan *netplanSnapshot) hostdns.Observation {
	out := hostdns.Observation{Owner: "networkd", Source: dnsSource, Current: hostdns.Config{Servers: []string{}, Search: []string{}}, Links: []hostdns.NetworkLink{}, Reason: "未发现符合条件的静态 networkd 链路"}
	if d.Owner == "netplan" {
		out.Owner, out.Reason = "netplan", "未发现可安全局部管理的静态 netplan 链路"
	}
	path := dnsSource
	if link, e := os.Readlink(dnsSource); e == nil {
		out.LinkTarget = link
		path = link
		if !filepath.IsAbs(path) {
			path = filepath.Join("/etc", path)
		}
		path = filepath.Clean(path)
		if path != "/run/systemd/resolve/stub-resolv.conf" && path != "/run/systemd/resolve/resolv.conf" && path != "/run/NetworkManager/resolv.conf" {
			path = ""
		}
	}
	if path != "" {
		if file, e := readDNSFile(path); e == nil {
			out.Current = parseDNS(file.Data)
		}
	}
	if reason := d.hostScopeReason(); reason != "" {
		out.Reason = reason
		return d.withPending(out)
	}
	b, e := openDNSService(context.Background(), networkdName)
	if e != nil {
		out.Reason = "无法连接宿主机 networkd"
		return d.withPending(out)
	}
	defer b.close()
	supported := networkdSupported(b) == nil
	resolverReason := networkdResolverReason()
	resolved, _ := openDNSService(context.Background(), resolvedName)
	if resolved != nil {
		defer resolved.close()
	}
	var refs []networkdLinkRef
	if e = b.call(networkdRoot, networkdName+".Manager.ListLinks").Store(&refs); e != nil || len(refs) > 32 {
		out.Reason = "无法在读取预算内取得完整 networkd 网卡清单"
		return d.withPending(out)
	}
	observationBytes := 0
	for _, ref := range refs {
		if ref.Index <= 0 || len(ref.Name) == 0 || len(ref.Name) > 15 || strings.Trim(ref.Name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") != "" || !strings.HasPrefix(string(ref.Path), "/org/freedesktop/network1/link/") {
			out.Reason = "networkd 网卡身份无效"
			out.Links = []hostdns.NetworkLink{}
			return d.withPending(out)
		}
		link := networkdObserveLink(b, resolved, ref)
		if d.Owner == "netplan" {
			link.Writable = false
			link.Reason = "持久源未确认为可管理的 netplan 定义"
		}
		if len(link.LoadedSources) > 0 {
			if _, candidate := netplanGeneratedID("networkd", link.LoadedSources[0]); candidate {
				if netplan == nil {
					netplan = readNetplanSources()
				}
				link.Netplan = netplan.source("networkd", link.LoadedSources[0])
			}
			if link.Netplan != nil {
				link.Writable = false
				if d.Owner == "netplan" {
					sources, sourceErr := networkSources(link.LoadedSources[0])
					if sourceErr != nil {
						link.Reason = "无法复核 netplan 生成源"
					} else {
						link.Reason = netplanLinkReason(netplan, link, sources)
						link.Writable = link.Reason == ""
						if link.Writable {
							link.SourceHash = netplanViewHash(netplan, link.SourceHash)
							link.Netplan.Reason = ""
						}
					}
				}
			}
		}
		if !supported {
			link.Writable = false
			link.Reason = "networkd 缺少已确认的 DNS 局部写入接口"
		}
		if resolverReason != "" {
			link.Writable = false
			link.Reason = resolverReason
		}
		out.Writable = out.Writable || link.Writable
		encoded, err := json.Marshal(link)
		if err != nil {
			out.Reason = "networkd DNS 观测无法编码"
			out.Links = []hostdns.NetworkLink{}
			return d.withPending(out)
		}
		observationBytes += len(encoded)
		if observationBytes > 2<<20 {
			out.Reason = "networkd DNS 观测结果超过读取上限"
			out.Links = []hostdns.NetworkLink{}
			return d.withPending(out)
		}
		out.Links = append(out.Links, link)
	}
	if netplan != nil && netplan.problem == "" && !netplan.stable() {
		for i := range out.Links {
			invalidateNetplanSource(out.Links[i].Netplan)
			if d.Owner == "netplan" && out.Links[i].Netplan != nil {
				out.Links[i].Writable = false
				out.Links[i].Reason = out.Links[i].Netplan.Reason
			}
		}
		out.Writable = false
		for _, link := range out.Links {
			out.Writable = out.Writable || link.Writable
		}
	}
	if e = b.unchangedOwner(); e != nil {
		out.Reason = "networkd 状态读取未确认，请刷新"
		out.Links = []hostdns.NetworkLink{}
		out.Writable = false
	}
	if out.Writable {
		out.Reason = ""
	}
	return d.withPending(out)
}
