package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

func networkWritableSource(name string) bool {
	root := "/etc/systemd/network"
	if filepath.Dir(name) == root {
		return networkSourcePath(name, filepath.Base(name), false)
	}
	parent := filepath.Dir(name)
	base := strings.TrimSuffix(filepath.Base(parent), ".d")
	return filepath.Dir(parent) == root && strings.HasSuffix(base, ".network") && networkSourcePath(name, base, true)
}

// Only these observed runtime files may belong to the resolved service user.
// Persistent sources and every file accepted by a writer remain root-owned.
func readObservedDNSFile(path string) (dnsFile, error) {
	if path != "/run/systemd/resolve/stub-resolv.conf" && path != "/run/systemd/resolve/resolv.conf" {
		return readDNSFile(path)
	}
	b, err := openDNSService(context.Background(), resolvedName)
	if err != nil {
		return dnsFile{}, err
	}
	defer b.close()
	var owner uint32
	if err = b.conn.BusObject().CallWithContext(b.ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, b.owner).Store(&owner); err != nil {
		return dnsFile{}, err
	}
	file, err := readProtectedTextFileForOwner(path, hostdns.SourceLimit, owner)
	if err != nil {
		return dnsFile{}, err
	}
	if err = b.unchangedOwner(); err != nil {
		return dnsFile{}, err
	}
	return file, nil
}

func networkdResolverReason() string {
	info, e := os.Lstat(dnsSource)
	if e != nil || info.Mode()&os.ModeSymlink == 0 {
		return "解析器入口尚未确认为 resolved 的标准链接"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return "解析器入口链接归属不安全"
	}
	link, e := os.Readlink(dnsSource)
	if e != nil {
		return "无法读取解析器入口链接"
	}
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(dnsSource), link)
	}
	link = filepath.Clean(link)
	if link != "/run/systemd/resolve/stub-resolv.conf" && link != "/run/systemd/resolve/resolv.conf" {
		return "解析器入口未关联 resolved，当前保持只读"
	}
	if _, e = readObservedDNSFile(link); e != nil {
		return "无法安全读取 resolved 解析器入口"
	}
	return ""
}

// DNS-only calls do not reload links or touch DHCP addresses and routes.
func networkdSupported(b *dnsBus) error {
	var raw string
	if e := b.call(networkdRoot, "org.freedesktop.DBus.Introspectable.Introspect").Store(&raw); e != nil {
		return e
	}
	if len(raw) > 256<<10 {
		return errors.New("networkd introspection exceeds budget")
	}
	var node struct {
		Interfaces []struct {
			Name    string `xml:"name,attr"`
			Methods []struct {
				Name string `xml:"name,attr"`
				Args []struct {
					Type      string `xml:"type,attr"`
					Direction string `xml:"direction,attr"`
				} `xml:"arg"`
			} `xml:"method"`
		} `xml:"interface"`
	}
	if xml.Unmarshal([]byte(raw), &node) != nil {
		return errors.New("invalid networkd introspection")
	}
	want := map[string]string{"SetLinkDNSEx": "ia(iayqs)", "SetLinkDomains": "ia(sb)"}
	seen := map[string]bool{}
	for _, iface := range node.Interfaces {
		if iface.Name != networkdName+".Manager" {
			continue
		}
		for _, method := range iface.Methods {
			if signature, ok := want[method.Name]; ok {
				in, out := "", ""
				for _, a := range method.Args {
					if a.Direction == "out" {
						out += a.Type
					} else if a.Direction == "" || a.Direction == "in" {
						in += a.Type
					} else {
						return errors.New("invalid networkd method direction")
					}
				}
				if seen[method.Name] || in != signature || out != "" {
					return errors.New("unsupported networkd DNS method")
				}
				seen[method.Name] = true
			}
		}
	}
	if len(seen) != len(want) {
		return errors.New("networkd lacks DNS-only methods")
	}
	return b.unchangedOwner()
}

func networkCanonical(state *hostdns.LinkDNS) (hostdns.LinkDNS, error) {
	out := hostdns.LinkDNS{Servers: []hostdns.DNSServer{}, Domains: []hostdns.DNSDomain{}}
	if state == nil || len(state.Servers) > 64 || len(state.Domains) > 128 {
		return out, errors.New("incomplete network DNS state")
	}
	for _, s := range state.Servers {
		ip, e := netip.ParseAddr(s.Address)
		if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || s.ServerName != "" || s.Port != 0 && s.Port != 53 {
			return out, errors.New("unsupported static network DNS server")
		}
		out.Servers = append(out.Servers, hostdns.DNSServer{Address: ip.String()})
	}
	for _, d := range state.Domains {
		name := strings.ToLower(strings.TrimSuffix(d.Domain, "."))
		if d.Routing && d.Domain == "." {
			name = "."
		}
		if name != "." && !hostdns.Hostname(name) || name == "." && !d.Routing {
			return out, errors.New("unsupported network DNS domain")
		}
		out.Domains = append(out.Domains, hostdns.DNSDomain{Domain: name, Routing: d.Routing})
	}
	// Search order affects short-name resolution; only routing-domain order is
	// semantically irrelevant when comparing networkd and resolved snapshots.
	sort.SliceStable(out.Domains, func(i, j int) bool {
		a, b := out.Domains[i], out.Domains[j]
		if a.Routing != b.Routing {
			return !a.Routing
		}
		return a.Routing && a.Domain < b.Domain
	})
	return out, nil
}
func networkConfigState(config hostdns.Config, routes []string) hostdns.LinkDNS {
	out := hostdns.LinkDNS{Servers: []hostdns.DNSServer{}, Domains: []hostdns.DNSDomain{}}
	for _, s := range config.Servers {
		out.Servers = append(out.Servers, hostdns.DNSServer{Address: s})
	}
	for _, d := range config.Search {
		out.Domains = append(out.Domains, hostdns.DNSDomain{Domain: d})
	}
	for _, d := range routes {
		out.Domains = append(out.Domains, hostdns.DNSDomain{Domain: strings.TrimPrefix(d, "~"), Routing: true})
	}
	return out
}
func networkSame(a, b *hostdns.LinkDNS) bool {
	x, e := networkCanonical(a)
	if e != nil {
		return false
	}
	y, e := networkCanonical(b)
	return e == nil && reflect.DeepEqual(x, y)
}
func networkConfig(p *hostdns.NetworkDNS) hostdns.Config {
	return hostdns.Config{Servers: append([]string{}, p.Servers...), Search: append([]string{}, p.Search...)}
}

// A .network can match many links, including links created later. Only an exact
// single Name match permits this source to be changed for one target.
func networkExclusive(sources []networkSource, iface string) bool {
	names := []string{}
	for _, source := range sources {
		if source.Masked {
			continue
		}
		section, pending := "", ""
		for _, physical := range strings.Split(string(source.File.Data), "\n") {
			line := strings.TrimSpace(physical)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			line, pending = pending+line, ""
			if strings.HasSuffix(line, "\\") {
				pending = strings.TrimSuffix(line, "\\") + " "
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(line[1 : len(line)-1])
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if section == "Match" && ok && strings.TrimSpace(key) == "Name" {
				words, e := networkDNSWords(strings.TrimSpace(value))
				if e != nil {
					return false
				}
				if len(words) == 0 {
					names = []string{}
				} else {
					names = append(names, words...)
				}
			}
		}
		if pending != "" {
			return false
		}
	}
	return len(names) == 1 && names[0] == iface
}

func networkWriteReason(view hostdns.NetworkLink, sources []networkSource) string {
	if view.State != "configured" || view.Owner != "networkd" || view.Persistent == nil || view.Loaded == nil || view.Effective == nil {
		return "链路、持久源或 resolved 状态未完整确认"
	}
	if len(sources) == 0 || !networkWritableSource(sources[len(sources)-1].Path) || sources[len(sources)-1].Masked {
		return "最后生效的配置源不属于可写的本机 /etc networkd 配置"
	}
	paths := []string{}
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	if !slices.Equal(paths, view.LoadedSources) {
		return "磁盘源与 networkd 加载源不一致，须先核对外部配置"
	}
	if !networkExclusive(sources, view.Interface) {
		return "持久配置未按唯一网卡名称匹配，不能局部修改共享配置"
	}
	p := view.Persistent
	for _, v := range []*bool{p.DHCP4, p.DHCP6, p.IPv6RA} {
		if v == nil || *v {
			return "自动 DNS 策略尚未全部明确关闭，当前仅支持纯静态链路"
		}
	}
	// Unset UseDNR inherits UseDNS. An explicit encrypted resolver policy must
	// not be silently replaced by a static DNS runtime override.
	for _, v := range []*bool{p.DNR4, p.DNR6, p.DNRRA} {
		if v != nil && *v {
			return "仍允许自动获取加密 DNS，当前保持只读"
		}
	}
	for _, v := range []*string{p.Domains4, p.Domains6, p.DomainsRA} {
		if v == nil || *v != "no" {
			return "自动搜索域或路由域策略未明确关闭，保持只读"
		}
	}
	if len(p.Servers) < 1 || len(p.Servers) > 3 || len(p.Search) > 6 || len(strings.Join(p.Search, " ")) > 253 {
		return "静态 DNS 或搜索域超出可写范围"
	}
	expected := networkConfigState(networkConfig(p), p.RoutingDomains)
	if !networkSame(&expected, view.Loaded) || !networkSame(view.Loaded, view.Effective) {
		return "持久、networkd 运行与 resolved DNS 不一致，须先核对外部修改"
	}
	for _, server := range view.Loaded.Servers {
		if server.Source != "static" && server.Source != "runtime" {
			return "仍存在自动获取的运行 DNS，保持只读"
		}
	}
	for _, domain := range view.Loaded.Domains {
		if domain.Source != "static" && domain.Source != "runtime" {
			return "仍存在自动获取的运行域名，保持只读"
		}
	}
	return ""
}

func networkOtherHash(sources []networkSource, edited string) string {
	other := []networkSource{}
	for _, source := range sources {
		if source.Path != edited {
			other = append(other, source)
		}
	}
	raw, _ := json.Marshal(other)
	return secure.Hash(raw)
}

func networkViewHash(sources []networkSource, b *dnsBus, view hostdns.NetworkLink) string {
	raw, _ := json.Marshal([]any{networkSourceHash(sources, b, view.Index, view.Interface), view.Loaded, view.Effective})
	return secure.Hash(raw)
}

var networkManagedSuffix = regexp.MustCompile(`\n# NginxPanel DNS override\n\[Network\]\nDNS=\nDNS=[^\n]*\nDomains=\nDomains=[^\n]*\n$`)

func renderNetworkDNS(before []byte, config hostdns.Config, routes []string) ([]byte, error) {
	// Replace only our DNS-only suffix. All original source, comments and
	// unrelated keys remain byte-identical; repeated changes do not grow it.
	prefix := networkManagedSuffix.ReplaceAll(before, nil)
	var out bytes.Buffer
	out.Write(prefix)
	if out.Len() > 0 && prefix[len(prefix)-1] != '\n' {
		out.WriteByte('\n')
	}
	out.WriteString("\n# NginxPanel DNS override\n[Network]\nDNS=\nDNS=" + strings.Join(config.Servers, " ") + "\nDomains=\nDomains=" + strings.Join(append(append([]string{}, config.Search...), routes...), " ") + "\n")
	if out.Len() > hostdns.SourceLimit {
		return nil, errors.New("network DNS candidate exceeds budget")
	}
	return out.Bytes(), nil
}

type networkdTarget struct {
	Ref     networkdLinkRef
	View    hostdns.NetworkLink
	Sources []networkSource
}

func findNetworkd(b, r *dnsBus, target string) (*networkdTarget, error) {
	if !hostdns.NetworkdTarget(target) || r == nil {
		return nil, errors.New("invalid networkd target")
	}
	var refs []networkdLinkRef
	if e := b.call(networkdRoot, networkdName+".Manager.ListLinks").Store(&refs); e != nil || len(refs) > 32 {
		return nil, errors.New("networkd inventory unavailable")
	}
	name := strings.TrimPrefix(target, "networkd:")
	for _, ref := range refs {
		if ref.Name != name {
			continue
		}
		if ref.Index <= 0 || !strings.HasPrefix(string(ref.Path), "/org/freedesktop/network1/link/") {
			return nil, errors.New("invalid networkd link identity")
		}
		view := networkdObserveLink(b, r, ref)
		if len(view.DiskSources) == 0 {
			return nil, errors.New("networkd source unavailable")
		}
		sources, e := networkSources(view.DiskSources[0])
		if e != nil {
			return nil, e
		}
		if view.SourceHash != networkViewHash(sources, b, view) {
			return nil, errors.New("networkd source changed while reading")
		}
		if e = b.unchangedOwner(); e != nil {
			return nil, e
		}
		return &networkdTarget{ref, view, sources}, nil
	}
	return nil, errors.New("networkd target is missing")
}

func networkDNSWire(state hostdns.LinkDNS) []resolvedDNSRecord {
	out := []resolvedDNSRecord{}
	for _, server := range state.Servers {
		ip, _ := netip.ParseAddr(server.Address)
		family := int32(10)
		if ip.Is4() {
			family = 2
		}
		out = append(out, resolvedDNSRecord{Family: family, Address: ip.AsSlice()})
	}
	return out
}
func networkDomainsWire(state hostdns.LinkDNS) []resolvedDomain {
	out := []resolvedDomain{}
	for _, d := range state.Domains {
		out = append(out, resolvedDomain{Name: d.Domain, Routing: d.Routing})
	}
	return out
}

func knownNetworkdRejection(e error) bool {
	var busError dbus.Error
	if !errors.As(e, &busError) {
		return false
	}
	return slices.Contains([]string{"org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.InvalidArgs", "org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner"}, busError.Name)
}
