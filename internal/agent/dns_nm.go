package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type nmTarget struct {
	View                           hostdns.Connection
	Device, Profile, Active        dbus.ObjectPath
	Applied, Persistent            nmSettings
	AppliedVersion, ProfileVersion uint64
	Filename, FileHash             string
	ResolverState                  string
}

func nmGet[T any](b *nmBus, path dbus.ObjectPath, iface, key string) (T, error) {
	var out T
	v, e := b.property(path, iface, key)
	if e != nil {
		return out, e
	}
	if e = dbus.Store([]any{v.Value()}, &out); e != nil {
		return out, e
	}
	return out, nil
}
func nmProfileHash(path string) (string, error) {
	if filepath.Dir(path) != "/etc/NetworkManager/system-connections" || !strings.HasSuffix(path, ".nmconnection") {
		return "", errors.New("profile is not a persistent NetworkManager keyfile")
	}
	infoDir, e := os.Lstat(filepath.Dir(path))
	if e != nil {
		return "", e
	}
	dirStat, ok := infoDir.Sys().(*syscall.Stat_t)
	if !ok || !infoDir.IsDir() || dirStat.Uid != 0 || infoDir.Mode().Perm()&0022 != 0 {
		return "", errors.New("unsafe keyfile directory")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return "", e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0077 != 0 || info.Size() > 256<<10 {
		return "", errors.New("unsafe NetworkManager profile")
	}
	raw, e := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	if e != nil || len(raw) > 256<<10 {
		return "", errors.New("NetworkManager profile exceeds budget")
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(info, after) || info.ModTime() != after.ModTime() || info.Size() != after.Size() {
		return "", errors.New("NetworkManager profile changed")
	}
	// Only the hash leaves this function: keyfiles can contain Wi-Fi secrets.
	return secure.Hash(raw), nil
}
func nmSupported(b *nmBus) error {
	v, e := nmGet[string](b, nmRoot, nmName, "Version")
	if e != nil {
		return e
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return errors.New("unrecognized NetworkManager version")
	}
	major, e := strconv.Atoi(parts[0])
	if e != nil {
		return e
	}
	minor, e := strconv.Atoi(parts[1])
	if e != nil {
		return e
	}
	if major < 1 || major == 1 && minor < 44 {
		return errors.New("NetworkManager 1.44 or newer is required for version-checked persistence")
	}
	return nil
}
func nmDevices(b *nmBus) ([]dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	e := b.call(nmRoot, nmName+".GetDevices").Store(&paths)
	if e == nil && len(paths) > 32 {
		e = errors.New("NetworkManager device inventory exceeds budget")
	}
	return paths, e
}
func nmReadDevice(b *nmBus, path dbus.ObjectPath) (*nmTarget, error) {
	t := &nmTarget{Device: path}
	t.View.RoutingDomains = []string{}
	t.View.Reason = "连接无法完整读取，保持只读"
	iface, e := nmGet[string](b, path, nmName+".Device", "Interface")
	if e != nil {
		return nil, e
	}
	t.View.Interface = iface
	active, e := nmGet[dbus.ObjectPath](b, path, nmName+".Device", "ActiveConnection")
	if e != nil || active == "/" {
		return nil, errors.New("device is not active")
	}
	t.Active = active
	t.Profile, e = nmGet[dbus.ObjectPath](b, active, nmName+".Connection.Active", "Connection")
	if e != nil {
		return nil, e
	}
	t.ProfileVersion, e = nmGet[uint64](b, t.Profile, nmName+".Settings.Connection", "VersionId")
	profileVersionErr := e
	if e = b.call(t.Profile, nmName+".Settings.Connection.GetSettings").Store(&t.Persistent); e != nil {
		return nil, e
	}
	uuid := nmString(t.Persistent, "connection", "uuid")
	t.View.Target = uuid + "@" + iface
	t.View.Name = nmString(t.Persistent, "connection", "id")
	if len(t.View.Name) > 256 || !hostdns.ValidTarget(t.View.Target) {
		return nil, errors.New("invalid connection identity")
	}
	if e = b.call(path, nmName+".Device.GetAppliedConnection", uint32(0)).Store(&t.Applied, &t.AppliedVersion); e != nil {
		return t, e
	}
	if nmString(t.Applied, "connection", "uuid") != uuid {
		return t, errors.New("active profile identity mismatch")
	}
	t.View.Method4 = nmString(t.Persistent, "ipv4", "method")
	t.View.Method6 = nmString(t.Persistent, "ipv6", "method")
	persistent, _, e := nmConfig(t.Persistent)
	t.View.Persistent = &persistent
	if e != nil {
		t.View.Persistent = nil
		t.View.Reason = "连接使用尚未支持的 DNS 地址或搜索属性"
		return t, e
	}
	applied, routing, e := nmConfig(t.Applied)
	t.View.Applied = &applied
	if routing != nil {
		t.View.RoutingDomains = routing
	}
	if e != nil {
		t.View.Applied = nil
		t.View.Reason = "运行中连接使用尚未支持的 DNS 属性"
		return t, e
	}
	for _, settings := range []nmSettings{t.Persistent, t.Applied} {
		snapshot, err := nmCapture(settings)
		if err != nil {
			return t, err
		}
		if !nmSame(snapshot, snapshot) {
			t.View.Reason = "连接含有尚未支持的 DNS 属性"
			return t, errors.New("unsupported DNS snapshot")
		}
	}
	if len(dbus.MakeVariant(t.Persistent).String()) > 256<<10 || len(dbus.MakeVariant(t.Applied).String()) > 256<<10 {
		return t, errors.New("connection settings exceed budget")
	}
	state, e := nmGet[uint32](b, path, nmName+".Device", "State")
	if e != nil || state != 100 {
		t.View.Reason = "连接尚未激活，不能变更 DNS"
		return t, errors.New("device is not activated")
	}
	kind, e := nmGet[uint32](b, path, nmName+".Device", "DeviceType")
	if e != nil || kind != 1 && kind != 2 {
		t.View.Reason = "当前仅支持直接连接的以太网和 Wi-Fi 设备"
		return t, errors.New("unsupported device type")
	}
	managed, e := nmGet[bool](b, path, nmName+".Device", "Managed")
	if e != nil || !managed {
		return t, errors.New("device is not managed")
	}
	unsaved, e := nmGet[bool](b, t.Profile, nmName+".Settings.Connection", "Unsaved")
	if e != nil || unsaved {
		t.View.Reason = "连接有未保存修改，须先由本机处理"
		return t, errors.New("profile is unsaved")
	}
	flags, e := nmGet[uint32](b, t.Profile, nmName+".Settings.Connection", "Flags")
	if e != nil || flags != 0 {
		t.View.Reason = "生成、临时或外部连接保持只读"
		return t, errors.New("profile is generated or external")
	}
	t.Filename, e = nmGet[string](b, t.Profile, nmName+".Settings.Connection", "Filename")
	if e != nil {
		return t, e
	}
	t.FileHash, e = nmProfileHash(t.Filename)
	if e != nil {
		t.View.Reason = "持久源不是安全的 NetworkManager keyfile；netplan、ifcfg 等源保持只读"
		return t, e
	}
	profileVersion, e := nmGet[uint64](b, t.Profile, nmName+".Settings.Connection", "VersionId")
	if e != nil || profileVersionErr != nil || t.ProfileVersion == 0 || profileVersion != t.ProfileVersion || t.AppliedVersion == 0 {
		t.View.Reason = "缺少连接版本检查接口"
		return t, errors.New("connection versions unavailable")
	}
	if nmString(t.Persistent, "connection", "master") != "" || nmString(t.Persistent, "connection", "controller") != "" {
		t.View.Reason = "控制器从属连接保持只读"
		return t, errors.New("controller port not supported")
	}
	if t.View.Persistent.IPv4 == nil && t.View.Persistent.IPv6 == nil {
		return t, errors.New("no supported IP family")
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if nmString(t.Persistent, family, "method") != nmString(t.Applied, family, "method") {
			t.View.Reason = "持久与运行中的 IP 方法不同，须先由本机处理"
			return t, errors.New("IP methods differ")
		}
	}
	t.ResolverState, e = nmResolverOwner(b)
	if e != nil {
		t.View.Reason = "NetworkManager 未管理可确认的主机解析器入口"
		return t, e
	}
	t.View.Effective, _ = nmEffective(b, t)
	activeNow, e := nmGet[dbus.ObjectPath](b, path, nmName+".Device", "ActiveConnection")
	if e != nil || activeNow != t.Active {
		return t, errors.New("active connection changed")
	}
	profileNow, e := nmGet[uint64](b, t.Profile, nmName+".Settings.Connection", "VersionId")
	if e != nil || profileNow != t.ProfileVersion {
		return t, errors.New("persistent connection changed")
	}
	t.View.SourceHash = t.hash(b)
	t.View.Writable = true
	t.View.Reason = ""
	return t, nil
}
func (t *nmTarget) hash(b *nmBus) string {
	raw, _ := json.Marshal([]any{b.busID, b.owner, t.View.Target, t.Device, t.Profile, t.Filename, t.FileHash, t.ResolverState, t.AppliedVersion, t.ProfileVersion, dbus.MakeVariant(t.Persistent).String(), dbus.MakeVariant(t.Applied).String()})
	return secure.Hash(raw)
}
func nmFind(b *nmBus, target string) (*nmTarget, error) {
	if !hostdns.ValidTarget(target) {
		return nil, errors.New("invalid connection target")
	}
	parts := strings.SplitN(target, "@", 2)
	paths, e := nmDevices(b)
	if e != nil {
		return nil, e
	}
	for _, path := range paths {
		iface, e := nmGet[string](b, path, nmName+".Device", "Interface")
		if e != nil {
			return nil, e
		}
		if iface != parts[1] {
			continue
		}
		t, e := nmReadDevice(b, path)
		if e != nil {
			return nil, e
		}
		if t.View.Target != target {
			return nil, errors.New("active connection changed")
		}
		return t, b.unchangedOwner()
	}
	return nil, errors.New("connection interface is unavailable")
}
func (d *HostDNS) observeNM() hostdns.Observation {
	out := hostdns.Observation{Owner: "networkmanager", Source: dnsSource, Connections: []hostdns.Connection{}, Current: hostdns.Config{Servers: []string{}, Search: []string{}}, Reason: "NetworkManager 未连接或不支持安全的连接级 DNS 管理"}
	if f, e := readDNSFile(dnsSource); e == nil {
		out.Current = parseDNS(f.Data)
	} else if link, e := os.Readlink(dnsSource); e == nil {
		out.LinkTarget = link
		path := filepath.Clean(filepath.Join("/etc", link))
		if filepath.IsAbs(link) {
			path = filepath.Clean(link)
		}
		if path == "/run/NetworkManager/resolv.conf" || path == "/run/systemd/resolve/stub-resolv.conf" || path == "/run/systemd/resolve/resolv.conf" {
			if f, e := readDNSFile(path); e == nil {
				out.Current = parseDNS(f.Data)
			}
		}
	}
	if d.Dev {
		return d.withPending(out)
	}
	b, e := openDNSBus(context.Background())
	if e != nil {
		return d.withPending(out)
	}
	defer b.close()
	supported := nmSupported(b)
	paths, e := nmDevices(b)
	if e != nil {
		return d.withPending(out)
	}
	for _, path := range paths {
		t, e := nmReadDevice(b, path)
		if t == nil {
			continue
		}
		if supported != nil {
			t.View.Writable = false
			t.View.Reason = "需要 NetworkManager 1.44 及以上的版本检查接口"
		} else if e != nil {
			t.View.Writable = false
		}
		out.Connections = append(out.Connections, t.View)
	}
	if b.unchangedOwner() != nil {
		out.Reason = "NetworkManager 在读取期间发生变化，请刷新"
		return d.withPending(out)
	}
	reason := d.hostScopeReason()
	for i := range out.Connections {
		c := &out.Connections[i]
		if reason != "" {
			c.Writable = false
			c.Reason = reason
		}
		out.Writable = out.Writable || c.Writable
	}
	if out.Writable {
		out.Reason = ""
	} else if supported != nil {
		out.Reason = "需要 NetworkManager 1.44 及以上的版本检查接口"
	} else if reason != "" {
		out.Reason = reason
	} else {
		out.Reason = "没有可安全接管的连接，请查看各连接的只读原因"
	}
	return d.withPending(out)
}

var errNMSourceChanged = errors.New("NetworkManager keyfile changed before update")

func nmUpdate(b *nmBus, t *nmTarget, persistent bool, s nmSettings) error {
	hash, err := nmProfileHash(t.Filename)
	if err != nil || hash != t.FileHash {
		return errNMSourceChanged
	}
	if persistent {
		var result map[string]dbus.Variant
		return b.call(t.Profile, nmName+".Settings.Connection.Update2", s, uint32(1|64), map[string]dbus.Variant{"version-id": dbus.MakeVariant(t.ProfileVersion)}).Store(&result)
	}
	return b.call(t.Device, nmName+".Device.Reapply", s, t.AppliedVersion, uint32(1)).Err
}
func nmSnapshotTarget(t *nmTarget, persistent bool) (nmDNS, error) {
	if persistent {
		return nmCapture(t.Persistent)
	}
	return nmCapture(t.Applied)
}
func nmSettingsTarget(t *nmTarget, persistent bool) nmSettings {
	if persistent {
		return t.Persistent
	}
	return t.Applied
}
func nmVersion(t *nmTarget, persistent bool) uint64 {
	if persistent {
		return t.ProfileVersion
	}
	return t.AppliedVersion
}
func nmReadError() error {
	return errors.New("NetworkManager 连接或持久源发生变化，无法确认 DNS 操作")
}

func nmEffective(b *nmBus, t *nmTarget) (*hostdns.Config, error) {
	c := &hostdns.Config{Servers: []string{}, Search: []string{}}
	for i, key := range []string{"Ip4Config", "Ip6Config"} {
		path, e := nmGet[dbus.ObjectPath](b, t.Device, nmName+".Device", key)
		if e != nil {
			return nil, e
		}
		if path == "/" {
			continue
		}
		iface := nmName + []string{".IP4Config", ".IP6Config"}[i]
		f := &hostdns.Family{Servers: []string{}, Search: []string{}}
		if i == 0 {
			data, e := nmGet[[]uint32](b, path, iface, "Nameservers")
			if e != nil || len(data) > 32 {
				return nil, errors.New("effective IPv4 DNS unavailable")
			}
			for _, n := range data {
				var a [4]byte
				binary.NativeEndian.PutUint32(a[:], n)
				f.Servers = append(f.Servers, netip.AddrFrom4(a).String())
			}
		} else {
			data, e := nmGet[[][]byte](b, path, iface, "Nameservers")
			if e != nil || len(data) > 32 {
				return nil, errors.New("effective IPv6 DNS unavailable")
			}
			for _, a := range data {
				ip, ok := netip.AddrFromSlice(a)
				if !ok {
					return nil, errors.New("invalid effective IPv6 DNS")
				}
				f.Servers = append(f.Servers, ip.String())
			}
		}
		search, e := nmGet[[]string](b, path, iface, "Searches")
		if e != nil || len(search) > 64 {
			return nil, errors.New("effective DNS searches unavailable")
		}
		for _, s := range search {
			if len(s) > 254 {
				return nil, errors.New("effective DNS search exceeds budget")
			}
			f.Search = append(f.Search, s)
		}
		if i == 0 {
			c.IPv4 = f
		} else {
			c.IPv6 = f
		}
	}
	return c, nil
}

func nmResolverOwner(b *nmBus) (string, error) {
	path := dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager")
	mode, e := nmGet[string](b, path, nmName+".DnsManager", "Mode")
	if e != nil {
		return "", e
	}
	rc, e := nmGet[string](b, path, nmName+".DnsManager", "RcManager")
	if e != nil {
		return "", e
	}
	target := dnsSource
	if link, err := os.Readlink(dnsSource); err == nil {
		target = link
		if !filepath.IsAbs(target) {
			target = filepath.Join("/etc", target)
		}
		target = filepath.Clean(target)
	}
	allowed := false
	if mode == "default" && (rc == "file" || rc == "symlink") && (target == dnsSource || target == "/run/NetworkManager/resolv.conf") {
		allowed = true
	}
	if mode == "systemd-resolved" && (rc == "file" || rc == "symlink" || rc == "unmanaged") && (target == "/run/systemd/resolve/stub-resolv.conf" || target == "/run/systemd/resolve/resolv.conf") {
		allowed = true
	}
	if !allowed {
		return "", errors.New("unconfirmed NetworkManager resolver owner")
	}
	source, e := readDNSFile(target)
	if e != nil || strings.Contains(string(source.Data), "no-reload") {
		return "", errors.New("resolver entrance cannot be safely managed")
	}
	return mode + ":" + rc + ":" + target, nil
}
