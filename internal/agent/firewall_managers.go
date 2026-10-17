package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/firewall"
)

const firewalldName = "org.fedoraproject.FirewallD1"
const firewalldRoot = dbus.ObjectPath("/org/fedoraproject/FirewallD1")

func firewallBool(value bool) *bool { return &value }

// Retain the per-frame allocation bound and additionally bound the complete
// manager observation, including replies to per-policy reads and bus signals.
type firewalldBusWire struct {
	dnsBusWire
	readBytes int
}

func (w *firewalldBusWire) Read(p []byte) (int, error) {
	remaining := (8 << 20) - w.readBytes
	if remaining <= 0 {
		return 0, errors.New("firewalld observation exceeds bus budget")
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := w.dnsBusWire.Read(p)
	w.readBytes += n
	return n, err
}

func readFirewalld(parent context.Context) firewall.Firewalld {
	out := firewall.Firewalld{Registration: firewall.RegistrationView{State: "unavailable", Reason: "尚未核对 firewalld root 登记"}, Zones: []firewall.Zone{}, PolicyInventory: firewall.EmptyFirewalldPolicies("firewalld policy 尚未读取"), Reason: "无法读取本机 firewalld 状态"}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	raw, e := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if e != nil {
		return out
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	conn, e := dbus.NewConn(&firewalldBusWire{dnsBusWire: dnsBusWire{Conn: raw}}, dbus.WithContext(ctx))
	if e != nil {
		raw.Close()
		return out
	}
	defer conn.Close()
	if conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}) != nil || conn.Hello() != nil {
		return out
	}
	var owner string
	if e = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, firewalldName).Store(&owner); e != nil {
		var reply dbus.Error
		if errors.As(e, &reply) && reply.Name == "org.freedesktop.DBus.Error.NameHasNoOwner" {
			out.Running = firewallBool(false)
			out.Reason = "firewalld 当前未运行"
		}
		return out
	}
	peer := conn.Object(owner, firewalldRoot)
	var panicMode bool
	if e = peer.CallWithContext(ctx, firewalldName+".queryPanicMode", dbus.FlagNoAutoStart).Store(&panicMode); e != nil {
		return out
	}
	out.Running = firewallBool(true)
	out.Panic = &panicMode
	var defaultZone string
	if e = peer.CallWithContext(ctx, firewalldName+".getDefaultZone", dbus.FlagNoAutoStart).Store(&defaultZone); e != nil || !firewallName(defaultZone) {
		out.Reason = "firewalld 正在运行，但默认 zone 无法完整读取"
		return out
	}
	out.DefaultZone = defaultZone
	var zones map[string]map[string][]string
	if e = peer.CallWithContext(ctx, firewalldName+".zone.getActiveZones", dbus.FlagNoAutoStart).Store(&zones); e != nil || len(zones) > 128 {
		out.Reason = "firewalld zone 清单无法在预算内完整读取"
		return out
	}
	total := 0
	entries := []firewall.Zone{}
	for name, zone := range zones {
		if !firewallName(name) || len(zone) > 8 || len(zone["interfaces"])+len(zone["sources"]) > 256 {
			out.Reason = "firewalld zone 内容无效或超过预算"
			return out
		}
		for _, values := range zone {
			for _, value := range values {
				total += len(value)
				if !firewallName(value) || total > 32<<10 {
					out.Reason = "firewalld zone 内容无效或超过预算"
					return out
				}
			}
		}
		entry := firewall.Zone{Name: name, Interfaces: append([]string{}, zone["interfaces"]...), Sources: append([]string{}, zone["sources"]...)}
		sort.Strings(entry.Interfaces)
		sort.Strings(entry.Sources)
		entries = append(entries, entry)
	}
	out.Zones = entries
	sort.Slice(out.Zones, func(i, j int) bool { return out.Zones[i].Name < out.Zones[j].Name })
	var configured dbus.Variant
	e = conn.Object(owner, dbus.ObjectPath(string(firewalldRoot)+"/config")).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, firewalldName+".config", "FirewallBackend").Store(&configured)
	if e == nil {
		if value, ok := configured.Value().(string); ok && (value == "nftables" || value == "iptables") {
			out.ConfiguredBackend = value
		}
	}
	policyCtx, policyCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	out.PolicyInventory = readFirewalldPolicies(policyCtx, conn, owner)
	policyCancel()
	var after string
	if e = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, firewalldName).Store(&after); e != nil || after != owner {
		out.Running = nil
		out.Panic = nil
		out.DefaultZone = ""
		out.ConfiguredBackend = ""
		out.Zones = []firewall.Zone{}
		out.PolicyInventory = firewall.EmptyFirewalldPolicies("firewalld 在读取期间变化或无法再次核对，请刷新")
		out.Reason = "firewalld 在读取期间变化，请刷新"
		return out
	}
	out.Reason = ""
	if out.ConfiguredBackend == "" {
		out.Reason = "运行状态已读取，配置中的后端选择不可用"
	}
	return out
}

func ufwConfigured() (*bool, error) {
	return ufwConfigurationFlag("/etc/ufw/ufw.conf", "ENABLED")
}

// Only the two fixed system configuration locations call this reader.
func ufwConfigurationFlag(path, field string) (*bool, error) {
	if e := existingRootDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > 16<<10 {
		return nil, errors.New("unsafe ufw configuration")
	}
	raw, e := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if e != nil || len(raw) > 16<<10 || !utf8.Valid(raw) {
		return nil, errors.New("ufw configuration exceeds budget")
	}
	var enabled *bool
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != field {
			continue
		}
		// No shell evaluation, expansion, guessed defaults or last-key wins.
		value = strings.TrimSpace(value)
		if enabled != nil || value != "yes" && value != "no" {
			return nil, errors.New("ambiguous ufw enable state")
		}
		enabled = firewallBool(value == "yes")
	}
	if enabled == nil {
		return nil, errors.New("ufw configuration flag is unspecified")
	}
	after, e := f.Stat()
	if e != nil || after.Size() != int64(len(raw)) || after.ModTime() != info.ModTime() {
		return nil, errors.New("ufw configuration changed while reading")
	}
	return enabled, nil
}

func readUFW(ctx context.Context) firewall.UFW {
	out := firewall.UFW{Registration: firewall.RegistrationView{State: "unavailable", Reason: "尚未核对 UFW 本机授权登记"}, RuleInventory: firewall.EmptyUFWRules("尚未读取 UFW 用户规则"), Reason: "未发现可用的 UFW 程序"}
	for _, path := range []string{"/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"} {
		if _, e := trustedFile(path, true); e == nil {
			out.Installed = true
			break
		}
	}
	configured, configErr := ufwConfigured()
	out.Enabled = configured
	ipv6, ipv6Err := ufwConfigurationFlag("/etc/default/ufw", "IPV6")
	out.IPv6 = ipv6
	if !out.Installed {
		if configErr == nil {
			out.Reason = "存在 UFW 启用配置，但程序不可用"
		}
		return out
	}
	raw, e := firewallRead(ctx, "ufw", "status", 256<<10)
	if e != nil {
		out.Reason = "UFW 状态读取失败或超时"
		return out
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	switch strings.TrimSpace(line) {
	case "Status: active":
		out.Active = firewallBool(true)
	case "Status: inactive":
		out.Active = firewallBool(false)
	default:
		out.Reason = "UFW 返回了无法识别的状态"
		return out
	}
	out.Reason = ""
	if configErr != nil || ipv6Err != nil {
		out.Reason = "UFW 当前状态已读取，持久启用或 IPv6 配置无法完整确认"
	}
	added, e := firewallRead(ctx, "ufw", "added", firewall.UFWReadBytes)
	if e != nil {
		out.RuleInventory = firewall.EmptyUFWRules("UFW 用户规则读取失败、超时或超过预算")
	} else {
		inventory, parseErr := parseUFWAdded(added)
		if parseErr != nil {
			out.RuleInventory = firewall.EmptyUFWRules("UFW 用户规则报告无法完整解析或超过预算")
		} else {
			out.RuleInventory = inventory
		}
	}
	return out
}
