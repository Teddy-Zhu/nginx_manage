package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/firewall"
)

type firewalldBus struct {
	conn         *dbus.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	owner, busID string
	process      networkdProcess
}

func openFirewalldBus(parent context.Context) (*firewalldBus, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		cancel()
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	conn, err := dbus.NewConn(&firewalldBusWire{dnsBusWire: dnsBusWire{Conn: raw}}, dbus.WithContext(ctx))
	if err != nil {
		raw.Close()
		cancel()
		return nil, err
	}
	b := &firewalldBus{conn: conn, ctx: ctx, cancel: cancel}
	if err = conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err == nil {
		err = conn.Hello()
	}
	if err == nil {
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, firewalldName).Store(&b.owner)
	}
	if err == nil {
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", dbus.FlagNoAutoStart).Store(&b.busID)
	}
	var uid, pid uint32
	if err == nil {
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, b.owner).Store(&uid)
	}
	if err == nil && uid != 0 {
		err = errors.New("firewalld 服务不是本机 root 所有")
	}
	if err == nil {
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", dbus.FlagNoAutoStart, b.owner).Store(&pid)
	}
	if err == nil {
		b.process, err = networkProcess(pid)
	}
	if err == nil && (!validFirewalldBusOwner(b.owner) || !validFirewalldBusID(b.busID)) {
		err = errors.New("firewalld 服务身份无效")
	}
	if err == nil {
		err = b.unchangedOwner()
	}
	if err != nil {
		b.close()
		return nil, err
	}
	return b, nil
}
func (b *firewalldBus) close() { b.conn.Close(); b.cancel() }
func (b *firewalldBus) call(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return b.conn.Object(b.owner, path).CallWithContext(b.ctx, method, dbus.FlagNoAutoStart, args...)
}
func (b *firewalldBus) unchangedOwner() error {
	var owner string
	if err := b.conn.BusObject().CallWithContext(b.ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, firewalldName).Store(&owner); err != nil {
		return err
	}
	if owner != b.owner {
		return errors.New("firewalld 服务所有者已变化")
	}
	return nil
}
func validFirewalldBusOwner(owner string) bool {
	if len(owner) < 4 || len(owner) > 255 || owner[0] != ':' {
		return false
	}
	parts := strings.Split(owner[1:], ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}
func validFirewalldBusID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

type firewalldRegistrationSnapshot struct {
	Inventory          firewall.FirewalldPolicyInventory
	Policy             firewall.FirewalldPolicy
	Runtime, Permanent map[string]dbus.Variant
	Path               dbus.ObjectPath
}

// The complete inventory and a second full read of the fixed object must
// agree. This detects drift, not concurrent administrator writes atomically.
func (b *firewalldBus) registrationSnapshot() (firewalldRegistrationSnapshot, error) {
	out := firewalldRegistrationSnapshot{Inventory: readFirewalldPolicies(b.ctx, b.conn, b.owner)}
	if !out.Inventory.Available {
		return out, errors.New(out.Inventory.Reason)
	}
	for _, p := range out.Inventory.Policies {
		if p.Name == firewall.FirewalldHostPolicy {
			out.Policy = p
			break
		}
	}
	if out.Policy.Runtime != nil {
		if err := b.call(firewalldRoot, firewalldName+".policy.getPolicySettings", firewall.FirewalldHostPolicy).Store(&out.Runtime); err != nil {
			return out, err
		}
		s, _, err := summarizeFirewalldPolicy(out.Runtime)
		if err != nil || s.Hash != out.Policy.Runtime.Hash {
			return out, errors.New("firewalld 运行 policy 在读取期间变化")
		}
	}
	if out.Policy.Permanent != nil {
		config := dbus.ObjectPath(string(firewalldRoot) + "/config")
		if err := b.call(config, firewalldName+".config.getPolicyByName", firewall.FirewalldHostPolicy).Store(&out.Path); err != nil {
			return out, err
		}
		if !out.Path.IsValid() || !strings.HasPrefix(string(out.Path), string(firewalldRoot)+"/config/policy/") {
			return out, errors.New("firewalld policy 对象路径无效")
		}
		var name dbus.Variant
		if err := b.call(out.Path, "org.freedesktop.DBus.Properties.Get", firewalldName+".config.policy", "name").Store(&name); err != nil || name.Value() != firewall.FirewalldHostPolicy {
			return out, errors.New("firewalld policy 对象名称不匹配")
		}
		if err := b.call(out.Path, firewalldName+".config.policy.getSettings").Store(&out.Permanent); err != nil {
			return out, err
		}
		s, _, err := summarizeFirewalldPolicy(out.Permanent)
		if err != nil || s.Hash != out.Policy.Permanent.Hash {
			return out, errors.New("firewalld 永久 policy 在读取期间变化")
		}
	}
	return out, b.unchangedOwner()
}

func firewalldEmptySettings(owner string) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"description": dbus.MakeVariant("nginxpanel:firewalld:v1:" + owner),
		"target":      dbus.MakeVariant("CONTINUE"), "priority": dbus.MakeVariant(int32(firewall.FirewalldHostPriority)),
		"ingress_zones": dbus.MakeVariant([]string{"ANY"}), "egress_zones": dbus.MakeVariant([]string{"HOST"}),
	}
}

// Documented empty/default keys may be omitted. Every present key is typed
// and checked, including flags and lists which the public summary hides.
func firewalldEmptyMatches(settings map[string]dbus.Variant, owner string) bool {
	if _, _, err := summarizeFirewalldPolicy(settings); err != nil {
		return false
	}
	expected := firewalldEmptySettings(owner)
	for key, value := range expected {
		actual, ok := settings[key]
		if !ok || actual.Signature() != value.Signature() {
			return false
		}
		switch v := value.Value().(type) {
		case []string:
			a, ok := actual.Value().([]string)
			if !ok || !slices.Equal(a, v) {
				return false
			}
		default:
			if actual.Value() != v {
				return false
			}
		}
	}
	for key, value := range settings {
		if _, ok := expected[key]; ok {
			continue
		}
		switch v := value.Value().(type) {
		case string:
			if v != "" {
				return false
			}
		case bool:
			if v {
				return false
			}
		case []string:
			if len(v) != 0 {
				return false
			}
		case [][]any:
			if len(v) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
