package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
)

// Only the local system bus is reachable. Bound each frame before godbus
// allocates its body; neither a Web URL nor DBUS_SYSTEM_BUS_ADDRESS is used.
type dnsBusWire struct {
	net.Conn
	binary    atomic.Bool
	header    [16]byte
	offset    int
	left      uint64
	authBytes int
}

func (w *dnsBusWire) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("BEGIN\r\n")) {
		w.binary.Store(true)
	}
	return w.Conn.Write(p)
}
func (w *dnsBusWire) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !w.binary.Load() {
		n, e := w.Conn.Read(p)
		w.authBytes += n
		if w.authBytes > 4096 {
			return 0, errors.New("system bus authentication exceeds budget")
		}
		return n, e
	}
	if w.offset == 0 && w.left == 0 {
		if _, e := io.ReadFull(w.Conn, w.header[:]); e != nil {
			return 0, e
		}
		var order binary.ByteOrder
		switch w.header[0] {
		case 'l':
			order = binary.LittleEndian
		case 'B':
			order = binary.BigEndian
		default:
			return 0, errors.New("invalid system bus frame")
		}
		body := uint64(order.Uint32(w.header[4:8]))
		fields := uint64(order.Uint32(w.header[12:16]))
		w.left = ((fields + 7) &^ uint64(7)) + body
		if w.left+16 > 1<<20 {
			return 0, errors.New("system bus frame exceeds DNS budget")
		}
	}
	if w.offset < 16 {
		n := copy(p, w.header[w.offset:])
		w.offset += n
		if w.offset == 16 && w.left == 0 {
			w.offset = 0
		}
		return n, nil
	}
	if uint64(len(p)) > w.left {
		p = p[:int(w.left)]
	}
	n, e := w.Conn.Read(p)
	w.left -= uint64(n)
	if w.left == 0 {
		w.offset = 0
	}
	return n, e
}

const nmName = "org.freedesktop.NetworkManager"
const nmRoot = dbus.ObjectPath("/org/freedesktop/NetworkManager")

type dnsBus struct {
	conn         *dbus.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	owner, busID string
	service      string
}

func openDNSBus(parent context.Context) (*dnsBus, error) { return openDNSService(parent, nmName) }
func openDNSService(parent context.Context, service string) (*dnsBus, error) {
	if service != nmName && service != networkdName && service != resolvedName {
		return nil, errors.New("unsupported DNS service")
	}

	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	raw, e := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if e != nil {
		cancel()
		return nil, e
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	conn, e := dbus.NewConn(&dnsBusWire{Conn: raw}, dbus.WithContext(ctx))
	if e != nil {
		raw.Close()
		cancel()
		return nil, e
	}
	b := &dnsBus{conn: conn, ctx: ctx, cancel: cancel, service: service}
	if e = conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); e == nil {
		e = conn.Hello()
	}
	if e == nil {
		e = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, service).Store(&b.owner)
	}
	if e == nil {
		e = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", dbus.FlagNoAutoStart).Store(&b.busID)
	}
	if e != nil {
		b.close()
		return nil, e
	}
	return b, nil
}
func (b *dnsBus) close() { b.conn.Close(); b.cancel() }
func (b *dnsBus) call(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return b.conn.Object(b.owner, path).CallWithContext(b.ctx, method, dbus.FlagNoAutoStart, args...)
}
func (b *dnsBus) property(path dbus.ObjectPath, iface, key string) (dbus.Variant, error) {
	var v dbus.Variant
	e := b.call(path, "org.freedesktop.DBus.Properties.Get", iface, key).Store(&v)
	return v, e
}
func (b *dnsBus) unchangedOwner() error {
	var owner string
	e := b.conn.BusObject().CallWithContext(b.ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, b.service).Store(&owner)
	if e == nil && owner != b.owner {
		e = errors.New("DNS service owner changed")
	}
	return e
}

func dnsProperty[T any](b *dnsBus, path dbus.ObjectPath, iface, key string) (T, error) {
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
