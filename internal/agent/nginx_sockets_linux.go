package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// SOCK_DIAG reports IPV6_V6ONLY for passive IPv6 sockets. /proc/net alone
// cannot distinguish an IPv6-only wildcard from a dual-stack wildcard.
const (
	nginxSockDiagByFamily = 20
	nginxDiagV6Only       = 11
	nginxSocketBytes      = 2 << 20
	nginxSocketObjects    = 8192
)

type networkSocket struct {
	listener listener
	inode    string
	passive  bool
}

func networkSockets(ctx context.Context, networks ...string) ([]networkSocket, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if len(networks) == 0 {
		networks = []string{"tcp4", "tcp6", "udp4", "udp6"}
	}
	if len(networks) > 4 {
		return nil, errors.New("invalid socket diagnostic protocols")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := unix.Getsockname(fd)
	local, ok := address.(*unix.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, errors.New("invalid socket diagnostic port")
	}
	// Reuse only the bounded, read-only receive/poll transport. The firewall
	// query allowlist is unchanged; requests here can only dump TCP/UDP sockets.
	socket := &nftReadSocket{fd: fd, pid: local.Pid, buffer: make([]byte, nftDatagramBytes)}
	out := []networkSocket{}
	for _, network := range networks {
		switch network {
		case "tcp4", "tcp6", "udp4", "udp6":
		default:
			return nil, errors.New("invalid socket diagnostic protocol")
		}
		familyStart := len(out)
		family := byte(unix.AF_INET)
		if strings.HasSuffix(network, "6") {
			family = unix.AF_INET6
		}
		protocol, states := byte(unix.IPPROTO_TCP), uint32(1<<10)
		if strings.HasPrefix(network, "udp") {
			// Connected UDP sockets also reserve a local endpoint and can receive
			// traffic intended for a new shared UDP listener.
			protocol, states = unix.IPPROTO_UDP, 1<<7|1<<1
		}
		data := make([]byte, 56)
		data[0], data[1] = family, protocol
		binary.NativeEndian.PutUint32(data[4:8], states)
		socket.sequence++
		message := netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(data)), Type: nginxSockDiagByFamily, Flags: netlink.Request | netlink.Dump, Sequence: socket.sequence, PID: socket.pid}, Data: data}
		raw, err := message.MarshalBinary()
		if err != nil {
			return nil, err
		}
		for {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			err = unix.Sendto(fd, raw, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				if err = socket.wait(ctx, unix.POLLOUT); err != nil {
					return nil, err
				}
				continue
			}
			break
		}
		if err != nil {
			return nil, err
		}
		for {
			done, err := socket.receive(ctx, socket.sequence, func(message netlink.Message) error {
				if socket.bytes > nginxSocketBytes || socket.objects > nginxSocketObjects {
					return errors.New("socket diagnostics exceed 2 MiB or 8192 objects")
				}
				if message.Header.Type != nginxSockDiagByFamily {
					return errors.New("invalid socket diagnostic response type")
				}
				item, err := parseNginxSocket(message.Data, network, family, states)
				if err != nil {
					return err
				}
				out = append(out, item)
				return nil
			})
			if err != nil {
				// IPv6 can be disabled on a deployment target. Only an explicit
				// unsupported family, with no partial response, is skippable.
				if family == unix.AF_INET6 && len(out) == familyStart && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT)) {
					break
				}
				return nil, err
			}
			if socket.bytes > nginxSocketBytes || socket.objects > nginxSocketObjects {
				return nil, errors.New("socket diagnostics exceed read budget")
			}
			if done {
				break
			}
		}
	}
	return out, nil
}

func parseNginxSocket(data []byte, network string, family byte, states uint32) (networkSocket, error) {
	invalid := errors.New("incomplete kernel socket diagnostics")
	if len(data) < 72 || data[0] != family || data[1] >= 32 || states&(1<<data[1]) == 0 {
		return networkSocket{}, invalid
	}
	var address netip.Addr
	if family == unix.AF_INET {
		address = netip.AddrFrom4([4]byte(data[8:12]))
	} else {
		address = netip.AddrFrom16([16]byte(data[8:24]))
	}
	port, inode := int(binary.BigEndian.Uint16(data[4:6])), binary.NativeEndian.Uint32(data[68:72])
	if port == 0 || inode == 0 {
		return networkSocket{}, invalid
	}
	out := networkSocket{listener: listener{Network: network, IP: address.String(), Port: port}, inode: strconv.FormatUint(uint64(inode), 10), passive: data[1] == 7 || data[1] == 10}
	foundV6Only := false
	for attributes := data[72:]; len(attributes) != 0; {
		if len(attributes) < 4 {
			return networkSocket{}, invalid
		}
		length := int(binary.NativeEndian.Uint16(attributes[:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(attributes) {
			return networkSocket{}, invalid
		}
		for _, value := range attributes[length:aligned] {
			if value != 0 {
				return networkSocket{}, invalid
			}
		}
		if kind&0x3fff == nginxDiagV6Only {
			value := attributes[4:length]
			if kind != nginxDiagV6Only || family != unix.AF_INET6 || foundV6Only || len(value) != 1 || value[0] > 1 {
				return networkSocket{}, invalid
			}
			foundV6Only, out.listener.DualStack = true, value[0] == 0
		}
		attributes = attributes[aligned:]
	}
	if family == unix.AF_INET6 && !foundV6Only {
		if out.passive || address.IsUnspecified() {
			return networkSocket{}, errors.New("kernel did not confirm IPV6_V6ONLY")
		}
		// A connected UDP socket has a specific local address. A mapped
		// address is IPv4; a native IPv6 address cannot cover IPv4 endpoints.
		out.listener.DualStack = address.Is4In6()
	}
	return out, nil
}

func listenerPrefixes(l listener) []netip.Prefix {
	address, err := netip.ParseAddr(l.IP)
	if err != nil || address.Zone() != "" {
		return nil
	}
	switch l.Network {
	case "tcp4", "udp4":
		if !address.Is4() || l.DualStack {
			return nil
		}
	case "tcp6", "udp6":
		if !address.Is6() || address.Is4In6() && !l.DualStack {
			return nil
		}
	default:
		return nil
	}
	if strings.HasSuffix(l.Network, "4") || address.Is4In6() {
		address = address.Unmap()
		if !address.Is4() {
			return nil
		}
	}
	bits := address.BitLen()
	if address.IsUnspecified() {
		bits = 0
	}
	out := []netip.Prefix{netip.PrefixFrom(address, bits)}
	if address.Is6() && address.IsUnspecified() && l.DualStack {
		out = append(out, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	}
	return out
}

func listenersOverlap(a, b listener) bool {
	if len(a.Network) != 4 || len(b.Network) != 4 || a.Port != b.Port || a.Network[:3] != b.Network[:3] {
		return false
	}
	for _, left := range listenerPrefixes(a) {
		for _, right := range listenerPrefixes(b) {
			if left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr())) {
				return true
			}
		}
	}
	return false
}

func listenerCovers(a, b listener) bool {
	if len(a.Network) != 4 || len(b.Network) != 4 || a.Port != b.Port || a.Network[:3] != b.Network[:3] {
		return false
	}
	if a.Network == b.Network && a.IP == b.IP && a.DualStack != b.DualStack {
		return false
	}
	left, right := listenerPrefixes(a), listenerPrefixes(b)
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	for _, prefix := range right {
		covered := false
		for _, candidate := range left {
			if candidate.Addr().BitLen() == prefix.Addr().BitLen() && candidate.Bits() <= prefix.Bits() && candidate.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func checkListenerOccupancy(wants []listener, owned map[string]bool, sockets []networkSocket) error {
	for _, socket := range sockets {
		if owned[socket.inode] {
			continue
		}
		for _, want := range wants {
			if listenersOverlap(want, socket.listener) {
				return fmt.Errorf("listener %s %s:%d conflicts with another process", want.Network, want.IP, want.Port)
			}
		}
	}
	return nil
}

func confirmNginxListeners(wants []listener, owned map[string]bool, sockets []networkSocket) error {
	if err := checkListenerOccupancy(wants, owned, sockets); err != nil {
		return err
	}
	for _, want := range wants {
		found := false
		for _, socket := range sockets {
			if socket.passive && owned[socket.inode] && listenerCovers(socket.listener, want) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("Nginx listener ownership or IPv6 mode is unconfirmed")
		}
	}
	for _, socket := range sockets {
		if !socket.passive || !owned[socket.inode] {
			continue
		}
		found := false
		for _, want := range wants {
			if listenerCovers(want, socket.listener) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("unexpected Nginx listener remains active")
		}
	}
	return nil
}

func (n *Nginx) checkListenerAvailability(ctx context.Context, m manifest) error {
	pid, err := n.masterPID()
	if err != nil {
		return err
	}
	owned, err := processSockets(pid)
	if err != nil {
		return err
	}
	sockets, err := networkSockets(ctx)
	if err != nil {
		return err
	}
	return checkListenerOccupancy(m.Listeners, owned, sockets)
}
