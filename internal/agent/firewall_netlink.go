package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const nftReadBytes = 32 << 20
const nftDatagramBytes = 64 << 10
const nftReadObjects = firewall.MaxEntries + 4*firewall.MaxRules + 8192

// The send method only implements GET operations. In particular, a successful
// read does not grant ownership of any object or authorize a transaction.
// Receive processes one bounded datagram at a time instead of accumulating an
// unbounded multipart dump in netlink.Conn.Receive.
type nftReadSocket struct {
	table          string
	set            string
	fd             int
	pid, sequence  uint32
	bytes, objects int
	buffer         []byte
}

func openNFTRead() (*nftReadSocket, error) {
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if e != nil {
		return nil, e
	}
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		unix.Close(fd)
		return nil, e
	}
	address, e := unix.Getsockname(fd)
	if e != nil {
		unix.Close(fd)
		return nil, e
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		unix.Close(fd)
		return nil, errors.New("invalid netlink port")
	}
	return &nftReadSocket{table: firewall.NFTHostTable, fd: fd, pid: local.Pid, buffer: make([]byte, nftDatagramBytes)}, nil
}
func (s *nftReadSocket) close() { unix.Close(s.fd) }
func (s *nftReadSocket) wait(ctx context.Context, event int16) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		milliseconds := 100
		if deadline, ok := ctx.Deadline(); ok {
			left := time.Until(deadline)
			if left <= 0 {
				return context.DeadlineExceeded
			}
			milliseconds = min(milliseconds, max(1, int(left.Milliseconds())))
		}
		fds := []unix.PollFd{{Fd: int32(s.fd), Events: event}}
		n, e := unix.Poll(fds, milliseconds)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("netlink read connection failed")
		}
		if fds[0].Revents&event != 0 {
			return nil
		}
	}
}
func (s *nftReadSocket) send(ctx context.Context, message netlink.Message) error {
	// A closed GET allowlist makes accidental future reuse for writes fail.
	kind := uint16(message.Header.Type)
	switch kind {
	case unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETGEN,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETTABLE,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETCHAIN,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETSET,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETSETELEM,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETOBJ,
		unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETFLOWTABLE:
	default:
		return errors.New("unsupported nftables read")
	}
	message.Header.Length = uint32(unix.NLMSG_HDRLEN + len(message.Data))
	raw, e := message.MarshalBinary()
	if e != nil {
		return e
	}
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		e = unix.Sendto(s.fd, raw, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if !errors.Is(e, unix.EAGAIN) {
			return e
		}
		if e = s.wait(ctx, unix.POLLOUT); e != nil {
			return e
		}
	}
}
func (s *nftReadSocket) receive(ctx context.Context, sequence uint32, fn func(netlink.Message) error) (bool, error) {
	for {
		if e := ctx.Err(); e != nil {
			return false, e
		}
		n, _, flags, sender, e := unix.Recvmsg(s.fd, s.buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.EAGAIN) {
			if e = s.wait(ctx, unix.POLLIN); e != nil {
				return false, e
			}
			continue
		}
		if e != nil {
			return false, e
		}
		peer, ok := sender.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 || peer.Groups != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 {
			return false, errors.New("incomplete netlink datagram")
		}
		s.bytes += n
		if s.bytes > nftReadBytes {
			return false, fault.Unavailable("目标表内核快照超过 32 MiB 读取预算")
		}
		raw := s.buffer[:n]
		done := false
		for len(raw) > 0 {
			if len(raw) < unix.NLMSG_HDRLEN {
				return false, errors.New("short netlink header")
			}
			length := int(binary.NativeEndian.Uint32(raw[:4]))
			aligned := (length + 3) &^ 3
			if length < unix.NLMSG_HDRLEN || aligned > len(raw) {
				return false, errors.New("invalid netlink length")
			}
			m := netlink.Message{Header: netlink.Header{Length: uint32(length), Type: netlink.HeaderType(binary.NativeEndian.Uint16(raw[4:6])), Flags: netlink.HeaderFlags(binary.NativeEndian.Uint16(raw[6:8])), Sequence: binary.NativeEndian.Uint32(raw[8:12]), PID: binary.NativeEndian.Uint32(raw[12:16])}, Data: raw[unix.NLMSG_HDRLEN:length]}
			raw = raw[aligned:]
			if done || m.Header.Sequence != sequence || m.Header.PID != 0 && m.Header.PID != s.pid || m.Header.Flags&netlink.DumpInterrupted != 0 {
				return false, errors.New("inconsistent netlink response")
			}
			switch m.Header.Type {
			case netlink.Error:
				if len(m.Data) < 4 {
					return false, errors.New("short netlink error")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
				if code < 0 {
					return false, syscall.Errno(-int64(code))
				}
				return false, errors.New("unexpected netlink acknowledgement")
			case netlink.Done:
				if len(m.Data) != 0 {
					if len(m.Data) < 4 {
						return false, errors.New("short netlink completion")
					}
					code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
					if code < 0 {
						return false, syscall.Errno(-int64(code))
					}
					if code != 0 {
						return false, errors.New("invalid netlink completion")
					}
				}
				done = true
			case netlink.Overrun, netlink.Noop:
				return false, errors.New("incomplete netlink response")
			default:
				s.objects++
				if s.objects > nftReadObjects {
					return false, fault.Unavailable("目标表内核快照对象数超过读取预算")
				}
				if e = fn(m); e != nil {
					return false, e
				}
				if m.Header.Flags&netlink.Multi == 0 {
					done = true
				}
			}
		}
		return done, nil
	}
}
func (s *nftReadSocket) query(ctx context.Context, kind, reply uint16, dump bool, table bool, fn func(netlink.Message) error) error {
	s.sequence++
	family := byte(unix.NFPROTO_INET)
	if kind == unix.NFT_MSG_GETGEN {
		family = unix.NFPROTO_UNSPEC
	}
	data := []byte{family, unix.NFNETLINK_V0, 0, 0}
	if table {
		if s.table != firewall.NFTHostTable && s.table != firewall.NFTFail2banTable {
			return errors.New("unsupported fixed nftables read target")
		}
		// TABLE_NAME, CHAIN_TABLE, RULE_TABLE, SET_TABLE, OBJ_TABLE and
		// FLOWTABLE_TABLE all have UAPI attribute number 1.
		attributes, e := netlink.MarshalAttributes([]netlink.Attribute{{Type: 1, Data: []byte(s.table + "\x00")}})
		if e != nil {
			return e
		}
		data = append(data, attributes...)
		if kind == unix.NFT_MSG_GETSETELEM {
			if s.set == "" || len(s.set) > 256 {
				return errors.New("invalid address set read target")
			}
			attrs, e := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_SET_ELEM_LIST_SET, Data: []byte(s.set + "\x00")}})
			if e != nil {
				return e
			}
			data = append(data, attrs...)
		}
	}
	flags := netlink.Request
	if dump {
		flags |= netlink.Dump
	}
	message := netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | kind), Flags: flags, Sequence: s.sequence, PID: s.pid}, Data: data}
	if e := s.send(ctx, message); e != nil {
		return e
	}
	for {
		done, e := s.receive(ctx, s.sequence, func(m netlink.Message) error {
			if m.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|reply) || len(m.Data) < 4 || m.Data[0] != family || m.Data[1] != unix.NFNETLINK_V0 {
				return errors.New("unexpected nftables object")
			}
			return fn(m)
		})
		if e != nil {
			return e
		}
		if done {
			return nil
		}
	}
}
func nftAttributes(m netlink.Message) (map[uint16]netlink.Attribute, error) {
	attrs, e := netlink.UnmarshalAttributes(m.Data[4:])
	if e != nil {
		return nil, e
	}
	out := map[uint16]netlink.Attribute{}
	for _, a := range attrs {
		kind := a.Type & ^uint16(netlink.Nested|netlink.NetByteOrder)
		// Repeated padding has no semantic content; every other duplicate is
		// ambiguous and must not produce a fingerprint of a partial object.
		padding := m.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE) && kind == 5 || m.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWCHAIN) && kind == unix.NFTA_CHAIN_PAD || m.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE) && kind == unix.NFTA_RULE_PAD || m.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWSET) && kind == unix.NFTA_SET_PAD
		if padding {
			if len(bytes.Trim(a.Data, "\x00")) != 0 {
				return nil, errors.New("invalid nftables padding")
			}
			continue
		}
		if _, ok := out[kind]; ok {
			return nil, errors.New("duplicate nftables attribute")
		}
		if m.Header.Type == netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWCHAIN) && kind == unix.NFTA_CHAIN_COUNTERS {
			// Keep the presence/shape and all unknown counter attributes. Only
			// these two dynamic UAPI values are normalized, without resetting
			// the kernel counters or decoding any rule expression.
			counters, e := netlink.UnmarshalAttributes(a.Data)
			if e != nil {
				return nil, e
			}
			seen := map[uint16]bool{}
			for i, counter := range counters {
				field := counter.Type & ^uint16(netlink.Nested|netlink.NetByteOrder)
				if field == unix.NFTA_COUNTER_BYTES || field == unix.NFTA_COUNTER_PACKETS {
					if seen[field] || len(counter.Data) != 8 {
						return nil, errors.New("invalid nftables chain counter")
					}
					seen[field] = true
					counters[i].Data = make([]byte, 8)
				}
			}
			a.Data, e = netlink.MarshalAttributes(counters)
			if e != nil {
				return nil, e
			}
		}
		out[kind] = a
	}
	return out, nil
}
func nftString(a netlink.Attribute) (string, error) {
	if a.Type&(netlink.Nested|netlink.NetByteOrder) != 0 || len(a.Data) < 2 || len(a.Data) > 257 || a.Data[len(a.Data)-1] != 0 || bytes.IndexByte(a.Data[:len(a.Data)-1], 0) >= 0 {
		return "", errors.New("invalid nftables name")
	}
	return string(a.Data[:len(a.Data)-1]), nil
}
func (s *nftReadSocket) generation(ctx context.Context) (uint32, error) {
	var value uint32
	count := 0
	e := s.query(ctx, unix.NFT_MSG_GETGEN, unix.NFT_MSG_NEWGEN, false, false, func(m netlink.Message) error {
		count++
		attrs, e := nftAttributes(m)
		if e != nil {
			return e
		}
		a, ok := attrs[unix.NFTA_GEN_ID]
		if !ok || len(a.Data) != 4 {
			return errors.New("missing nftables generation")
		}
		value = binary.BigEndian.Uint32(a.Data)
		return nil
	})
	if e == nil && (count != 1 || value == 0) {
		e = fault.Unavailable("内核未提供可用于事务核对的非零规则代次")
	}
	return value, e
}
func nftFrame(h hash.Hash, raw []byte) {
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw))))
	h.Write(raw)
}
func nftObjectHash(h hash.Hash, m netlink.Message, attrs map[uint16]netlink.Attribute) {
	// Expression attributes remain completely opaque: no expression is
	// decoded or silently removed, including unknown expression types.
	kinds := make([]int, 0, len(attrs))
	for kind := range attrs {
		kinds = append(kinds, int(kind))
	}
	sort.Ints(kinds)
	nftFrame(h, binary.BigEndian.AppendUint16(nil, uint16(m.Header.Type)))
	nftFrame(h, []byte{m.Data[0]})
	nftFrame(h, binary.BigEndian.AppendUint32(nil, uint32(len(kinds))))
	for _, kind := range kinds {
		a := attrs[uint16(kind)]
		nftFrame(h, binary.BigEndian.AppendUint16(nil, a.Type))
		nftFrame(h, a.Data)
	}
}
func nftNamespace() (string, error) {
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	id := string(bytes.TrimSpace(boot))
	if !validID(id) {
		return "", errors.New("invalid boot identity")
	}
	var st unix.Stat_t
	if e = unix.Stat("/proc/self/ns/net", &st); e != nil {
		return "", e
	}
	return secure.Hash([]byte(fmt.Sprintf("%s:%d:%d", id, st.Dev, st.Ino))), nil
}

func readNFTKernel(ctx context.Context) firewall.KernelView {
	out := firewall.KernelView{Reason: "受管目标表的内核快照无法完整读取"}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, e := snapshotNFTKernel(call)
	if e != nil {
		var known *fault.Error
		if errors.As(e, &known) {
			out.Reason = known.Message
		} else if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			out.Reason = "目标表内核快照未能在读取期限内完成"
		}
		return out
	}
	return value
}
func snapshotNFTKernel(ctx context.Context) (firewall.KernelView, error) {
	return snapshotNFTKernelInspect(ctx, nil)
}

func snapshotNFTKernelInspect(ctx context.Context, inspect func(uint16, map[uint16]netlink.Attribute) error) (firewall.KernelView, error) {
	return snapshotNFTTargetInspect(ctx, firewall.NFTPortInput, inspect)
}
func snapshotNFTTargetInspect(ctx context.Context, target firewall.NFTTarget, inspect func(uint16, map[uint16]netlink.Attribute) error) (firewall.KernelView, error) {
	var out firewall.KernelView
	layout, e := target.Layout()
	if e != nil {
		return out, e
	}
	namespace, e := nftNamespace()
	if e != nil {
		return out, e
	}
	s, e := openNFTRead()
	if e != nil {
		return out, e
	}
	defer s.close()
	s.table = layout.Table
	generation, e := s.generation(ctx)
	if e != nil {
		return out, e
	}
	h := sha256.New()
	nftFrame(h, []byte("nginxpanel:nft-snapshot:v1"))
	nftFrame(h, []byte(namespace))
	count := 0
	e = s.query(ctx, unix.NFT_MSG_GETTABLE, unix.NFT_MSG_NEWTABLE, false, true, func(m netlink.Message) error {
		count++
		if count > 1 {
			return errors.New("duplicate nftables table")
		}
		attrs, e := nftAttributes(m)
		if e != nil {
			return e
		}
		name, e := nftString(attrs[unix.NFTA_TABLE_NAME])
		if e != nil || name != layout.Table {
			return errors.New("unexpected nftables table")
		}
		if inspect != nil {
			if err := inspect(uint16(m.Header.Type), attrs); err != nil {
				return err
			}
		}
		nftObjectHash(h, m, attrs)
		return nil
	})
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return out, e
	}
	if e == nil && count != 1 || errors.Is(e, unix.ENOENT) && count != 0 {
		return out, errors.New("ambiguous nftables table presence")
	}
	out.TableExists = count == 1
	setNames := []string{}
	if out.TableExists {
		// Some supported kernels dump every inet chain even when TABLE was
		// supplied. Consume the full bounded dump, filter locally and retain
		// the global generation check; never mistake an unfiltered prefix for
		// a complete target-table result.
		for _, query := range []struct {
			request, reply uint16
			category       string
		}{{unix.NFT_MSG_GETCHAIN, unix.NFT_MSG_NEWCHAIN, "chain"}, {unix.NFT_MSG_GETRULE, unix.NFT_MSG_NEWRULE, "rule"}, {unix.NFT_MSG_GETSET, unix.NFT_MSG_NEWSET, "set"}, {unix.NFT_MSG_GETOBJ, unix.NFT_MSG_NEWOBJ, "object"}, {unix.NFT_MSG_GETFLOWTABLE, unix.NFT_MSG_NEWFLOWTABLE, "flowtable"}} {
			e = s.query(ctx, query.request, query.reply, true, true, func(m netlink.Message) error {
				attrs, e := nftAttributes(m)
				if e != nil {
					return e
				}
				table, e := nftString(attrs[1])
				if e != nil {
					return e
				}
				if table != layout.Table {
					return nil
				}
				switch query.category {
				case "chain":
					out.Chains++
				case "rule":
					out.Rules++
				case "set":
					name, e := nftString(attrs[unix.NFTA_SET_NAME])
					if e != nil || name == "" || len(setNames) >= 2*firewall.MaxRules {
						return errors.New("invalid or excessive address sets")
					}
					setNames = append(setNames, name)
				default:
					return fault.Unavailable("目标表包含不支持的状态对象或 flowtable")
				}
				if out.Chains > 128 || out.Rules > firewall.MaxEntries {
					return fault.Unavailable("目标表链或规则数超过读取预算")
				}
				if inspect != nil {
					if err := inspect(uint16(m.Header.Type), attrs); err != nil {
						return err
					}
				}
				nftObjectHash(h, m, attrs)
				return nil
			})
			if e != nil {
				return out, e
			}
		}
	}
	for _, name := range setNames {
		s.set = name
		e = s.query(ctx, unix.NFT_MSG_GETSETELEM, unix.NFT_MSG_NEWSETELEM, true, true, func(m netlink.Message) error {
			attrs, e := nftAttributes(m)
			if e != nil {
				return e
			}
			table, e := nftString(attrs[unix.NFTA_SET_ELEM_LIST_TABLE])
			if e != nil || table != layout.Table {
				return errors.New("unexpected address set table")
			}
			set, e := nftString(attrs[unix.NFTA_SET_ELEM_LIST_SET])
			if e != nil || set != name {
				return errors.New("unexpected address set name")
			}
			if inspect != nil {
				if e = inspect(uint16(m.Header.Type), attrs); e != nil {
					return e
				}
			}
			nftObjectHash(h, m, attrs)
			return nil
		})
		s.set = ""
		if e != nil {
			return out, e
		}
	}
	current, e := s.generation(ctx)
	if e != nil {
		return out, e
	}
	if current != generation {
		return out, fault.Conflict("读取期间内核规则代次变化，须重新读取")
	}
	currentNamespace, e := nftNamespace()
	if e != nil {
		return out, e
	}
	if currentNamespace != namespace {
		return out, fault.Conflict("读取期间网络命名空间变化，须重新读取")
	}
	nftFrame(h, []byte{byte(count)})
	out.Available = true
	out.Generation = generation
	out.NamespaceID = namespace
	out.Fingerprint = hex.EncodeToString(h.Sum(nil))
	out.Bytes = s.bytes
	out.ObservedAt = time.Now().Unix()
	return out, nil
}
