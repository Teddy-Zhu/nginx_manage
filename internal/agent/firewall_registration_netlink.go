package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
)

const nftRegistrationPrefix = "nginxpanel:registration:v1:"

// Registration has no chains, hooks, rules or executable input. Its only
// mutations are exclusive creation and deletion of one proved-empty table.
// Policy application must use a separate reachability/recovery executor.
type nftRegistrationBatch struct {
	wire    []byte
	hash    string
	headers [3][]byte
}

func prepareNFTRegistration(baseline firewall.KernelView, owner string, remove bool) (nftRegistrationBatch, error) {
	var out nftRegistrationBatch
	if !baseline.Available || baseline.Generation == 0 || len(baseline.NamespaceID) != 64 || len(baseline.Fingerprint) != 64 || baseline.TableExists != remove || !validID(owner) {
		return out, errors.New("防火墙登记事务的基线无效")
	}
	kind := uint16(unix.NFT_MSG_NEWTABLE)
	flags := netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl
	attrs := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(firewall.NFTHostTable + "\x00")}}
	if remove {
		kind = unix.NFT_MSG_DELTABLE
		flags = netlink.Request | netlink.Acknowledge
	} else {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: binary.BigEndian.AppendUint32(nil, 0)}, netlink.Attribute{Type: 6, Data: []byte(nftRegistrationPrefix + owner)})
	}
	messages := []struct {
		kind     uint16
		flags    netlink.HeaderFlags
		family   byte
		resource uint16
		attrs    []netlink.Attribute
	}{
		{unix.NFNL_MSG_BATCH_BEGIN, netlink.Request, unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, []netlink.Attribute{{Type: unix.NFNL_BATCH_GENID, Data: binary.BigEndian.AppendUint32(nil, baseline.Generation)}}},
		{unix.NFNL_SUBSYS_NFTABLES<<8 | kind, flags, unix.NFPROTO_INET, 0, attrs},
		{unix.NFNL_MSG_BATCH_END, netlink.Request, unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, nil},
	}
	for i, m := range messages {
		data, err := netlink.MarshalAttributes(m.attrs)
		if err != nil {
			return out, err
		}
		data = append([]byte{m.family, unix.NFNETLINK_V0, byte(m.resource >> 8), byte(m.resource)}, data...)
		raw, err := (netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(data)), Type: netlink.HeaderType(m.kind), Flags: m.flags, Sequence: uint32(i + 1)}, Data: data}).MarshalBinary()
		if err != nil {
			return out, err
		}
		out.headers[i] = append([]byte(nil), raw[:unix.NLMSG_HDRLEN]...)
		out.wire = append(out.wire, raw...)
	}
	if len(out.wire) > 1024 {
		return nftRegistrationBatch{}, errors.New("防火墙登记事务超限")
	}
	h := sha256.New()
	nftFrame(h, []byte("nginxpanel:nft-registration:v1"))
	nftFrame(h, []byte(baseline.NamespaceID))
	nftFrame(h, []byte(baseline.Fingerprint))
	nftFrame(h, out.wire)
	out.hash = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

func verifyNFTRegistrationTable(attrs map[uint16]netlink.Attribute, owner string) error {
	// UAPI table userdata is attribute 6. Unknown attributes, flags, users or
	// children make the table unsuitable for this empty-registration executor.
	if len(attrs) != 5 {
		return errors.New("登记表包含未预期的内核属性")
	}
	name, err := nftString(attrs[unix.NFTA_TABLE_NAME])
	if err != nil || name != firewall.NFTHostTable {
		return errors.New("登记表名称不匹配")
	}
	for _, kind := range []uint16{unix.NFTA_TABLE_FLAGS, unix.NFTA_TABLE_USE} {
		a, ok := attrs[kind]
		if !ok || a.Type != kind || len(a.Data) != 4 || binary.BigEndian.Uint32(a.Data) != 0 {
			return errors.New("登记表包含标志或使用者")
		}
	}
	handle, ok := attrs[unix.NFTA_TABLE_HANDLE]
	if !ok || handle.Type != unix.NFTA_TABLE_HANDLE || len(handle.Data) != 8 || binary.BigEndian.Uint64(handle.Data) == 0 {
		return errors.New("登记表句柄无效")
	}
	marker, ok := attrs[6]
	if !ok || marker.Type != 6 || !bytes.Equal(marker.Data, []byte(nftRegistrationPrefix+owner)) {
		return errors.New("登记表标记与独立 root 意图不匹配")
	}
	return nil
}

func snapshotNFTRegistration(ctx context.Context, owner string) (firewall.KernelView, error) {
	view, err := snapshotNFTKernelInspect(ctx, func(attrs map[uint16]netlink.Attribute) error { return verifyNFTRegistrationTable(attrs, owner) })
	if err == nil && (view.Chains != 0 || view.Rules != 0) {
		err = errors.New("登记表包含链或规则，禁止空表执行器修改")
	}
	return view, err
}

// A dedicated fixed-table writer reuses only socket setup and the poll helper;
// nftReadSocket.send remains GET-only. There is one bounded datagram, no batch
// splitting, automatic retries, flush, shell, or general netlink write endpoint.
func submitNFTRegistration(ctx context.Context, batch nftRegistrationBatch) error {
	if len(batch.wire) == 0 || len(batch.wire) > 1024 {
		return errors.New("防火墙登记事务大小无效")
	}
	s, err := openNFTRead()
	if err != nil {
		return err
	}
	defer s.close()
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = unix.Sendto(s.fd, batch.wire, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	// A GETGEN on the same socket is a barrier after the complete batch. Consume
	// every preceding ACK, including a commit failure attributed to BEGIN;
	// one successful NEWTABLE/DELTABLE ACK alone does not certify commit.
	barrier := netlink.Message{Header: netlink.Header{Length: unix.NLMSG_HDRLEN + 4, Type: unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETGEN, Flags: netlink.Request, Sequence: 4}, Data: []byte{unix.NFPROTO_UNSPEC, unix.NFNETLINK_V0, 0, 0}}
	barrierWire, err := barrier.MarshalBinary()
	if err != nil {
		return err
	}
	if err = s.send(ctx, barrier); err != nil {
		return err
	}
	ack, done, received := false, false, 0
	var rejected error
	for !done {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, _, flags, sender, e := unix.Recvmsg(s.fd, s.buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.EAGAIN) {
			if e = s.wait(ctx, unix.POLLIN); e != nil {
				return e
			}
			continue
		}
		if e != nil {
			return e
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		received += n
		if !ok || from.Pid != 0 || from.Groups != 0 || n == 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || received > 64<<10 {
			return errors.New("登记事务回执来源、边界或预算无效")
		}
		raw := s.buffer[:n]
		for len(raw) > 0 {
			if len(raw) < unix.NLMSG_HDRLEN {
				return errors.New("登记事务回执头不完整")
			}
			length := int(binary.NativeEndian.Uint32(raw[:4]))
			aligned := (length + 3) &^ 3
			if length < unix.NLMSG_HDRLEN || aligned > len(raw) {
				return errors.New("登记事务回执边界无效")
			}
			kind := netlink.HeaderType(binary.NativeEndian.Uint16(raw[4:6]))
			sequence, pid := binary.NativeEndian.Uint32(raw[8:12]), binary.NativeEndian.Uint32(raw[12:16])
			data := raw[unix.NLMSG_HDRLEN:length]
			messageFlags := netlink.HeaderFlags(binary.NativeEndian.Uint16(raw[6:8]))
			raw = raw[aligned:]
			if done || pid != 0 && pid != s.pid || sequence < 1 || sequence > 4 || messageFlags&netlink.DumpInterrupted != 0 {
				return errors.New("登记事务回执序列无效")
			}
			if kind == netlink.Error {
				if len(data) < 4+unix.NLMSG_HDRLEN {
					return errors.New("登记事务错误回执不完整")
				}
				code := int32(binary.NativeEndian.Uint32(data[:4]))
				expected := barrierWire[:unix.NLMSG_HDRLEN]
				if sequence <= 3 {
					expected = batch.headers[sequence-1]
				}
				if !bytes.Equal(data[4:4+unix.NLMSG_HDRLEN], expected) || code > 0 {
					return errors.New("登记事务原请求回执无效")
				}
				if code < 0 {
					rejected = syscall.Errno(-int64(code))
					if sequence == 4 {
						done = true
					}
					continue
				}
				if sequence != 2 || ack {
					return errors.New("登记事务确认重复或无效")
				}
				ack = true
				continue
			}
			if sequence != 4 || kind != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWGEN) || len(data) < 4 || data[0] != unix.NFPROTO_UNSPEC || data[1] != unix.NFNETLINK_V0 {
				return errors.New("登记事务屏障无效")
			}
			attrs, e := nftAttributes(netlink.Message{Header: netlink.Header{Type: kind}, Data: data})
			if e != nil {
				return e
			}
			generation, ok := attrs[unix.NFTA_GEN_ID]
			if !ok || len(generation.Data) != 4 || binary.BigEndian.Uint32(generation.Data) == 0 {
				return errors.New("登记事务屏障缺少代次")
			}
			done = true
		}
	}
	if rejected != nil {
		return rejected
	}
	if !ack {
		return errors.New("登记事务缺少操作回执")
	}
	return nil
}
