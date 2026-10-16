package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
)

// Only root-compiled fixed-table transactions reach this transport. No API
// accepts serialized messages. One atomic datagram is submitted once, after a
// durable intent. Every ACK (including BEGIN commit errors) precedes the same
// socket GETGEN barrier; no individual ACK is treated as commit confirmation.
func submitNFTBatch(ctx context.Context, wire []byte) error {
	if len(wire) == 0 || len(wire) > firewall.NFTBatchBytes {
		return errors.New("防火墙事务大小无效")
	}
	headers := map[uint32][]byte{}
	required := map[uint32]bool{}
	raw := wire
	for len(raw) > 0 {
		if len(raw) < unix.NLMSG_HDRLEN {
			return errors.New("防火墙事务头不完整")
		}
		n := int(binary.NativeEndian.Uint32(raw[:4]))
		aligned := (n + 3) &^ 3
		if n < unix.NLMSG_HDRLEN+4 || aligned > len(raw) {
			return errors.New("防火墙事务边界无效")
		}
		seq := binary.NativeEndian.Uint32(raw[8:12])
		kind := binary.NativeEndian.Uint16(raw[4:6])
		flags := netlink.HeaderFlags(binary.NativeEndian.Uint16(raw[6:8]))
		if seq != uint32(len(headers)+1) || flags&netlink.Request == 0 || binary.NativeEndian.Uint32(raw[12:16]) != 0 || len(headers) >= firewall.MaxEntries+5 {
			return errors.New("防火墙事务序列无效")
		}
		switch kind {
		case unix.NFNL_MSG_BATCH_BEGIN, unix.NFNL_MSG_BATCH_END, unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE, unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELTABLE, unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN, unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE:
		default:
			return errors.New("防火墙事务包含未授权消息类型")
		}
		headers[seq] = append([]byte(nil), raw[:unix.NLMSG_HDRLEN]...)
		if flags&netlink.Acknowledge != 0 {
			required[seq] = true
		}
		raw = raw[aligned:]
	}
	if len(headers) < 3 || binary.NativeEndian.Uint16(headers[1][4:6]) != unix.NFNL_MSG_BATCH_BEGIN || binary.NativeEndian.Uint16(headers[uint32(len(headers))][4:6]) != unix.NFNL_MSG_BATCH_END {
		return errors.New("防火墙事务缺少批边界")
	}
	s, err := openNFTRead()
	if err != nil {
		return err
	}
	defer s.close()
	// CAP_ACK bounds error replies independently of the original expression size.
	// Buffer increases apply only to this socket. A kernel that cannot reserve
	// the bounded buffers is rejected before submission, without changing sysctls.
	if err = unix.SetsockoptInt(s.fd, unix.SOL_NETLINK, unix.NETLINK_CAP_ACK, 1); err != nil {
		return err
	}
	receiveSize := max(64<<10, len(headers)*1024)
	if err = unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, receiveSize); err != nil {
		return err
	}
	if err = unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, len(wire)+4096); err != nil {
		return err
	}
	rcv, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return err
	}
	snd, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		return err
	}
	if rcv < receiveSize || snd < len(wire)+32 {
		return errors.New("防火墙事务 socket 缓冲不足")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = unix.Sendto(s.fd, wire, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	sequence := uint32(len(headers) + 1)
	barrier := netlink.Message{Header: netlink.Header{Length: unix.NLMSG_HDRLEN + 4, Type: unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETGEN, Flags: netlink.Request, Sequence: sequence}, Data: []byte{unix.NFPROTO_UNSPEC, unix.NFNETLINK_V0, 0, 0}}
	barrierWire, err := barrier.MarshalBinary()
	if err != nil {
		return err
	}
	headers[sequence] = barrierWire[:unix.NLMSG_HDRLEN]
	if err = s.send(ctx, barrier); err != nil {
		return err
	}
	seen := map[uint32]bool{}
	done, received, messages := false, 0, 0
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
		if !ok || from.Pid != 0 || from.Groups != 0 || n == 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || received > max(64<<10, len(headers)*256) {
			return errors.New("防火墙回执来源、边界或预算无效")
		}
		raw = s.buffer[:n]
		for len(raw) > 0 {
			messages++
			if len(raw) < unix.NLMSG_HDRLEN || messages > len(headers)+2 {
				return errors.New("防火墙回执头或数量无效")
			}
			length := int(binary.NativeEndian.Uint32(raw[:4]))
			aligned := (length + 3) &^ 3
			if length < unix.NLMSG_HDRLEN || aligned > len(raw) {
				return errors.New("防火墙回执边界无效")
			}
			kind := netlink.HeaderType(binary.NativeEndian.Uint16(raw[4:6]))
			seq, pid := binary.NativeEndian.Uint32(raw[8:12]), binary.NativeEndian.Uint32(raw[12:16])
			data := raw[unix.NLMSG_HDRLEN:length]
			replyFlags := netlink.HeaderFlags(binary.NativeEndian.Uint16(raw[6:8]))
			raw = raw[aligned:]
			expected, ok := headers[seq]
			if done || !ok || pid != 0 && pid != s.pid || replyFlags&netlink.DumpInterrupted != 0 {
				return errors.New("防火墙回执序列无效")
			}
			if kind == netlink.Error {
				if seen[seq] || len(data) < 4+unix.NLMSG_HDRLEN || !bytes.Equal(data[4:4+unix.NLMSG_HDRLEN], expected) {
					return errors.New("防火墙原请求回执不匹配")
				}
				seen[seq] = true
				code := int32(binary.NativeEndian.Uint32(data[:4]))
				if code > 0 {
					return errors.New("防火墙错误码无效")
				}
				if code < 0 {
					rejected = syscall.Errno(-int64(code))
					if seq == sequence {
						done = true
					}
					continue
				}
				if !required[seq] {
					return errors.New("未预期的防火墙成功回执")
				}
				continue
			}
			if seq != sequence || kind != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWGEN) || len(data) < 4 || data[0] != unix.NFPROTO_UNSPEC || data[1] != unix.NFNETLINK_V0 {
				return errors.New("防火墙事务屏障无效")
			}
			attrs, e := nftAttributes(netlink.Message{Header: netlink.Header{Type: kind}, Data: data})
			if e != nil {
				return e
			}
			generation, ok := attrs[unix.NFTA_GEN_ID]
			if !ok || len(generation.Data) != 4 || binary.BigEndian.Uint32(generation.Data) == 0 {
				return errors.New("防火墙事务屏障缺少代次")
			}
			done = true
		}
	}
	if rejected != nil {
		return rejected
	}
	for seq := range required {
		if !seen[seq] {
			return errors.New("防火墙事务缺少操作回执")
		}
	}
	return nil
}
