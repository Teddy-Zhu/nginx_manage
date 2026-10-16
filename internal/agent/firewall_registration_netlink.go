package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
)

const nftRegistrationPrefix = "nginxpanel:registration:v1:"

// Registration has no chains, hooks, rules or executable input. Its only
// mutations are exclusive creation and deletion of one proved-empty table.
// Policy application must use a separate reachability/recovery executor.
type nftRegistrationBatch struct {
	wire []byte
	hash string
}

func prepareNFTRegistration(baseline firewall.KernelView, owner string, remove bool) (nftRegistrationBatch, error) {
	return prepareNFTTargetRegistration(firewall.NFTPortInput, baseline, owner, remove)
}

func nftTargetRegistrationMarker(target firewall.NFTTarget, owner string) (string, error) {
	if !validID(owner) {
		return "", errors.New("无效的独立登记所有者")
	}
	switch target {
	case firewall.NFTPortInput:
		return nftRegistrationPrefix + owner, nil
	case firewall.NFTFail2banInput:
		return "nginxpanel:fail2ban:registration:v1:" + owner, nil
	default:
		return "", errors.New("未知独立登记目标")
	}
}

func prepareNFTTargetRegistration(target firewall.NFTTarget, baseline firewall.KernelView, owner string, remove bool) (nftRegistrationBatch, error) {
	var out nftRegistrationBatch
	layout, err := target.Layout()
	if err != nil {
		return out, err
	}
	marker, err := nftTargetRegistrationMarker(target, owner)
	if err != nil {
		return out, err
	}
	if !baseline.Available || baseline.Generation == 0 || len(baseline.NamespaceID) != 64 || len(baseline.Fingerprint) != 64 || baseline.TableExists != remove || baseline.Chains != 0 || baseline.Rules != 0 || !validID(owner) {
		return out, errors.New("防火墙登记事务的基线无效")
	}
	kind := uint16(unix.NFT_MSG_NEWTABLE)
	flags := netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl
	attrs := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(layout.Table + "\x00")}}
	if remove {
		kind = unix.NFT_MSG_DELTABLE
		flags = netlink.Request | netlink.Acknowledge
	} else {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_TABLE_FLAGS, Data: binary.BigEndian.AppendUint32(nil, 0)}, netlink.Attribute{Type: 6, Data: []byte(marker)})
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
	view, err := snapshotNFTKernelInspect(ctx, func(kind uint16, attrs map[uint16]netlink.Attribute) error {
		if kind != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE {
			return errors.New("登记表包含子对象")
		}
		return verifyNFTRegistrationTable(attrs, owner)
	})
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
	return submitNFTBatch(ctx, batch.wire)
}
