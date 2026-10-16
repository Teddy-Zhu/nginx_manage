package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
)

const NFTBatchBytes = 8 << 20

// NFTCreateBatch is a serialization result, never an execution authority. The
// executor must first durably record its independent intent/recovery material,
// recheck namespace/ownership and prove completion after sending this batch.
type NFTCreateBatch struct {
	Wire     []byte
	Hash     string
	Messages int
}

// PrepareNFTCreate encodes only exclusive creation of the fixed table. There
// is deliberately no flush, delete, takeover, replacement or send operation.
// The batch generation precondition prevents a concurrent kernel policy change
// from being silently incorporated into a previously inspected baseline.
func PrepareNFTCreate(program *NFTProgram, baseline KernelView) (NFTCreateBatch, error) {
	var out NFTCreateBatch
	if !baseline.Available || baseline.Generation == 0 || baseline.TableExists || len(baseline.NamespaceID) != 64 || len(baseline.Fingerprint) != 64 {
		return out, fault.Unavailable("仅能为已核对且目标表不存在的内核快照生成新建事务")
	}
	if program == nil || program.Table == nil || program.Chain == nil || program.Table.Name != NFTHostTable || byte(program.Table.Family) != unix.NFPROTO_INET || program.Chain.Table != program.Table || program.Chain.Name != NFTHostChain || program.Chain.Type != "filter" || program.Chain.Device != "" || program.Table.Flags != 0 || program.Chain.Hooknum == nil || uint32(*program.Chain.Hooknum) != unix.NF_INET_LOCAL_IN || program.Chain.Priority == nil || int(*program.Chain.Priority) != NFTHostPriority || program.Chain.Policy == nil || uint32(*program.Chain.Policy) != uint32(expr.VerdictAccept) || len(program.Rules) < 2 || len(program.Rules) > MaxEntries {
		return out, errors.New("invalid fixed nftables program")
	}
	appendMessage := func(kind uint16, flags netlink.HeaderFlags, family byte, resource uint16, attrs []netlink.Attribute) error {
		data, e := netlink.MarshalAttributes(attrs)
		if e != nil {
			return e
		}
		header := []byte{family, unix.NFNETLINK_V0, byte(resource >> 8), byte(resource)}
		data = append(header, data...)
		message := netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(data)), Type: netlink.HeaderType(kind), Flags: flags, Sequence: uint32(out.Messages + 1)}, Data: data}
		raw, e := message.MarshalBinary()
		if e != nil {
			return e
		}
		if len(out.Wire)+len(raw) > NFTBatchBytes {
			return fault.Invalid("防火墙事务序列化超过 8 MiB")
		}
		out.Wire = append(out.Wire, raw...)
		out.Messages++
		return nil
	}
	begin := []netlink.Attribute{{Type: unix.NFNL_BATCH_GENID, Data: binary.BigEndian.AppendUint32(nil, baseline.Generation)}}
	if e := appendMessage(unix.NFNL_MSG_BATCH_BEGIN, netlink.Request, unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, begin); e != nil {
		return NFTCreateBatch{}, e
	}
	request := netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl
	// NFTA_TABLE_USERDATA is attribute 6 in Linux UAPI nf_tables.h. Its marker
	// identifies our format; only a separate root registration can prove owner.
	table := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(NFTHostTable + "\x00")}, {Type: unix.NFTA_TABLE_FLAGS, Data: binary.BigEndian.AppendUint32(nil, 0)}, {Type: 6, Data: []byte("nginxpanel:direct:v1")}}
	if e := appendMessage(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE, request, unix.NFPROTO_INET, 0, table); e != nil {
		return NFTCreateBatch{}, e
	}
	hook, e := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_HOOK_HOOKNUM, Data: binary.BigEndian.AppendUint32(nil, unix.NF_INET_LOCAL_IN)}, {Type: unix.NFTA_HOOK_PRIORITY, Data: binary.BigEndian.AppendUint32(nil, uint32(NFTHostPriority))}})
	if e != nil {
		return NFTCreateBatch{}, e
	}
	chain := []netlink.Attribute{{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(NFTHostTable + "\x00")}, {Type: unix.NFTA_CHAIN_NAME, Data: []byte(NFTHostChain + "\x00")}, {Type: unix.NFTA_CHAIN_HOOK | netlink.Nested, Data: hook}, {Type: unix.NFTA_CHAIN_TYPE, Data: []byte("filter\x00")}, {Type: unix.NFTA_CHAIN_POLICY, Data: binary.BigEndian.AppendUint32(nil, uint32(expr.VerdictAccept))}}
	if e = appendMessage(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWCHAIN, request, unix.NFPROTO_INET, 0, chain); e != nil {
		return NFTCreateBatch{}, e
	}
	for _, rule := range program.Rules {
		if rule == nil || rule.Table != program.Table || rule.Chain != program.Chain || rule.Handle != 0 || rule.Position != 0 || rule.Flags != 0 {
			return NFTCreateBatch{}, errors.New("invalid new nftables rule")
		}
		expressions := make([]netlink.Attribute, 0, len(rule.Exprs))
		for _, expression := range rule.Exprs {
			raw, e := expr.Marshal(unix.NFPROTO_INET, expression)
			if e != nil {
				return NFTCreateBatch{}, e
			}
			expressions = append(expressions, netlink.Attribute{Type: unix.NFTA_LIST_ELEM | netlink.Nested, Data: raw})
		}
		encoded, e := netlink.MarshalAttributes(expressions)
		if e != nil {
			return NFTCreateBatch{}, e
		}
		attrs := []netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(NFTHostTable + "\x00")}, {Type: unix.NFTA_RULE_CHAIN, Data: []byte(NFTHostChain + "\x00")}, {Type: unix.NFTA_RULE_EXPRESSIONS | netlink.Nested, Data: encoded}, {Type: unix.NFTA_RULE_USERDATA, Data: rule.UserData}}
		if e = appendMessage(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Append, unix.NFPROTO_INET, 0, attrs); e != nil {
			return NFTCreateBatch{}, e
		}
	}
	if e = appendMessage(unix.NFNL_MSG_BATCH_END, netlink.Request, unix.NFPROTO_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, nil); e != nil {
		return NFTCreateBatch{}, e
	}
	h := sha256.New()
	frame := func(raw []byte) { h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw)))); h.Write(raw) }
	frame([]byte("nginxpanel:nft-create:v1"))
	frame([]byte(baseline.NamespaceID))
	frame([]byte(baseline.Fingerprint))
	frame(out.Wire)
	out.Hash = hex.EncodeToString(h.Sum(nil))
	return out, nil
}
