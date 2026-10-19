package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
)

func nftUint32(attrs map[uint16]netlink.Attribute, kind uint16, want uint32) bool {
	a, ok := attrs[kind]
	return ok && a.Type == kind && len(a.Data) == 4 && binary.BigEndian.Uint32(a.Data) == want
}
func nftHandle(attrs map[uint16]netlink.Attribute, kind uint16) (uint64, bool) {
	a, ok := attrs[kind]
	if !ok || a.Type != kind || len(a.Data) != 8 {
		return 0, false
	}
	value := binary.BigEndian.Uint64(a.Data)
	return value, value != 0
}
func nftBytes(attrs map[uint16]netlink.Attribute, kind uint16, expected []byte) bool {
	a, ok := attrs[kind]
	return ok && a.Type == kind && bytes.Equal(a.Data, expected)
}
func nftNestedMap(raw []byte, padding uint16) (map[uint16]netlink.Attribute, error) {
	list, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return nil, err
	}
	out := map[uint16]netlink.Attribute{}
	for _, a := range list {
		kind := a.Type &^ uint16(netlink.Nested)
		if kind == padding && padding != 0 {
			if a.Type != padding || len(bytes.Trim(a.Data, "\x00")) != 0 {
				return nil, errors.New("invalid nftables nested padding")
			}
			continue
		}
		if kind == 0 || kind&netlink.NetByteOrder != 0 {
			return nil, errors.New("unsupported nftables nested attribute")
		}
		if _, duplicate := out[kind]; duplicate {
			return nil, errors.New("duplicate nftables nested attribute")
		}
		out[kind] = a
	}
	return out, nil
}

// Prove the entire fixed table against a root-compiled program, preserving rule
// order. No expression, attribute or object is silently dropped during proof.
// Handles remain in the returned fingerprint to detect later replacement, but
// semantic matching also works after an interrupted first submission/reboot.
func snapshotNFTProgram(ctx context.Context, program *firewall.NFTProgram, marker string) (firewall.KernelView, error) {
	return snapshotNFTTargetProgram(ctx, firewall.NFTPortInput, program, marker)
}
func snapshotNFTTargetProgram(ctx context.Context, target firewall.NFTTarget, program *firewall.NFTProgram, marker string) (firewall.KernelView, error) {
	layout, err := target.Layout()
	if err != nil {
		return firewall.KernelView{}, err
	}
	if program != nil && (program.Table == nil || program.Chain == nil || program.Table.Name != layout.Table || program.Chain.Table != program.Table || program.Chain.Name != layout.Chain || program.Chain.Priority == nil || int(*program.Chain.Priority) != layout.Priority) {
		return firewall.KernelView{}, errors.New("受管表编译目标与读取目标不匹配")
	}
	chains, rules := 0, 0
	handles := map[uint64]bool{}
	var previous uint64
	expectedRules := 0
	if program != nil {
		expectedRules = len(program.Rules)
	}
	view, err := snapshotNFTTargetInspect(ctx, target, func(kind uint16, attrs map[uint16]netlink.Attribute) error {
		switch kind {
		case unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE:
			use := uint32(0)
			if program != nil {
				use = 1
			}
			_, validHandle := nftHandle(attrs, nftaTableHandle)
			if len(attrs) != 5 || !validHandle || !nftBytes(attrs, unix.NFTA_TABLE_NAME, []byte(layout.Table+"\x00")) || !nftUint32(attrs, unix.NFTA_TABLE_FLAGS, 0) || !nftUint32(attrs, unix.NFTA_TABLE_USE, use) || !nftBytes(attrs, 6, []byte(marker)) {
				return errors.New("受管表与独立登记或编译结果不匹配")
			}
		case unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN:
			chains++
			if program == nil || chains != 1 {
				return errors.New("受管表包含未预期的链")
			}
			_, validHandle := nftHandle(attrs, unix.NFTA_CHAIN_HANDLE)
			if !validHandle || !nftBytes(attrs, unix.NFTA_CHAIN_TABLE, []byte(layout.Table+"\x00")) || !nftBytes(attrs, unix.NFTA_CHAIN_NAME, []byte(layout.Chain+"\x00")) || !nftBytes(attrs, unix.NFTA_CHAIN_TYPE, []byte("filter\x00")) || !nftUint32(attrs, unix.NFTA_CHAIN_POLICY, uint32(expr.VerdictAccept)) || !nftUint32(attrs, nftaChainFlags, 1 /* NFT_CHAIN_BASE, Linux UAPI */) || !nftUint32(attrs, unix.NFTA_CHAIN_USE, uint32(expectedRules)) {
				return errors.New("受管基础链的结构、策略或引用数变化")
			}
			hook, ok := attrs[unix.NFTA_CHAIN_HOOK]
			if !ok || hook.Type&^uint16(netlink.Nested) != unix.NFTA_CHAIN_HOOK {
				return errors.New("受管基础链 hook 无效")
			}
			hookAttrs, err := nftNestedMap(hook.Data, 0)
			if err != nil || len(hookAttrs) != 2 || !nftUint32(hookAttrs, unix.NFTA_HOOK_HOOKNUM, unix.NF_INET_LOCAL_IN) || !nftUint32(hookAttrs, unix.NFTA_HOOK_PRIORITY, uint32(int32(layout.Priority))) {
				return errors.New("受管基础链 hook 或优先级变化")
			}
			count := 8
			if counters, ok := attrs[unix.NFTA_CHAIN_COUNTERS]; ok {
				count++
				if counters.Type&^uint16(netlink.Nested) != unix.NFTA_CHAIN_COUNTERS {
					return errors.New("未知基础链计数属性")
				}
				fields, err := nftNestedMap(counters.Data, unix.NFTA_COUNTER_PAD)
				if err != nil || len(fields) != 2 || !nftBytes(fields, unix.NFTA_COUNTER_BYTES, make([]byte, 8)) || !nftBytes(fields, unix.NFTA_COUNTER_PACKETS, make([]byte, 8)) {
					return errors.New("未知基础链计数结构")
				}
			}
			if len(attrs) != count {
				return errors.New("受管基础链包含未知属性")
			}
		case unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE:
			if program == nil || rules >= expectedRules || chains != 1 {
				return errors.New("受管表包含未预期的规则")
			}
			handle, ok := nftHandle(attrs, unix.NFTA_RULE_HANDLE)
			if !ok || handles[handle] || !nftBytes(attrs, unix.NFTA_RULE_TABLE, []byte(layout.Table+"\x00")) || !nftBytes(attrs, unix.NFTA_RULE_CHAIN, []byte(layout.Chain+"\x00")) || !nftBytes(attrs, unix.NFTA_RULE_USERDATA, program.Rules[rules].UserData) {
				return errors.New("受管规则的身份、链或标记变化")
			}
			count := 5
			if position, exists := attrs[unix.NFTA_RULE_POSITION]; exists {
				count++
				if position.Type != unix.NFTA_RULE_POSITION || len(position.Data) != 8 || binary.BigEndian.Uint64(position.Data) != previous {
					return errors.New("受管规则顺序变化")
				}
			}
			expressions, exists := attrs[unix.NFTA_RULE_EXPRESSIONS]
			if len(attrs) != count || !exists || expressions.Type&^uint16(netlink.Nested) != unix.NFTA_RULE_EXPRESSIONS {
				return errors.New("受管规则包含未知属性")
			}
			if err := firewall.VerifyNFTExpressions(program.Rules[rules].Exprs, expressions.Data); err != nil {
				return err
			}
			handles[handle], previous = true, handle
			rules++
		default:
			return errors.New("受管表包含未预期对象")
		}
		return nil
	})
	if err == nil && view.TableExists && (rules != expectedRules || program != nil && chains != 1 || program == nil && chains != 0) {
		err = errors.New("受管表对象不完整")
	}
	return view, err
}
