package firewall

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// This matcher is deliberately driven by the compiler's exact expression tree.
// It never decodes with a library which can silently skip unknown expressions.
// Unknown names, attributes, duplicates, flags or changed bytes fail the proof.
// Only the documented BOOL default and TCP RST's omitted zero ICMP code differ
// between our encoding and supported kernels' dumps.
type nftShape map[uint16]nftShape

// Linux UAPI enum nft_bitwise_attributes assigns OP = 6. The pinned x/sys
// exports the preceding fields but does not export NFTA_BITWISE_OP.
const nftaBitwiseOp uint16 = 6

func nftAttrMap(raw []byte) (map[uint16]netlink.Attribute, error) {
	attrs, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return nil, err
	}
	out := map[uint16]netlink.Attribute{}
	for _, a := range attrs {
		kind := a.Type &^ uint16(netlink.Nested)
		if kind == 0 || kind&netlink.NetByteOrder != 0 {
			return nil, errors.New("unsupported nftables attribute flags")
		}
		if _, exists := out[kind]; exists {
			return nil, errors.New("duplicate nftables expression attribute")
		}
		out[kind] = a
	}
	return out, nil
}

func nftAttrEqual(want, got map[uint16]netlink.Attribute, shape nftShape) bool {
	if len(want) != len(got) {
		return false
	}
	for kind, expected := range want {
		actual, ok := got[kind]
		if !ok {
			return false
		}
		nested, container := shape[kind]
		if !container {
			if expected.Type != kind || actual.Type != kind || !bytes.Equal(expected.Data, actual.Data) {
				return false
			}
			continue
		}
		a, err := nftAttrMap(expected.Data)
		if err != nil {
			return false
		}
		b, err := nftAttrMap(actual.Data)
		if err != nil || !nftAttrEqual(a, b, nested) {
			return false
		}
	}
	return true
}

func nftExpressionEqual(expected, actual []byte) bool {
	want, err := nftAttrMap(expected)
	if err != nil {
		return false
	}
	got, err := nftAttrMap(actual)
	if err != nil || len(want) != 2 || len(got) != 2 {
		return false
	}
	name, ok := want[unix.NFTA_EXPR_NAME]
	found, present := got[unix.NFTA_EXPR_NAME]
	if !ok || !present || name.Type != unix.NFTA_EXPR_NAME || found.Type != unix.NFTA_EXPR_NAME || !bytes.Equal(name.Data, found.Data) {
		return false
	}
	wantedData, ok := want[unix.NFTA_EXPR_DATA]
	actualData, present := got[unix.NFTA_EXPR_DATA]
	if !ok || !present {
		return false
	}
	wantFields, err := nftAttrMap(wantedData.Data)
	if err != nil {
		return false
	}
	gotFields, err := nftAttrMap(actualData.Data)
	if err != nil {
		return false
	}
	dataValue := nftShape{}
	var shape nftShape
	switch string(name.Data) {
	case "meta\x00", "ct\x00", "payload\x00":
		shape = nftShape{}
	case "cmp\x00":
		shape = nftShape{unix.NFTA_CMP_DATA: dataValue}
	case "bitwise\x00":
		shape = nftShape{unix.NFTA_BITWISE_MASK: dataValue, unix.NFTA_BITWISE_XOR: dataValue}
		if op, ok := gotFields[nftaBitwiseOp]; ok {
			if op.Type != nftaBitwiseOp || len(op.Data) != 4 || binary.BigEndian.Uint32(op.Data) != unix.NFT_BITWISE_BOOL {
				return false
			}
			delete(gotFields, nftaBitwiseOp)
		}
	case "range\x00":
		shape = nftShape{unix.NFTA_RANGE_FROM_DATA: dataValue, unix.NFTA_RANGE_TO_DATA: dataValue}
	case "immediate\x00":
		shape = nftShape{unix.NFTA_IMMEDIATE_DATA: nftShape{unix.NFTA_DATA_VERDICT: nftShape{}}}
	case "reject\x00":
		shape = nftShape{}
		kind := wantFields[unix.NFTA_REJECT_TYPE]
		if len(kind.Data) == 4 && binary.BigEndian.Uint32(kind.Data) == unix.NFT_REJECT_TCP_RST {
			code := wantFields[unix.NFTA_REJECT_ICMP_CODE]
			if !bytes.Equal(code.Data, []byte{0}) {
				return false
			}
			delete(wantFields, unix.NFTA_REJECT_ICMP_CODE)
			if code, exists := gotFields[unix.NFTA_REJECT_ICMP_CODE]; exists {
				if code.Type != unix.NFTA_REJECT_ICMP_CODE || !bytes.Equal(code.Data, []byte{0}) {
					return false
				}
				delete(gotFields, unix.NFTA_REJECT_ICMP_CODE)
			}
		}
	default:
		return false
	}
	return nftAttrEqual(wantFields, gotFields, shape)
}

func VerifyNFTExpressions(ruleExpressions []expr.Any, raw []byte) error {
	elements, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return err
	}
	if len(elements) != len(ruleExpressions) {
		return errors.New("nftables expression count changed")
	}
	for i, element := range elements {
		if element.Type&^uint16(netlink.Nested) != unix.NFTA_LIST_ELEM {
			return errors.New("unknown nftables expression element")
		}
		expected, err := expr.Marshal(unix.NFPROTO_INET, ruleExpressions[i])
		if err != nil {
			return err
		}
		if !nftExpressionEqual(expected, element.Data) {
			return errors.New("nftables expression differs from compiled program")
		}
	}
	return nil
}
