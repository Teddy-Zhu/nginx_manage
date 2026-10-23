package firewall

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// NFTA_SET_HANDLE from the Linux UAPI is absent from the current unix bindings.
const nftaSetHandle = 16

type NFTSetElement struct {
	Key []byte
	End bool
}
type NFTAddressSet struct {
	Name     string
	ID       uint32
	KeyLen   uint32
	Elements []NFTSetElement
}
type addressInterval struct{ First, Last netip.Addr }

func sourceIntervals(sources []string, family string) []addressInterval {
	ranges := []addressInterval{}
	for _, source := range sources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix.Addr().Is4() != (family == "ipv4") {
			continue
		}
		first := prefix.Masked().Addr()
		last := slices.Clone(first.AsSlice())
		mask := net.CIDRMask(prefix.Bits(), first.BitLen())
		for i := range last {
			last[i] |= ^mask[i]
		}
		end, _ := netip.AddrFromSlice(last)
		ranges = append(ranges, addressInterval{first, end})
	}
	slices.SortFunc(ranges, func(a, b addressInterval) int { return a.First.Compare(b.First) })
	out := make([]addressInterval, 0, len(ranges))
	for _, r := range ranges {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Last.Compare(r.First) >= 0 || last.Last.Next() == r.First {
				if r.Last.Compare(last.Last) > 0 {
					last.Last = r.Last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
func (program *NFTProgram) sourceSet(sources []string, family string) (*NFTAddressSet, bool) {
	ranges := sourceIntervals(sources, family)
	if len(ranges) == 0 {
		return nil, false
	}
	if len(ranges) == 1 && ranges[0].First.IsUnspecified() && !ranges[0].Last.Next().IsValid() {
		return nil, true
	}
	keyLen := uint32(4)
	label := "np4_"
	if family == "ipv6" {
		keyLen = 16
		label = "np6_"
	}
	var identity []byte
	for _, r := range ranges {
		identity = append(identity, r.First.AsSlice()...)
		identity = append(identity, r.Last.AsSlice()...)
	}
	name := label + secure.Hash(identity)[:24]
	for i := range program.Sets {
		if program.Sets[i].Name == name {
			return &program.Sets[i], true
		}
	}
	set := NFTAddressSet{Name: name, ID: uint32(len(program.Sets) + 1), KeyLen: keyLen, Elements: []NFTSetElement{}}
	for _, r := range ranges {
		set.Elements = append(set.Elements, NFTSetElement{Key: r.First.AsSlice()})
		next := r.Last.Next()
		if !next.IsValid() {
			set.Elements = append([]NFTSetElement{{Key: make([]byte, keyLen), End: true}}, set.Elements...)
		} else {
			set.Elements = append(set.Elements, NFTSetElement{Key: next.AsSlice(), End: true})
		}
	}
	program.Sets = append(program.Sets, set)
	return &program.Sets[len(program.Sets)-1], true
}
func mergeNFTSets(base, other *NFTProgram) {
	ids := map[string]uint32{}
	for _, set := range base.Sets {
		ids[set.Name] = set.ID
	}
	for _, set := range other.Sets {
		if _, ok := ids[set.Name]; !ok {
			set.ID = uint32(len(base.Sets) + 1)
			base.Sets = append(base.Sets, set)
			ids[set.Name] = set.ID
		}
	}
	for _, rule := range other.Rules {
		for _, expression := range rule.Exprs {
			if lookup, ok := expression.(*expr.Lookup); ok {
				lookup.SetID = ids[lookup.SetName]
			}
		}
	}
}
func nftSetAttrs(table string, set NFTAddressSet) ([]netlink.Attribute, error) {
	if set.ID == 0 || set.KeyLen != 4 && set.KeyLen != 16 || len(set.Elements) == 0 || len(set.Elements) > 2*MaxPolicyPrefixes {
		return nil, errors.New("invalid address set")
	}
	keyType := uint32(7)
	if set.KeyLen == 16 {
		keyType = 8
	}
	if len(set.Name) != 28 || set.Name[:4] != map[bool]string{true: "np4_", false: "np6_"}[set.KeyLen == 4] {
		return nil, errors.New("invalid address set name")
	}
	if _, err := hex.DecodeString(set.Name[4:]); err != nil {
		return nil, err
	}
	size, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_SET_DESC_SIZE, Data: binary.BigEndian.AppendUint32(nil, uint32(len(set.Elements)))}})
	if err != nil {
		return nil, err
	}
	return []netlink.Attribute{{Type: unix.NFTA_SET_TABLE, Data: []byte(table + "\x00")}, {Type: unix.NFTA_SET_NAME, Data: []byte(set.Name + "\x00")}, {Type: unix.NFTA_SET_FLAGS, Data: binary.BigEndian.AppendUint32(nil, unix.NFT_SET_INTERVAL)}, {Type: unix.NFTA_SET_KEY_TYPE, Data: binary.BigEndian.AppendUint32(nil, keyType)}, {Type: unix.NFTA_SET_KEY_LEN, Data: binary.BigEndian.AppendUint32(nil, set.KeyLen)}, {Type: unix.NFTA_SET_ID, Data: binary.BigEndian.AppendUint32(nil, set.ID)}, {Type: unix.NFTA_SET_DESC | netlink.Nested, Data: size}}, nil
}
func nftSetElementAttrs(element NFTSetElement, keyLen uint32) ([]netlink.Attribute, error) {
	if len(element.Key) != int(keyLen) {
		return nil, errors.New("invalid address set element")
	}
	key, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_DATA_VALUE, Data: element.Key}})
	if err != nil {
		return nil, err
	}
	attrs := []netlink.Attribute{{Type: unix.NFTA_SET_ELEM_KEY | netlink.Nested, Data: key}}
	if element.End {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_SET_ELEM_FLAGS, Data: binary.BigEndian.AppendUint32(nil, unix.NFT_SET_ELEM_INTERVAL_END)})
	}
	return attrs, nil
}

// VerifyNFTSet proves the set's type and rejects dynamic, expiring or mapped data.
func VerifyNFTSet(set NFTAddressSet, attrs map[uint16]netlink.Attribute) error {
	expected, err := nftSetAttrs(NFTHostTable, set)
	if err != nil {
		return err
	}
	wanted := map[uint16]netlink.Attribute{}
	for _, a := range expected {
		wanted[a.Type&^uint16(netlink.Nested)] = a
	}
	for kind, a := range attrs {
		switch kind {
		case unix.NFTA_SET_ID:
			if len(a.Data) != 4 || binary.BigEndian.Uint32(a.Data) == 0 {
				return errors.New("invalid kernel set id")
			}
		case unix.NFTA_SET_POLICY:
			if len(a.Data) != 4 || binary.BigEndian.Uint32(a.Data) != 0 {
				return errors.New("unexpected address set policy")
			}
		case nftaSetHandle:
			if len(a.Data) != 8 || binary.BigEndian.Uint64(a.Data) == 0 {
				return errors.New("invalid address set handle")
			}
		case unix.NFTA_SET_DESC:
			fields, e := netlink.UnmarshalAttributes(a.Data)
			if e != nil || len(fields) != 1 || fields[0].Type != unix.NFTA_SET_DESC_SIZE || len(fields[0].Data) != 4 || binary.BigEndian.Uint32(fields[0].Data) != uint32(len(set.Elements)) {
				return errors.New("unexpected address set description")
			}
		default:
			want, ok := wanted[kind]
			if !ok || a.Type != want.Type || !bytes.Equal(a.Data, want.Data) {
				return errors.New("unexpected address set attribute")
			}
		}
	}
	for _, kind := range []uint16{unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME, unix.NFTA_SET_FLAGS, unix.NFTA_SET_KEY_TYPE, unix.NFTA_SET_KEY_LEN} {
		if _, ok := attrs[kind]; !ok {
			return errors.New("incomplete address set")
		}
	}
	return nil
}
func NFTSetElementKey(setName string, key []byte, end bool) string {
	label := byte(0)
	if end {
		label = 1
	}
	return setName + "\x00" + string(key) + string([]byte{label})
}
func VerifyNFTSetElements(set NFTAddressSet, raw []byte, remaining map[string]bool) error {
	elements, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return err
	}
	for _, element := range elements {
		if element.Type&^uint16(netlink.Nested) != unix.NFTA_LIST_ELEM {
			return errors.New("unknown address set element")
		}
		fields, err := netlink.UnmarshalAttributes(element.Data)
		if err != nil {
			return err
		}
		var key []byte
		end := false
		seen := map[uint16]bool{}
		for _, field := range fields {
			kind := field.Type &^ uint16(netlink.Nested)
			if seen[kind] {
				return errors.New("duplicate address set element field")
			}
			seen[kind] = true
			switch kind {
			case unix.NFTA_SET_ELEM_KEY:
				values, e := netlink.UnmarshalAttributes(field.Data)
				if e != nil || len(values) != 1 || values[0].Type != unix.NFTA_DATA_VALUE || len(values[0].Data) != int(set.KeyLen) {
					return errors.New("invalid address set key")
				}
				key = values[0].Data
			case unix.NFTA_SET_ELEM_FLAGS:
				if field.Type != unix.NFTA_SET_ELEM_FLAGS || len(field.Data) != 4 || binary.BigEndian.Uint32(field.Data) != unix.NFT_SET_ELEM_INTERVAL_END {
					return errors.New("unexpected address set flags")
				}
				end = true
			default:
				return errors.New("unexpected address set element data")
			}
		}
		identity := NFTSetElementKey(set.Name, key, end)
		if key == nil || !remaining[identity] {
			return errors.New("address set membership differs from compiled snapshot")
		}
		delete(remaining, identity)
	}
	return nil
}
