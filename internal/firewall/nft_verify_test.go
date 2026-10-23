package firewall

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestVerifyNFTLookupKernelFlags(t *testing.T) {
	lookup := &expr.Lookup{SourceRegister: 1, SetName: "np4_test", SetID: 1}
	expected, err := expr.Marshal(unix.NFPROTO_INET, lookup)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags []byte
		valid bool
	}{
		{"kernel default", []byte{0, 0, 0, 0}, true},
		{"inverted lookup", []byte{0, 0, 0, 1}, false},
		{"malformed flags", []byte{0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields, err := netlink.UnmarshalAttributes(expected)
			if err != nil {
				t.Fatal(err)
			}
			for i := range fields {
				if fields[i].Type&^uint16(netlink.Nested) != unix.NFTA_EXPR_DATA {
					continue
				}
				data, err := netlink.UnmarshalAttributes(fields[i].Data)
				if err != nil {
					t.Fatal(err)
				}
				var actual []netlink.Attribute
				for _, a := range data {
					if a.Type != unix.NFTA_LOOKUP_SET_ID {
						actual = append(actual, a)
					}
				}
				actual = append(actual, netlink.Attribute{Type: unix.NFTA_LOOKUP_FLAGS, Data: tc.flags})
				fields[i].Data, err = netlink.MarshalAttributes(actual)
				if err != nil {
					t.Fatal(err)
				}
			}
			actual, err := netlink.MarshalAttributes(fields)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_LIST_ELEM | netlink.Nested, Data: actual}})
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyNFTExpressions([]expr.Any{lookup}, raw)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
