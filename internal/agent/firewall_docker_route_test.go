package agent

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Captured RTM_NEWRULE payloads from a Linux 5.15 kernel, before any policy apply.
func TestDockerDefaultRoutingRuleKernelDump(t *testing.T) {
	for _, test := range []struct {
		name   string
		family byte
		table  uint32
		raw    string
	}{
		{"ipv4-local", 2, 255, "02000000ff0000010000000008000f00ff00000008000e00ffffffff0500150002000000"},
		{"ipv4-main", 2, 254, "02000000fe0000010000000008000f00fe00000008000e00ffffffff050015000200000008000600fe7f0000"},
		{"ipv4-default", 2, 253, "02000000fd0000010000000008000f00fd00000008000e00ffffffff050015000200000008000600ff7f0000"},
		{"ipv6-local", 10, 255, "0a000000ff0000010000000008000f00ff00000008000e00ffffffff0500150002000000"},
		{"ipv6-main", 10, 254, "0a000000fe0000010000000008000f00fe00000008000e00ffffffff050015000200000008000600fe7f0000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := hex.DecodeString(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			record, err := parseDockerRouteRecord(raw, test.family, true)
			if err != nil {
				t.Fatal(err)
			}
			got, err := dockerDefaultRoutingRule(record)
			if err != nil || got != test.table {
				t.Fatalf("default kernel rule: table=%d err=%v", got, err)
			}
		})
	}
}

func TestDockerDefaultRoutingRuleRejectsSuppression(t *testing.T) {
	for _, value := range [][]byte{
		nil, {255, 255, 255}, {255, 255, 255, 255, 0},
		{0, 0, 0, 0}, {1, 0, 0, 0}, {32, 0, 0, 0}, {128, 0, 0, 0}, {254, 255, 255, 255},
	} {
		record := dockerRouteRecord{Header: [12]byte{2, 0, 0, 0, 254, 0, 0, 1}}
		priority := make([]byte, 4)
		binary.NativeEndian.PutUint32(priority, 32766)
		record.Attributes = []dockerRouteAttribute{{dockerRulePriority, priority}, {dockerRuleSuppressPrefixLen, value}}
		if _, err := dockerDefaultRoutingRule(record); err == nil {
			t.Fatalf("accepted conditional or malformed suppression: %x", value)
		}
	}
}
