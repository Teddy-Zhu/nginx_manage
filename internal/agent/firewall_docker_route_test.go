package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

func TestDockerRouteMergedLocalInventoryProof(t *testing.T) {
	// Same Linux 5.15 destination: FIB_MATCH reports main, inventory local.
	read := func(raw string) dockerRouteRecord {
		t.Helper()
		data, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		record, err := parseDockerRouteRecord(data, 2, false)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	selectedRaw := "02200000fe02fe020000000008000f00fe00000008000100c000020a08000700c000020a0800040004000000"
	local := read("02200000ff02fe020000000008000f00ff00000008000100c000020a08000700c000020a0800040004000000")
	localID := dockerRouteIdentity(local)
	selectedID := dockerRouteIdentity(read(selectedRaw))
	for _, test := range []struct {
		name   string
		mutate func(*dockerRouteRecord)
		routes map[string]bool
		valid  bool
	}{
		{"unique-local", nil, map[string]bool{localID: true}, true},
		{"missing-local", nil, map[string]bool{}, false},
		{"main-only", nil, map[string]bool{selectedID: true}, false},
		{"ambiguous-local-main", nil, map[string]bool{localID: true, selectedID: true}, false},
		{"wrong-interface", func(r *dockerRouteRecord) { v, _ := r.attribute(dockerRouteOIF); binary.NativeEndian.PutUint32(v, 5) }, map[string]bool{localID: true}, false},
		{"wrong-source", func(r *dockerRouteRecord) { v, _ := r.attribute(dockerRoutePreferredSource); v[3]++ }, map[string]bool{localID: true}, false},
		{"wrong-destination", func(r *dockerRouteRecord) { v, _ := r.attribute(dockerRouteDST); v[3]++ }, map[string]bool{localID: true}, false},
		{"wrong-protocol", func(r *dockerRouteRecord) { r.Header[5]++ }, map[string]bool{localID: true}, false},
		{"non-host-prefix", func(r *dockerRouteRecord) { r.Header[1] = 24 }, map[string]bool{localID: true}, false},
		{"unicast", func(r *dockerRouteRecord) { r.Header[7] = 1 }, map[string]bool{localID: true}, false},
		{"ipv6", func(r *dockerRouteRecord) { r.Header[0], r.Header[1] = 10, 128 }, map[string]bool{localID: true}, false},
		{"conflicting-table", func(r *dockerRouteRecord) { r.Header[4] = 255 }, map[string]bool{localID: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := read(selectedRaw)
			if test.mutate != nil {
				test.mutate(&record)
			}
			before := dockerRouteIdentity(record)
			got := dockerRouteInventoryIdentity(record, dockerRoutingSnapshot{Routes: test.routes}, true)
			if (got != "") != test.valid || test.valid && got != localID {
				t.Fatalf("inventory proof=%q valid=%v", got, test.valid)
			}
			if dockerRouteIdentity(record) != before {
				t.Fatal("inventory matching changed the observed kernel reply")
			}
		})
	}
	snapshot := dockerRoutingSnapshot{Routes: map[string]bool{localID: true}}
	if got := dockerRouteInventoryIdentity(local, snapshot, true); got != localID {
		t.Fatal("rejected the exact local inventory entry")
	}
	if got := dockerRouteInventoryIdentity(read(selectedRaw), snapshot, false); got != "" {
		t.Fatal("applied local-table aliasing to a container route")
	}
}

func TestDockerRoutingEnvironmentExpiryCountdown(t *testing.T) {
	// Actual RA route from the Linux 5.15 IPv6 dump used in Docker validation.
	raw, err := hex.DecodeString("0a400000fe0900010000000008000f00fe00000014000100fec000000000000000000000000000000800060064000000080004000200000024000c0000000000000000000ba8830000000000000000000000000000000000000000000500140000000000")
	if err != nil {
		t.Fatal(err)
	}
	read := func() dockerRouteRecord {
		record, err := parseDockerRouteRecord(raw, 10, false)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	digest := func(record dockerRouteRecord) []byte {
		value, err := dockerRoutingEnvironmentRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first := read()
	cache, _ := first.attribute(dockerRouteCache)
	expires := binary.NativeEndian.Uint32(cache[8:12])
	before := digest(first)
	if binary.NativeEndian.Uint32(cache[8:12]) != expires {
		t.Fatal("digest changed the original routing inventory")
	}
	second := read()
	cache, _ = second.attribute(dockerRouteCache)
	binary.NativeEndian.PutUint32(cache[8:12], expires-100)
	if !bytes.Equal(before, digest(second)) {
		t.Fatal("a live lifetime countdown invalidated the routing environment")
	}
	for _, expires := range []uint32{0, ^uint32(0)} {
		binary.NativeEndian.PutUint32(cache[8:12], expires)
		if bytes.Equal(before, digest(second)) {
			t.Fatal("lifetime state change was ignored")
		}
	}
	second = read()
	second.Header[5]++
	if bytes.Equal(before, digest(second)) {
		t.Fatal("route protocol change was ignored")
	}
	second = read()
	cache, _ = second.attribute(dockerRouteCache)
	binary.NativeEndian.PutUint32(cache[12:16], 1)
	if bytes.Equal(before, digest(second)) {
		t.Fatal("route cache error was ignored")
	}
	explicit := read()
	lifetime := make([]byte, 4)
	binary.NativeEndian.PutUint32(lifetime, 600)
	explicit.Attributes = append(explicit.Attributes, dockerRouteAttribute{dockerRouteExpires, lifetime})
	before = digest(explicit)
	binary.NativeEndian.PutUint32(lifetime, 599)
	if !bytes.Equal(before, digest(explicit)) {
		t.Fatal("RTA_EXPIRES countdown invalidated the routing environment")
	}
	binary.NativeEndian.PutUint32(lifetime, 0)
	if bytes.Equal(before, digest(explicit)) {
		t.Fatal("RTA_EXPIRES lifetime state change was ignored")
	}
	explicit.Attributes[len(explicit.Attributes)-1].Value = []byte{1, 2, 3}
	if _, err := dockerRoutingEnvironmentRecord(explicit); err == nil {
		t.Fatal("accepted malformed route lifetime")
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
