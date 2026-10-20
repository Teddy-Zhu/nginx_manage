package agent

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/hostdns"
)

func nmSettingsWireReply(t *testing.T, settings map[string]map[string]dbus.Variant, version uint64) *dbus.Call {
	t.Helper()
	body := []any{settings, version}
	message := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldReplySerial: dbus.MakeVariant(uint32(1)),
		dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(body...)),
	}, Body: body}
	var wire bytes.Buffer
	if err := message.EncodeTo(&wire, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	decoded, err := dbus.DecodeMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	return &dbus.Call{Body: decoded.Body}
}

func TestNMSettingsDNSWireRoundTrip(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "static-ipv6", true: "empty-ipv6-tuples"}[empty], func(t *testing.T) {
			address := []byte{0xfd, 0x42, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
			gateway := append([]byte{}, address...)
			gateway[15] = 1
			addresses := []nmIPv6Address{{address, 64, gateway}}
			routes := []nmIPv6Route{{make([]byte, 16), 0, gateway, 200}}
			if empty {
				addresses, routes = []nmIPv6Address{}, []nmIPv6Route{}
			}
			settings := map[string]map[string]dbus.Variant{
				"connection": {"id": dbus.MakeVariant("private-profile"), "uuid": dbus.MakeVariant("9b017089-7b5a-432b-afbb-53d1347bd510")},
				"ipv4":       {"method": dbus.MakeVariant("manual"), "dns": dbus.MakeVariant([]uint32{}), "dns-search": dbus.MakeVariant([]string{"~internal.example.test"})},
				"ipv6": {
					"method": dbus.MakeVariant("manual"), "addresses": dbus.MakeVariant(addresses), "routes": dbus.MakeVariant(routes),
					"address-data": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("fd42:5::10"), "prefix": dbus.MakeVariant(uint32(64))}}),
					"route-data":   dbus.MakeVariant([]map[string]dbus.Variant{{"dest": dbus.MakeVariant("::"), "prefix": dbus.MakeVariant(uint32(0)), "next-hop": dbus.MakeVariant("fd42:5::1"), "metric": dbus.MakeVariant(uint32(200))}}),
				},
			}
			original := nmSettingsWireReply(t, settings, 7).Body[0].(map[string]map[string]dbus.Variant)
			before := nmSettingsWireReply(t, settings, 7)
			var loaded nmSettings
			var version uint64
			if err := nmReadSettings(before, &loaded, &version); err != nil || version != 7 {
				t.Fatalf("read settings: version=%d, error=%v", version, err)
			}
			if err := nmModify(loaded, hostdns.Config{IPv4: &hostdns.Family{Servers: []string{"192.0.2.12"}, Search: []string{"after.example.test"}}, IPv6: &hostdns.Family{Servers: []string{"fd42:5::12"}}}); err != nil {
				t.Fatal(err)
			}
			after := nmSettingsWireReply(t, loaded, version)
			actual := after.Body[0].(map[string]map[string]dbus.Variant)
			for _, key := range []string{"addresses", "routes", "address-data", "route-data"} {
				if !reflect.DeepEqual(original["ipv6"][key], actual["ipv6"][key]) {
					t.Fatalf("non-DNS property changed on the wire: %s", key)
				}
			}
			config, routes4, err := nmConfig(actual)
			if err != nil || !reflect.DeepEqual(config.IPv6.Servers, []string{"fd42:5::12"}) || !reflect.DeepEqual(routes4, []string{"~internal.example.test"}) {
				t.Fatalf("DNS update or route domain changed: config=%v, routes=%v, error=%v", config, routes4, err)
			}
		})
	}
}

func TestNMSettingsRejectUnrepresentableWireType(t *testing.T) {
	settings := map[string]map[string]dbus.Variant{"ethernet": {"unknown": dbus.MakeVariant([]struct{ A, B uint32 }{{1, 2}})}}
	var loaded nmSettings
	var version uint64
	if err := nmReadSettings(nmSettingsWireReply(t, settings, 1), &loaded, &version); err == nil {
		t.Fatal("unrepresentable compound setting must prevent a write")
	}
}
