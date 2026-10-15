package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"

	"github.com/godbus/dbus/v5"

	"nginxpanel/internal/hostdns"
)

type nmSettings map[string]map[string]dbus.Variant
type nmValue struct {
	Signature string          `json:"signature"`
	Data      json.RawMessage `json:"data"`
}
type nmDNS map[string]map[string]nmValue

var nmDNSKeys = []string{"dns", "dns-data", "dns-search", "ignore-auto-dns"}

func nmCapture(s nmSettings) (nmDNS, error) {
	out := nmDNS{}
	for _, family := range []string{"ipv4", "ipv6"} {
		props, ok := s[family]
		if !ok {
			continue
		}
		out[family] = map[string]nmValue{}
		for _, key := range nmDNSKeys {
			if v, ok := props[key]; ok {
				sig := v.Signature().String()
				if !(key == "dns" && (family == "ipv4" && sig == "au" || family == "ipv6" && sig == "aay") || (key == "dns-data" || key == "dns-search") && sig == "as" || key == "ignore-auto-dns" && sig == "b") {
					return nil, errors.New("unsupported DNS property type")
				}
				raw, e := json.Marshal(v.Value())
				if e != nil || len(raw) > 8192 {
					return nil, errors.New("DNS property exceeds budget")
				}
				out[family][key] = nmValue{sig, raw}
			}
		}
	}
	return out, nil
}
func (v nmValue) variant() (dbus.Variant, error) {
	var dst any
	switch v.Signature {
	case "au":
		dst = new([]uint32)
	case "aay":
		dst = new([][]byte)
	case "as":
		dst = new([]string)
	case "b":
		dst = new(bool)
	default:
		return dbus.Variant{}, errors.New("invalid DNS snapshot type")
	}
	if e := json.Unmarshal(v.Data, dst); e != nil {
		return dbus.Variant{}, e
	}
	return dbus.MakeVariant(reflect.ValueOf(dst).Elem().Interface()), nil
}
func (n nmDNS) restore(s nmSettings) error {
	for family, props := range n {
		if s[family] == nil {
			return errors.New("IP family disappeared")
		}
		for _, k := range nmDNSKeys {
			delete(s[family], k)
		}
		for k, v := range props {
			allowed := false
			for _, key := range nmDNSKeys {
				if key == k {
					allowed = true
				}
			}
			if !allowed {
				return errors.New("invalid DNS snapshot key")
			}
			value, e := v.variant()
			if e != nil {
				return e
			}
			s[family][k] = value
		}
	}
	return nil
}
func nmString(s nmSettings, family, key string) string {
	v, _ := s[family][key].Value().(string)
	return v
}
func nmFamily(s nmSettings, family string) (*hostdns.Family, []string, error) {
	method := nmString(s, family, "method")
	if method != "auto" && method != "dhcp" && method != "manual" {
		return nil, []string{}, nil
	}
	f := &hostdns.Family{Servers: []string{}, Search: []string{}}
	ignore, _ := s[family]["ignore-auto-dns"].Value().(bool)
	f.Automatic = (method == "auto" || method == "dhcp") && !ignore
	props := s[family]
	if data, ok := props["dns-data"]; ok {
		servers, ok := data.Value().([]string)
		if !ok || len(servers) > 32 {
			return nil, nil, errors.New("unsupported DNS data")
		}
		for _, v := range servers {
			ip, e := netip.ParseAddr(v)
			if e != nil || ip.Zone() != "" || family == "ipv4" && !ip.Is4() || family == "ipv6" && !ip.Is6() {
				return nil, nil, errors.New("encrypted or scoped DNS needs a dedicated adapter")
			}
			f.Servers = append(f.Servers, ip.String())
		}
	} else if v, ok := props["dns"]; ok {
		if family == "ipv4" {
			data, ok := v.Value().([]uint32)
			if !ok || len(data) > 32 {
				return nil, nil, errors.New("invalid IPv4 DNS data")
			}
			for _, n := range data {
				var a [4]byte
				binary.NativeEndian.PutUint32(a[:], n)
				f.Servers = append(f.Servers, netip.AddrFrom4(a).String())
			}
		} else {
			data, ok := v.Value().([][]byte)
			if !ok || len(data) > 32 {
				return nil, nil, errors.New("invalid IPv6 DNS data")
			}
			for _, a := range data {
				ip, ok := netip.AddrFromSlice(a)
				if !ok || !ip.Is6() || ip.Is4In6() {
					return nil, nil, errors.New("invalid IPv6 DNS address")
				}
				f.Servers = append(f.Servers, ip.String())
			}
		}
	}
	routing := []string{}
	if v, ok := props["dns-search"]; ok {
		search, ok := v.Value().([]string)
		if !ok || len(search) > 64 {
			return nil, nil, errors.New("unsupported DNS search data")
		}
		for _, domain := range search {
			if len(domain) > 254 {
				return nil, nil, errors.New("DNS domain exceeds budget")
			}
			if strings.HasPrefix(domain, "~") {
				routing = append(routing, domain)
			} else {
				f.Search = append(f.Search, domain)
			}
		}
	}
	return f, routing, nil
}
func nmConfig(s nmSettings) (hostdns.Config, []string, error) {
	c := hostdns.Config{Servers: []string{}, Search: []string{}}
	var r4, r6 []string
	var e error
	c.IPv4, r4, e = nmFamily(s, "ipv4")
	if e != nil {
		return c, nil, e
	}
	c.IPv6, r6, e = nmFamily(s, "ipv6")
	return c, append(r4, r6...), e
}
func nmModify(s nmSettings, c hostdns.Config) error {
	for i, f := range []*hostdns.Family{c.IPv4, c.IPv6} {
		if f == nil {
			continue
		}
		family := []string{"ipv4", "ipv6"}[i]
		before, routing, e := nmFamily(s, family)
		if e != nil || before == nil {
			return errors.New("unsupported target IP method")
		}
		method := nmString(s, family, "method")
		if f.Automatic && method != "auto" && method != "dhcp" {
			return errors.New("static connection cannot enable automatic DNS")
		}
		props := s[family]
		delete(props, "dns-data")
		if i == 0 {
			data := []uint32{}
			for _, v := range f.Servers {
				ip, e := netip.ParseAddr(v)
				if e != nil || !ip.Is4() {
					return errors.New("invalid IPv4 DNS")
				}
				a := ip.As4()
				data = append(data, binary.NativeEndian.Uint32(a[:]))
			}
			props["dns"] = dbus.MakeVariant(data)
		} else {
			data := [][]byte{}
			for _, v := range f.Servers {
				ip, e := netip.ParseAddr(v)
				if e != nil || !ip.Is6() {
					return errors.New("invalid IPv6 DNS")
				}
				a := ip.As16()
				data = append(data, append([]byte{}, a[:]...))
			}
			props["dns"] = dbus.MakeVariant(data)
		}
		search := append(append([]string{}, f.Search...), routing...)
		props["dns-search"] = dbus.MakeVariant(search)
		props["ignore-auto-dns"] = dbus.MakeVariant(!f.Automatic)
	}
	return nil
}

// Compare the effective DNS property meaning, while retaining exact absent /
// legacy property snapshots for restoration. All route domains participate.
func nmSame(a, b nmDNS) bool {
	makeSettings := func(n nmDNS) nmSettings {
		s := nmSettings{}
		for family := range n {
			s[family] = map[string]dbus.Variant{"method": dbus.MakeVariant("auto")}
		}
		if n.restore(s) != nil {
			return nil
		}
		return s
	}
	as, bs := makeSettings(a), makeSettings(b)
	if as == nil || bs == nil {
		return false
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		ac, ar, ae := nmFamily(as, family)
		bc, br, be := nmFamily(bs, family)
		if ae != nil || be != nil || !reflect.DeepEqual(ac, bc) || !reflect.DeepEqual(ar, br) {
			return false
		}
	}
	return true
}
