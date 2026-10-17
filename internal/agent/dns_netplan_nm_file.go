package agent

import (
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

// Ignore ordering and known keyfile encodings, not unknown policy changes.
// A matching in-memory profile alone cannot authorize overwriting a disk file.
func netplanNMNonDNSFile(raw []byte, uuid string) (map[string]map[string]string, error) {
	file, err := netplanNMKeyfile(raw)
	if err != nil {
		return nil, err
	}
	connection := file["connection"]
	if connection == nil {
		return nil, errors.New("missing generated connection identity")
	}
	if value, exists := connection["uuid"]; exists && !strings.EqualFold(value, uuid) {
		return nil, errors.New("generated connection UUID changed")
	}
	delete(connection, "uuid")
	if value, exists := connection["timestamp"]; exists {
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return nil, errors.New("invalid generated connection timestamp")
		}
		delete(connection, "timestamp")
	}
	if connection["type"] == "ethernet" {
		connection["type"] = "802-3-ethernet"
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		props := file[family]
		if props == nil {
			continue
		}
		delete(props, "dns")
		delete(props, "dns-search")
		if value, exists := props["ignore-auto-dns"]; exists {
			if value != "true" && value != "false" {
				return nil, errors.New("invalid generated automatic DNS policy")
			}
			if value == "false" {
				delete(props, "ignore-auto-dns")
			}
		}
		if family == "ipv6" {
			// On-disk absence means default-or-eui64, unlike D-Bus absence.
			modes := map[string]string{"": "2", "eui64": "0", "stable-privacy": "1", "default-or-eui64": "2", "default": "3", "0": "0", "1": "1", "2": "2", "3": "3"}
			value, exists := props["addr-gen-mode"]
			if exists && value == "" {
				return nil, errors.New("empty generated IPv6 address generation mode")
			}
			mode, ok := modes[value]
			if !ok {
				return nil, errors.New("unsupported generated IPv6 address generation mode")
			}
			props["addr-gen-mode"] = mode
		}
		gateway := props["gateway"]
		for key, value := range props {
			if !strings.HasPrefix(key, "address") {
				continue
			}
			index := strings.TrimPrefix(key, "address")
			if number, err := strconv.ParseUint(index, 10, 32); err != nil || number < 1 || strconv.FormatUint(number, 10) != index {
				continue
			}
			parts := strings.Split(value, ",")
			if len(parts) > 2 {
				return nil, errors.New("unsupported generated address encoding")
			}
			prefix, err := netip.ParsePrefix(parts[0])
			if err != nil || family == "ipv4" && !prefix.Addr().Is4() || family == "ipv6" && !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
				return nil, errors.New("invalid generated connection address")
			}
			props[key] = prefix.String()
			if len(parts) == 2 && parts[1] != "" {
				if index != "1" || gateway != "" && gateway != parts[1] {
					return nil, errors.New("ambiguous generated connection gateway")
				}
				gateway = parts[1]
			}
		}
		if gateway != "" {
			ip, err := netip.ParseAddr(gateway)
			if err != nil || ip.Zone() != "" || family == "ipv4" && !ip.Is4() || family == "ipv6" && !ip.Is6() || ip.Is4In6() {
				return nil, errors.New("invalid generated connection gateway")
			}
			props["gateway"] = ip.String()
		}
	}
	for section, props := range file {
		if len(props) == 0 {
			delete(file, section)
		}
	}
	return file, nil
}

func (d *HostDNS) netplanNMObservedFile(file dnsFile, t *nmTarget) error {
	uuid := nmString(t.Persistent, "connection", "uuid")
	want, err := netplanNMNonDNSFile(d.checkpoint.Before.Data, uuid)
	if err != nil {
		return err
	}
	actual, err := netplanNMNonDNSFile(file.Data, uuid)
	if err != nil || !reflect.DeepEqual(want, actual) {
		return errors.New("generated connection file contains an unapproved non-DNS change")
	}
	routes, err := netplanNMRoutes(t.Persistent)
	if err != nil || t.View.Persistent == nil {
		return errors.New("generated connection DNS cannot be confirmed")
	}
	return netplanNMGeneratedMatches(file, *t.View.Persistent, routes)
}
