package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const firewalldPolicyLimit = 64
const firewalldPolicySettingsBytes = 64 << 10
const firewalldPolicyInventoryBytes = 512 << 10

func firewalldObjectName(value string) bool {
	if value == "" || len(value) > 128 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, c := range value {
		// Policy sets use a slash-qualified policy name. This is a D-Bus
		// identifier only and is never used to construct a filesystem path.
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func firewalldPolicyNames(values []string) bool {
	if len(values) > firewalldPolicyLimit {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !firewalldObjectName(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func firewalldZoneNames(values []string) bool {
	if len(values) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !firewalldObjectName(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

// Only the documented value signatures are accepted. The hash retains every
// supplied key, signature, empty value and list order; no setting is ignored.
func summarizeFirewalldPolicy(settings map[string]dbus.Variant) (*firewall.FirewalldPolicySettings, int, error) {
	invalid := errors.New("invalid or oversized firewalld policy settings")
	if settings == nil || len(settings) > 32 {
		return nil, 0, invalid
	}
	signatures := map[string]string{
		"version": "s", "short": "s", "description": "s", "target": "s",
		"priority": "i", "masquerade": "b", "disable": "b",
		"ingress_zones": "as", "egress_zones": "as", "services": "as",
		"protocols": "as", "icmp_blocks": "as", "rich_rules": "as",
		"ports": "a(ss)", "source_ports": "a(ss)", "forward_ports": "a(ssss)",
	}
	type field struct {
		Signature string `json:"signature"`
		Value     any    `json:"value"`
	}
	canonical := map[string]field{}
	out := &firewall.FirewalldPolicySettings{IngressZones: []string{}, EgressZones: []string{}}
	validString := func(value string) bool {
		return len(value) <= 8192 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
	}
	for key, value := range settings {
		sig, exists := signatures[key]
		if !exists || value.Signature().String() != sig {
			return nil, 0, invalid
		}
		item := value.Value()
		switch sig {
		case "s":
			text, ok := item.(string)
			if !ok || !validString(text) {
				return nil, 0, invalid
			}
			if key == "target" {
				if !slices.Contains([]string{"CONTINUE", "ACCEPT", "REJECT", "DROP"}, text) {
					return nil, 0, invalid
				}
				out.Target = text
			}
		case "i":
			priority, ok := item.(int32)
			if !ok {
				return nil, 0, invalid
			}
			out.Priority = &priority
		case "b":
			flag, ok := item.(bool)
			if !ok {
				return nil, 0, invalid
			}
			if key == "masquerade" {
				out.Masquerade = &flag
			}
		case "as":
			values, ok := item.([]string)
			if !ok || len(values) > 1024 {
				return nil, 0, invalid
			}
			for _, text := range values {
				if !validString(text) {
					return nil, 0, invalid
				}
			}
			switch key {
			case "ingress_zones", "egress_zones":
				if !firewalldZoneNames(values) {
					return nil, 0, invalid
				}
				if key == "ingress_zones" {
					out.IngressZones = append(out.IngressZones, values...)
				} else {
					out.EgressZones = append(out.EgressZones, values...)
				}
			default:
				out.Entries += len(values)
				if key == "rich_rules" {
					out.RichRules = len(values)
				}
			}
		case "a(ss)", "a(ssss)":
			// D-Bus structs decode to []any, including inside an array.
			values, ok := item.([][]any)
			if !ok || len(values) > 1024 {
				return nil, 0, invalid
			}
			width := 2
			if sig == "a(ssss)" {
				width = 4
			}
			for _, tuple := range values {
				if len(tuple) != width {
					return nil, 0, invalid
				}
				for _, value := range tuple {
					text, ok := value.(string)
					if !ok || !validString(text) {
						return nil, 0, invalid
					}
				}
			}
			out.Entries += len(values)
		}
		canonical[key] = field{Signature: sig, Value: item}
	}
	if out.Entries > 4096 {
		return nil, 0, invalid
	}
	raw, err := json.Marshal(canonical)
	if err != nil || len(raw) > firewalldPolicySettingsBytes {
		return nil, 0, invalid
	}
	out.Hash = secure.Hash(append([]byte("firewalld.policy.settings\x00"), raw...))
	return out, len(raw), nil
}

// All calls go to one observed unique owner. Runtime/permanent are separate
// reads; successful collection does not promise an atomic manager snapshot.
func readFirewalldPolicies(ctx context.Context, conn *dbus.Conn, owner string) firewall.FirewalldPolicyInventory {
	failure := firewall.EmptyFirewalldPolicies("firewalld policy 接口不可用、读取不完整或超过预算")
	peer := conn.Object(owner, firewalldRoot)
	config := conn.Object(owner, dbus.ObjectPath(string(firewalldRoot)+"/config"))
	var runtime, permanent []string
	var active map[string]map[string][]string
	if peer.CallWithContext(ctx, firewalldName+".policy.getPolicies", dbus.FlagNoAutoStart).Store(&runtime) != nil || !firewalldPolicyNames(runtime) {
		return failure
	}
	if config.CallWithContext(ctx, firewalldName+".config.getPolicyNames", dbus.FlagNoAutoStart).Store(&permanent) != nil || !firewalldPolicyNames(permanent) {
		return failure
	}
	if peer.CallWithContext(ctx, firewalldName+".policy.getActivePolicies", dbus.FlagNoAutoStart).Store(&active) != nil || len(active) > firewalldPolicyLimit {
		return failure
	}
	for name, zones := range active {
		if !slices.Contains(runtime, name) || len(zones) != 2 || len(zones["ingress_zones"]) == 0 || len(zones["egress_zones"]) == 0 || !firewalldZoneNames(zones["ingress_zones"]) || !firewalldZoneNames(zones["egress_zones"]) {
			return failure
		}
		sort.Strings(zones["ingress_zones"])
		sort.Strings(zones["egress_zones"])
	}
	names := append(append([]string{}, runtime...), permanent...)
	sort.Strings(names)
	names = slices.Compact(names)
	if len(names) > firewalldPolicyLimit {
		return failure
	}
	out := firewall.EmptyFirewalldPolicies("")
	budget := 0
	for _, name := range names {
		entry := firewall.FirewalldPolicy{Name: name, ActiveIngressZones: []string{}, ActiveEgressZones: []string{}}
		for _, persistent := range []bool{false, true} {
			var settings map[string]dbus.Variant
			if !persistent {
				if !slices.Contains(runtime, name) {
					continue
				}
				if peer.CallWithContext(ctx, firewalldName+".policy.getPolicySettings", dbus.FlagNoAutoStart, name).Store(&settings) != nil {
					return failure
				}
			} else {
				if !slices.Contains(permanent, name) {
					continue
				}
				var path dbus.ObjectPath
				if config.CallWithContext(ctx, firewalldName+".config.getPolicyByName", dbus.FlagNoAutoStart, name).Store(&path) != nil || !path.IsValid() || !strings.HasPrefix(string(path), string(firewalldRoot)+"/config/policy/") {
					return failure
				}
				if conn.Object(owner, path).CallWithContext(ctx, firewalldName+".config.policy.getSettings", dbus.FlagNoAutoStart).Store(&settings) != nil {
					return failure
				}
			}
			summary, size, err := summarizeFirewalldPolicy(settings)
			budget += size
			if err != nil || budget > firewalldPolicyInventoryBytes {
				return failure
			}
			if persistent {
				entry.Permanent = summary
			} else {
				entry.Runtime = summary
			}
		}
		if zones, ok := active[name]; ok {
			entry.Active = true
			entry.ActiveIngressZones = append(entry.ActiveIngressZones, zones["ingress_zones"]...)
			entry.ActiveEgressZones = append(entry.ActiveEgressZones, zones["egress_zones"]...)
		}
		out.Policies = append(out.Policies, entry)
	}
	// Detect list/activation changes without treating a same-owner reload as a
	// coherent transaction. Settings themselves may still change between reads.
	var afterRuntime, afterPermanent []string
	var afterActive map[string]map[string][]string
	if peer.CallWithContext(ctx, firewalldName+".policy.getPolicies", dbus.FlagNoAutoStart).Store(&afterRuntime) != nil || config.CallWithContext(ctx, firewalldName+".config.getPolicyNames", dbus.FlagNoAutoStart).Store(&afterPermanent) != nil || peer.CallWithContext(ctx, firewalldName+".policy.getActivePolicies", dbus.FlagNoAutoStart).Store(&afterActive) != nil {
		return failure
	}
	if !firewalldPolicyNames(afterRuntime) || !firewalldPolicyNames(afterPermanent) || len(afterActive) > firewalldPolicyLimit {
		return failure
	}
	for name, zones := range afterActive {
		if !slices.Contains(afterRuntime, name) || len(zones) != 2 || len(zones["ingress_zones"]) == 0 || len(zones["egress_zones"]) == 0 || !firewalldZoneNames(zones["ingress_zones"]) || !firewalldZoneNames(zones["egress_zones"]) {
			return failure
		}
		sort.Strings(zones["ingress_zones"])
		sort.Strings(zones["egress_zones"])
	}
	sort.Strings(runtime)
	sort.Strings(permanent)
	sort.Strings(afterRuntime)
	sort.Strings(afterPermanent)
	beforeJSON, beforeErr := json.Marshal(active)
	afterJSON, afterErr := json.Marshal(afterActive)
	if !slices.Equal(runtime, afterRuntime) || !slices.Equal(permanent, afterPermanent) || beforeErr != nil || afterErr != nil || string(beforeJSON) != string(afterJSON) {
		return firewall.EmptyFirewalldPolicies("firewalld policy 清单或活动绑定在读取期间变化，请刷新")
	}
	out.Available = true
	return out
}

func validFirewalldPolicies(in firewall.FirewalldPolicyInventory) bool {
	if in.Policies == nil || len(in.Policies) > firewalldPolicyLimit || !in.Available && (len(in.Policies) != 0 || in.Reason == "") || in.Available && in.Reason != "" {
		return false
	}
	names := []string{}
	for _, policy := range in.Policies {
		names = append(names, policy.Name)
		if !firewalldZoneNames(policy.ActiveIngressZones) || !firewalldZoneNames(policy.ActiveEgressZones) || policy.ActiveIngressZones == nil || policy.ActiveEgressZones == nil || policy.Runtime == nil && policy.Permanent == nil || policy.Active && (policy.Runtime == nil || len(policy.ActiveIngressZones) == 0 || len(policy.ActiveEgressZones) == 0) || !policy.Active && (len(policy.ActiveIngressZones) != 0 || len(policy.ActiveEgressZones) != 0) {
			return false
		}
		for _, settings := range []*firewall.FirewalldPolicySettings{policy.Runtime, policy.Permanent} {
			if settings == nil {
				continue
			}
			hash, err := hex.DecodeString(settings.Hash)
			if err != nil || len(hash) != 32 || strings.ToLower(settings.Hash) != settings.Hash || settings.IngressZones == nil || settings.EgressZones == nil || !firewalldZoneNames(settings.IngressZones) || !firewalldZoneNames(settings.EgressZones) || !slices.Contains([]string{"", "CONTINUE", "ACCEPT", "REJECT", "DROP"}, settings.Target) || settings.RichRules < 0 || settings.RichRules > 1024 || settings.Entries < settings.RichRules || settings.Entries > 4096 {
				return false
			}
		}
	}
	return firewalldPolicyNames(names)
}
