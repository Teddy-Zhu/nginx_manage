package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

type netplanDirectory struct {
	Root   string
	Real   string
	State  networkDirectory
	Absent bool
}

type netplanSnapshot struct {
	dirs      []netplanDirectory
	files     []networkSource
	paths     []string
	network   *yaml.Node
	hash      string
	problem   string
	tool      netplanTool
	toolRead  bool
	toolError error
}

// Follow only the standard merged-/usr alias. Source-directory symlinks and
// individual YAML links are not accepted as trusted upstream configuration.
func netplanDirectoryState(root string) (netplanDirectory, error) {
	out := netplanDirectory{Root: root}
	real, err := filepath.EvalSymlinks(root)
	if os.IsNotExist(err) {
		out.Absent = true
		return out, nil
	}
	if err != nil || real != root && !(root == "/lib/netplan" && real == "/usr/lib/netplan") {
		return out, errors.New("untrusted netplan source directory")
	}
	out.Real = real
	out.State, err = networkDirectoryState(real)
	return out, err
}

func (s *netplanSnapshot) stable() bool {
	for _, dir := range s.dirs {
		after, err := netplanDirectoryState(dir.Root)
		if err != nil || after != dir {
			return false
		}
	}
	for _, file := range s.files {
		after, err := readDNSFile(file.Path)
		if err != nil || after.hash() != file.File.hash() {
			return false
		}
	}
	return true
}

// The effective basename set is selected first, then merged in lexical order.
// No raw YAML, Wi-Fi credentials or native parser diagnostics leave this reader.
func readNetplanSources() *netplanSnapshot {
	s := &netplanSnapshot{paths: []string{}}
	chosen := map[string]string{}
	for _, root := range []string{"/lib/netplan", "/etc/netplan", "/run/netplan"} {
		dir, err := netplanDirectoryState(root)
		if err != nil {
			s.problem = "netplan 源目录权限或链接不安全"
			return s
		}
		s.dirs = append(s.dirs, dir)
		if dir.Absent {
			continue
		}
		entries, err := networkDirectoryEntries(dir.Real)
		if err != nil {
			s.problem = "netplan 源目录无法在读取预算内完整列出"
			return s
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".yaml") {
				continue
			}
			if !entry.Type().IsRegular() || len(name) > 128 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
				s.problem = "netplan 源目录含不受支持的 YAML 文件或链接"
				return s
			}
			chosen[name] = filepath.Join(dir.Real, name)
		}
	}
	if len(chosen) == 0 || len(chosen) > 64 {
		s.problem = "未发现可完整读取的 netplan 源文件集"
		return s
	}
	names := make([]string, 0, len(chosen))
	for name := range chosen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s.paths = append(s.paths, chosen[name])
	}
	var merged *yaml.Node
	budget, nodes := 0, 0
	for _, path := range s.paths {
		file, err := readDNSFile(path)
		if err != nil {
			s.problem = "netplan 源文件不安全、超限或无法完整读取"
			return s
		}
		budget += len(file.Data)
		if budget > 256<<10 {
			s.problem = "netplan 源文件总量超过 256 KiB 读取上限"
			return s
		}
		s.files = append(s.files, networkSource{Path: path, File: file})
		doc := yaml.Node{}
		decoder := yaml.NewDecoder(bytes.NewReader(file.Data))
		if decoder.Decode(&doc) != nil || decoder.Decode(new(yaml.Node)) != io.EOF || len(doc.Content) != 1 || !netplanNodes(doc.Content[0], 0, &nodes) {
			s.problem = "netplan 源含无效或尚未支持的 YAML，不能推测合并结果"
			return s
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "network" || root.Content[1].Kind != yaml.MappingNode {
			s.problem = "netplan 源不是受支持的 network 映射"
			return s
		}
		merged, err = mergeNetplanNodes(merged, root.Content[1])
		if err != nil {
			s.problem = "netplan 多文件字段类型冲突，合并结果未确认"
			return s
		}
	}
	version := netplanField(merged, "version")
	if version == nil || version.Tag != "!!int" || version.Value != "2" {
		s.problem = "netplan 源版本不是受支持的 version 2"
		return s
	}
	if !s.stable() {
		s.problem = "netplan 源在读取期间变化，请刷新"
		return s
	}
	s.network = merged
	proofs := make([][2]string, 0, len(s.files))
	for _, file := range s.files {
		proofs = append(proofs, [2]string{file.Path, file.File.hash()})
	}
	raw, _ := json.Marshal(proofs)
	s.hash = secure.Hash(raw)
	return s
}

func netplanNodes(n *yaml.Node, depth int, count *int) bool {
	*count = *count + 1
	if n == nil || depth > 32 || *count > 16384 || n.Anchor != "" || n.Alias != nil {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 || n.Tag != "!!map" {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return false
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return false
		}
	default:
		return false
	}
	for _, child := range n.Content {
		if !netplanNodes(child, depth+1, count) {
			return false
		}
	}
	return true
}

func netplanField(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	return nil
}

func mergeNetplanNodes(before, after *yaml.Node) (*yaml.Node, error) {
	if before == nil {
		return after, nil
	}
	if before.Kind != after.Kind {
		return nil, errors.New("netplan field type changed")
	}
	if after.Kind == yaml.SequenceNode {
		before.Content = append(before.Content, after.Content...)
		return before, nil
	}
	if after.Kind != yaml.MappingNode {
		return after, nil
	}
	for i := 0; i < len(after.Content); i += 2 {
		found := false
		for j := 0; j < len(before.Content); j += 2 {
			if before.Content[j].Value != after.Content[i].Value {
				continue
			}
			merged, err := mergeNetplanNodes(before.Content[j+1], after.Content[i+1])
			if err != nil {
				return nil, err
			}
			before.Content[j+1], found = merged, true
			break
		}
		if !found {
			before.Content = append(before.Content, after.Content[i], after.Content[i+1])
		}
	}
	return before, nil
}

func netplanGeneratedID(renderer, file string) (string, bool) {
	if filepath.Clean(file) != file {
		return "", false
	}
	dir, prefix, suffix := "/run/systemd/network", "10-netplan-", ".network"
	if renderer == "NetworkManager" {
		dir, prefix, suffix = "/run/NetworkManager/system-connections", "netplan-", ".nmconnection"
	}
	if filepath.Dir(file) != dir || !strings.HasPrefix(filepath.Base(file), prefix) || !strings.HasSuffix(file, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(file), prefix), suffix)
	return id, len(id) > 0 && len(id) <= 128 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == ""
}

func (s *netplanSnapshot) source(renderer, file string) *hostdns.NetplanSource {
	id, generated := netplanGeneratedID(renderer, file)
	if !generated {
		return nil
	}
	out := &hostdns.NetplanSource{State: "unresolved", Renderer: renderer, Sources: append([]string{}, s.paths...), Reason: s.problem}
	if s.problem != "" {
		return out
	}
	var definition *yaml.Node
	for _, group := range []string{"ethernets", "wifis", "bridges", "bonds", "vlans", "tunnels", "modems", "virtual-ethernets", "dummy-devices", "nm-devices"} {
		if value := netplanField(netplanField(s.network, group), id); value != nil {
			if definition != nil {
				out.Reason = "netplan 定义 ID 跨设备类型重复，来源关联未确认"
				return out
			}
			definition, out.DeviceType = value, group
		}
	}
	if definition == nil || definition.Kind != yaml.MappingNode {
		out.Reason = "生成文件未能关联唯一 netplan 定义，可能存在生成命名差异或源已变化"
		return out
	}
	configured := netplanField(definition, "renderer")
	if configured == nil {
		configured = netplanField(s.network, "renderer")
	}
	actual := "networkd"
	if configured != nil {
		if configured.Kind != yaml.ScalarNode || configured.Tag != "!!str" {
			out.Reason = "netplan renderer 字段未确认"
			return out
		}
		actual = configured.Value
	}
	if actual != renderer {
		out.Reason = "netplan renderer 与当前生成文件所属后端不同"
		return out
	}
	out.State, out.Definition, out.SourceHash = "associated", id, s.hash
	out.Settings = netplanDNSFields(definition)
	out.Reason = "已关联 netplan 源；生成一致性及安全局部修改与恢复未确认，保持只读"
	if out.Settings == nil {
		out.Reason = "已关联 netplan 源，但 DNS 字段或原生透传尚未完整识别，保持只读"
	}
	return out
}

func netplanBool(n *yaml.Node) (*bool, bool) {
	if n == nil {
		return nil, true
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		return nil, false
	}
	value := false
	switch strings.ToLower(n.Value) {
	case "true":
		value = true
	case "false":
	default:
		return nil, false
	}
	return &value, true
}

func netplanStrings(n *yaml.Node) ([]string, bool) {
	out := []string{}
	if n == nil {
		return out, true
	}
	if n.Kind != yaml.SequenceNode || len(n.Content) > 32 {
		return nil, false
	}
	for _, value := range n.Content {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || len(value.Value) > 256 {
			return nil, false
		}
		out = append(out, value.Value)
	}
	return out, true
}

func netplanDNSFields(definition *yaml.Node) *hostdns.NetplanDNS {
	// Backend passthrough can override the portable nameservers projection.
	if netplanField(definition, "networkmanager") != nil || netplanField(definition, "networkd") != nil || netplanField(definition, "ra-overrides") != nil {
		return nil
	}
	out := &hostdns.NetplanDNS{Servers: []string{}, Search: []string{}, RoutingDomains: []string{}}
	var ok bool
	if out.DHCP4, ok = netplanBool(netplanField(definition, "dhcp4")); !ok {
		return nil
	}
	if out.DHCP6, ok = netplanBool(netplanField(definition, "dhcp6")); !ok {
		return nil
	}
	if out.AcceptRA, ok = netplanBool(netplanField(definition, "accept-ra")); !ok {
		return nil
	}
	for i, key := range []string{"dhcp4-overrides", "dhcp6-overrides"} {
		n := netplanField(definition, key)
		if n != nil && n.Kind != yaml.MappingNode {
			return nil
		}
		value, valid := netplanBool(netplanField(n, "use-dns"))
		if !valid {
			return nil
		}
		if i == 0 {
			out.UseDNS4 = value
		} else {
			out.UseDNS6 = value
		}
	}
	nameservers := netplanField(definition, "nameservers")
	if nameservers != nil && nameservers.Kind != yaml.MappingNode {
		return nil
	}
	if nameservers != nil {
		for i := 0; i < len(nameservers.Content); i += 2 {
			if key := nameservers.Content[i].Value; key != "addresses" && key != "search" {
				return nil
			}
		}
	}
	servers, valid := netplanStrings(netplanField(nameservers, "addresses"))
	if !valid {
		return nil
	}
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil || ip.Zone() != "" {
			return nil
		}
		out.Servers = append(out.Servers, ip.Unmap().String())
	}
	domains, valid := netplanStrings(netplanField(nameservers, "search"))
	if !valid {
		return nil
	}
	for _, domain := range domains {
		if domain == "~." {
			out.RoutingDomains = append(out.RoutingDomains, domain)
			continue
		}
		name, route := strings.CutPrefix(domain, "~")
		if !hostdns.Hostname(name) {
			return nil
		}
		if route {
			out.RoutingDomains = append(out.RoutingDomains, domain)
		} else {
			out.Search = append(out.Search, domain)
		}
	}
	return out
}

func invalidateNetplanSource(out *hostdns.NetplanSource) {
	if out == nil {
		return
	}
	out.State, out.SourceHash, out.Settings = "unresolved", "", nil
	out.Reason = "netplan 源在读取期间变化或无法复核，请刷新"
}
