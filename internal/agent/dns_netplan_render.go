package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"nginxpanel/internal/hostdns"
)

func netplanDocument(raw []byte) (*yaml.Node, error) {
	var doc yaml.Node
	nodes := 0
	d := yaml.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&doc) != nil || d.Decode(new(yaml.Node)) != io.EOF || len(doc.Content) != 1 || !netplanNodes(doc.Content[0], 0, &nodes) {
		return nil, errors.New("netplan YAML 无法完整识别")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "network" || root.Content[1].Kind != yaml.MappingNode {
		return nil, errors.New("netplan network 映射无效")
	}
	return root.Content[1], nil
}

// Edit only one block nameservers field. Other bytes, comments and source
// files stay untouched. Native generation subsequently proves the full result.
func renderNetplanDNS(raw []byte, iface string, config hostdns.Config, routes []string) ([]byte, error) {
	network, err := netplanDocument(raw)
	if err != nil {
		return nil, err
	}
	def := netplanField(netplanField(network, "ethernets"), iface)
	if def == nil || def.Kind != yaml.MappingNode || def.Style != 0 || len(def.Content) == 0 {
		return nil, errors.New("netplan 定义不是已有的独立块映射")
	}
	lines := strings.SplitAfter(string(raw), "\n")
	start, end, indent := -1, -1, def.Content[0].Column-1
	for i := 0; i < len(def.Content); i += 2 {
		if def.Content[i].Value != "nameservers" {
			continue
		}
		key, value := def.Content[i], def.Content[i+1]
		if value.Kind != yaml.MappingNode || value.Style != 0 {
			return nil, errors.New("netplan nameservers 须为块映射")
		}
		start, indent = key.Line-1, key.Column-1
		// The next mapping key outside this subtree bounds the replacement,
		// including multiline flow lists within nameservers.
		end = len(lines)
		var following func(*yaml.Node)
		following = func(n *yaml.Node) {
			if n == value {
				return
			}
			if n.Kind == yaml.MappingNode {
				for j := 0; j < len(n.Content); j += 2 {
					other := n.Content[j]
					if other.Line > key.Line && other.Column <= key.Column && other.Line-1 < end {
						end = other.Line - 1
					}
					following(n.Content[j+1])
				}
			} else {
				for _, child := range n.Content {
					following(child)
				}
			}
		}
		following(network)
		for end > start+1 {
			text := strings.TrimSpace(lines[end-1])
			if text != "" && text != "..." && !strings.HasPrefix(text, "#") {
				break
			}
			end--
		}
		break
	}
	if start < 0 {
		start, end = def.Content[0].Line-1, def.Content[0].Line-1
	}
	if indent < 1 || indent > 32 || start < 0 || start > len(lines) || end < start || end > len(lines) {
		return nil, errors.New("netplan DNS 字段边界未确认")
	}
	servers, _ := json.Marshal(config.Servers)
	domains := append(append([]string{}, config.Search...), routes...)
	search, _ := json.Marshal(domains)
	prefix := strings.Repeat(" ", indent)
	block := prefix + "nameservers:\n" + prefix + "  addresses: " + string(servers) + "\n" + prefix + "  search: " + string(search) + "\n"
	out := []byte(strings.Join(lines[:start], "") + block + strings.Join(lines[end:], ""))
	if len(out) > hostdns.SourceLimit {
		return nil, errors.New("netplan DNS 候选超过容量上限")
	}
	if _, err = netplanDocument(out); err != nil {
		return nil, err
	}
	return out, nil
}

func netplanEditedSource(s *netplanSnapshot, iface string, config hostdns.Config, routes []string) (networkSource, dnsFile, error) {
	var selected *networkSource
	withDNS := 0
	for i := range s.files {
		network, err := netplanDocument(s.files[i].File.Data)
		if err != nil {
			return networkSource{}, dnsFile{}, err
		}
		def := netplanField(netplanField(network, "ethernets"), iface)
		if def == nil {
			continue
		}
		if netplanField(def, "nameservers") != nil {
			withDNS++
			selected = &s.files[i]
		} else if withDNS == 0 {
			selected = &s.files[i]
		}
	}
	if selected == nil || withDNS > 1 || filepath.Dir(selected.Path) != "/etc/netplan" {
		return networkSource{}, dnsFile{}, errors.New("所选 netplan DNS 须由单一本机 /etc 源字段提供")
	}
	lower := strings.ToLower(filepath.Base(selected.Path) + "\n" + string(selected.File.Data))
	if strings.Contains(lower, "cloud-init") || strings.Contains(lower, "automatically generated") || strings.Contains(lower, "do not edit") {
		return networkSource{}, dnsFile{}, errors.New("netplan 源仍标记为外部生成，不能接管其输出")
	}
	after := selected.File
	var err error
	after.Data, err = renderNetplanDNS(selected.File.Data, iface, config, routes)
	return *selected, after, err
}

func stripNetworkDNS(raw []byte) ([]byte, error) {
	var out strings.Builder
	section := ""
	for _, physical := range strings.SplitAfter(string(raw), "\n") {
		line := strings.TrimSpace(physical)
		if strings.HasSuffix(line, "\\") {
			return nil, errors.New("原生生成配置含未支持的连续行")
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
		}
		key, _, found := strings.Cut(line, "=")
		if section == "Network" && found && (strings.TrimSpace(key) == "DNS" || strings.TrimSpace(key) == "Domains") {
			continue
		}
		out.WriteString(physical)
	}
	return []byte(out.String()), nil
}
