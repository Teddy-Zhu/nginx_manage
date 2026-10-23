package nginxconfig

import (
	"fmt"
	"net/url"
	"strings"

	"nginxpanel/internal/secure"
)

// A single target can be promoted to a site-owned group in one revision.
// Shared/native upstream groups retain the existing explicit editing guard.
func (p *Parsed) patchNewUpstream(id string, changes map[string][]string, metadata *ResourceMetadata) ([]File, error) {
	resource, doc, server, err := p.resource(id)
	if err != nil {
		return nil, err
	}
	if !resource.Fields["upstream"].Editable || len(resource.Fields["upstream"].Values) != 1 {
		return nil, fmt.Errorf("上游地址无法可靠编辑")
	}
	old := resource.Fields["upstream"].Values[0]
	name := upstreamName(old, resource.Kind)
	var exists bool
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if node.Name == "upstream" && len(node.Args) == 1 && node.Args[0].Value == name {
				exists = true
			}
			walk(node.Children)
		}
	}
	for _, document := range p.Documents {
		walk(document.Nodes)
	}
	if exists {
		return nil, fmt.Errorf("上游组被共享或包含自定义配置，请通过高级配置编辑")
	}
	members := changes["upstream_servers"]
	if err := validateField("upstream_servers", members, resource.Kind); err != nil {
		return nil, err
	}
	target := old
	if values, changed := changes["upstream"]; changed {
		if err := validateField("upstream", values, resource.Kind); err != nil {
			return nil, err
		}
		target = values[0]
	}
	group := "nginxpanel_up_" + strings.ReplaceAll(secure.ID(), "-", "")
	forwarded := map[string][]string{}
	for field, values := range changes {
		if field != "upstream_servers" {
			forwarded[field] = values
		}
	}
	if resource.Kind == "http" {
		u, _ := url.Parse(target)
		if u.Scheme == "https" && (len(resource.Fields["upstream_tls_name"].Values) == 0 || resource.Fields["upstream_tls_name"].Values[0] == "$proxy_host") {
			if _, changed := forwarded["upstream_tls_name"]; !changed {
				forwarded["upstream_tls_name"] = []string{u.Hostname()}
			}
		}
		if _, changed := forwarded["request_headers"]; !changed && resource.Fields["request_headers"].Editable {
			headers := append([]string(nil), resource.Fields["request_headers"].Values...)
			for i, header := range headers {
				parts := strings.Fields(header)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Host") && parts[1] == "$proxy_host" {
					headers[i] = "Host " + u.Host
				}
			}
			forwarded["request_headers"] = headers
		}
		u.Host = group
		forwarded["upstream"] = []string{u.String()}
	} else {
		forwarded["upstream"] = []string{group}
	}
	var source strings.Builder
	source.WriteString("\nupstream " + group + " {\n")
	for _, member := range members {
		args, _ := lineTokens(member)
		source.WriteString("    server " + argsText(args) + ";\n")
	}
	source.WriteString("}\n")
	files := append([]File(nil), p.Tree.Files...)
	for i := range files {
		if files[i].ID == doc.File.ID {
			files[i].Content = files[i].Content[:server.End] + source.String() + files[i].Content[server.End:]
		}
	}
	next, err := Parse(files, p.policy)
	if err != nil {
		return nil, err
	}
	return next.Patch(id, forwarded, metadata)
}
