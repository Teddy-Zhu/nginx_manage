package nginxconfig

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type CreateRequest struct {
	BaseVersion     int64             `json:"base_version"`
	Kind            string            `json:"kind"`
	Listen          []string          `json:"listen"`
	Domains         []string          `json:"domains"`
	Upstream        string            `json:"upstream"`
	UpstreamServers []string          `json:"upstream_servers"`
	PreserveHost    bool              `json:"preserve_host"`
	Metadata        *ResourceMetadata `json:"metadata,omitempty"`
}

func (s *Service) CreateResource(ctx context.Context, p auth.Principal, requestID, key string, in CreateRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Action string
		Input  CreateRequest
	}{"create", in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	if in.Kind != "http" && in.Kind != "stream" {
		return SaveResult{}, fault.Invalid("资源类型须为 http 或 stream")
	}
	for field, values := range map[string][]string{"listeners": in.Listen, "upstream": {in.Upstream}} {
		if err := validateField(field, values, in.Kind); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
	}
	if len(in.UpstreamServers) > 0 {
		if err := validateField("upstream_servers", in.UpstreamServers, in.Kind); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
	}
	if in.Kind == "http" {
		if err := validateField("domains", in.Domains, in.Kind); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
	} else if len(in.Domains) > 0 {
		return SaveResult{}, fault.Invalid("Stream 不使用 HTTP 域名")
	}
	metadata := ResourceMetadata{Enabled: true}
	if in.Metadata != nil {
		metadata = *in.Metadata
	}
	if err := validateMetadata(metadata); err != nil {
		return SaveResult{}, fault.Invalid(err.Error())
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return SaveResult{}, err
	}
	var main *Document
	for _, doc := range parsed.Documents {
		if doc.File.Path == "nginx.conf" {
			main = doc
		}
	}
	var parent *Node
	for _, node := range main.Nodes {
		if node.Name == in.Kind {
			if parent != nil {
				return SaveResult{}, fault.Conflict("主配置存在多个同类上下文，请先整理原生配置")
			}
			parent = node
		}
	}
	id := secure.ID()
	upstream := in.Upstream
	group := ""
	var block strings.Builder
	if len(in.UpstreamServers) > 0 {
		group = "nginxpanel_up_" + strings.ReplaceAll(id, "-", "")
		block.WriteString("\n    upstream " + group + " {\n")
		for _, line := range in.UpstreamServers {
			args, _ := lineTokens(line)
			block.WriteString("        server " + argsText(args) + ";\n")
		}
		block.WriteString("    }\n")
		if in.Kind == "http" {
			u, _ := url.Parse(in.Upstream)
			u.Host = group
			upstream = u.String()
		} else {
			upstream = group
		}
	}
	block.WriteString("\n    " + metadataLine(metadata) + "\n    # nginxpanel:resource " + id + "\n    server {\n")
	for _, line := range in.Listen {
		args, _ := lineTokens(line)
		block.WriteString("        listen " + argsText(args) + ";\n")
	}
	if in.Kind == "http" {
		u, _ := url.Parse(in.Upstream)
		host := "$proxy_host"
		if group != "" {
			host = u.Host
		}
		if in.PreserveHost {
			host = "$host"
		}
		block.WriteString("        server_name " + argsText(in.Domains) + ";\n        access_log logs/nginx/" + id + "/access.log nginxpanel_http;\n        error_log logs/nginx/" + id + "/error.log warn;\n        location / {\n            proxy_pass " + quote(upstream) + ";\n            proxy_http_version 1.1;\n            proxy_set_header Host " + host + ";\n            proxy_set_header X-Real-IP $remote_addr;\n            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n            proxy_set_header X-Forwarded-Proto $scheme;\n            proxy_connect_timeout 10s;\n            proxy_read_timeout 60s;\n")
		if u.Scheme == "https" {
			name := "$proxy_host"
			if group != "" {
				name = u.Hostname()
			}
			block.WriteString("            proxy_ssl_verify on;\n            proxy_ssl_server_name on;\n            proxy_ssl_name " + name + ";\n")
		}
		block.WriteString("        }\n")
	} else {
		block.WriteString("        proxy_pass " + quote(upstream) + ";\n        proxy_connect_timeout 10s;\n        proxy_timeout 60s;\n        access_log logs/stream/" + id + "/access.log nginxpanel_stream;\n        error_log logs/stream/" + id + "/error.log warn;\n")
	}
	block.WriteString("    }\n")
	content := main.File.Content
	if parent != nil {
		pos, indent := blockInsertion(content, parent.Close)
		content = content[:pos] + block.String() + indent + content[pos+len(indent):]
	} else {
		content += "\n" + in.Kind + " {" + block.String() + "}\n"
	}
	for i := range tree.Files {
		if tree.Files[i].ID == main.File.ID {
			tree.Files[i].Content = content
		}
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: tree.Files}, digest)
}

type ResourceActionRequest struct {
	BaseVersion int64  `json:"base_version"`
	Name        string `json:"name,omitempty"`
}

func (s *Service) ResourceAction(ctx context.Context, p auth.Principal, requestID, key, id, action string, in ResourceActionRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	if action != "copy" && action != "delete" {
		return SaveResult{}, fault.Invalid("资源操作无效")
	}
	encoded, _ := json.Marshal(struct {
		Action, ID string
		Input      ResourceActionRequest
	}{action, id, in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return SaveResult{}, err
	}
	resource, doc, block, err := parsed.resource(id)
	if err != nil {
		return SaveResult{}, err
	}
	edits := map[string][]Edit{}
	if action == "delete" {
		edits[doc.File.ID] = append(edits[doc.File.ID], Edit{block.Start, block.End, ""}, Edit{block.MarkerStart, block.MarkerEnd, ""})
		if block.MetadataStart >= 0 {
			edits[doc.File.ID] = append(edits[doc.File.ID], Edit{block.MetadataStart, block.MetadataEnd, ""})
		}
	} else {
		metadata := resource.Metadata
		metadata.Enabled = false
		metadata.Name = in.Name
		if metadata.Name == "" {
			name := []rune(resource.Metadata.Name)
			if len(name) > 125 {
				name = name[:125]
			}
			metadata.Name = string(name) + " 副本"
		}
		if err := validateMetadata(metadata); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
		newID := secure.ID()
		body := doc.File.Content[block.Start:block.End]
		copyEdits := []Edit{}
		cloneName, oldGroup := "", ""
		if field := resource.Fields["upstream_servers"]; field.Editable && len(field.Values) > 0 {
			owner, group, reason := parsed.target(doc, block, resource.Kind, specs(resource.Kind)["upstream_servers"])
			if reason != "" || group == nil {
				return SaveResult{}, fault.Conflict("上游组来源已变化")
			}
			oldGroup = group.Args[0].Value
			cloneName = "nginxpanel_up_" + strings.ReplaceAll(newID, "-", "")
			groupText := owner.File.Content[group.Start:group.End]
			groupText, err = applyEdits(groupText, []Edit{{group.Args[0].Start - group.Start, group.Args[0].End - group.Start, cloneName}})
			if err != nil {
				return SaveResult{}, err
			}
			edits[owner.File.ID] = append(edits[owner.File.ID], Edit{group.End, group.End, "\n" + groupText + "\n"})
		}
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if cloneName != "" && node.Name == "proxy_pass" && len(node.Args) == 1 && upstreamName(node.Args[0].Value, resource.Kind) == oldGroup {
					replacement := cloneName
					if resource.Kind == "http" {
						u, _ := url.Parse(node.Args[0].Value)
						u.Host = cloneName
						replacement = u.String()
					}
					copyEdits = append(copyEdits, Edit{node.Args[0].Start - block.Start, node.Args[0].End - block.Start, quote(replacement)})
				}
				if (node.Name == "access_log" || node.Name == "error_log") && len(node.Args) > 0 {
					v := node.Args[0].Value
					prefix := "logs/nginx/"
					if resource.Kind == "stream" {
						prefix = "logs/stream/"
					}
					if strings.HasPrefix(v, prefix+id+"/") {
						copyEdits = append(copyEdits, Edit{node.Args[0].Start - block.Start, node.Args[0].End - block.Start, quote(prefix + newID + "/" + strings.TrimPrefix(v, prefix+id+"/"))})
					}
				}
				walk(node.Children)
			}
		}
		walk(block.Children)
		body, err = applyEdits(body, copyEdits)
		if err != nil {
			return SaveResult{}, err
		}
		text := "\n" + metadataLine(metadata) + "\n# nginxpanel:resource " + newID + "\n" + body + "\n"
		edits[doc.File.ID] = append(edits[doc.File.ID], Edit{block.End, block.End, text})
	}
	files, err := parsed.editFiles(edits)
	if err != nil {
		return SaveResult{}, err
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}
