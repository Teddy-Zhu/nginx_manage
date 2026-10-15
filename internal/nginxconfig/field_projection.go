package nginxconfig

import (
	"fmt"
	"sort"
	"strings"
)

func (p *Parsed) project() {
	p.Tree.AccessLists = accessLists(p.Tree.Files)
	seen := map[string]bool{}
	contexts, uses := p.includeContexts()
	for _, doc := range p.Documents {
		root := ""
		for context := range contexts[doc.File.Path] {
			root = context
		}
		var walk func([]*Node, string)
		walk = func(nodes []*Node, context string) {
			for _, node := range nodes {
				if node.ResourceID != "" {
					add := func(message string) {
						p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{doc.File.ID, node.Line, "mapping", message})
					}
					if len(contexts[doc.File.Path]) != 1 || uses[doc.File.Path] > 1 {
						add("资源所在文件未唯一接入配置树，不能确定归属")
						continue
					}
					if seen[node.ResourceID] {
						add("同一资源 ID 出现多次")
						continue
					}
					seen[node.ResourceID] = true
					if context != "http" && context != "stream" {
						add("资源必须位于 http 或 stream 上下文")
						continue
					}
					r := Resource{ID: node.ResourceID, Kind: context, FileID: doc.File.ID, BlockKey: node.ResourceID, Line: node.Line, Fields: map[string]Field{}, Metadata: resourceMetadata(node)}
					for name, spec := range specs(context) {
						_, target, reason := p.target(doc, node, context, spec)
						field := Field{Values: []string{}, Editable: reason == "", Reason: reason, Format: spec.format}
						if target != nil {
							matches := []*Node{}
							if spec.target == "prefix" {
								matches = append(matches, target)
							} else {
								for _, child := range target.Children {
									if child.Name == spec.directive && (name != "access_list" || p.knownAccessInclude(child)) {
										matches = append(matches, child)
									}
								}
							}
							if !spec.multiple && len(matches) > 1 {
								field.Editable = false
								field.Reason = "存在重复指令，请使用原生配置明确修改目标"
							}
							for _, directive := range matches {
								if directive.ArgumentComments {
									field.Editable = false
									field.Reason = "参数中包含注释，请使用原生配置保留其位置"
								}
								values := nodeValues(directive)
								if spec.format == "lines" {
									field.Values = append(field.Values, argsText(values))
								} else {
									field.Values = append(field.Values, values...)
								}
								if name == "access_list" && len(values) == 1 {
									field.Values = []string{strings.TrimSuffix(strings.TrimPrefix(values[0], "security/acl/"), ".conf")}
								}
							}
							if len(field.Values) > 0 {
								if err := validateField(name, field.Values, context); err != nil {
									field.Editable = false
									if field.Reason == "" {
										field.Reason = "当前指令不能可靠映射：" + err.Error()
									}
								}
							}
						}
						r.Fields[name] = field
					}
					p.Tree.Resources = append(p.Tree.Resources, r)
				}
				walk(node.Children, childContext(context, node.Name))
			}
		}
		walk(doc.Nodes, root)
	}
	sort.Slice(p.Tree.Resources, func(i, j int) bool { return p.Tree.Resources[i].ID < p.Tree.Resources[j].ID })
}

func (p *Parsed) Patch(id string, changes map[string][]string, metadata *ResourceMetadata) ([]File, error) {
	resource, doc, server, err := p.resource(id)
	if err != nil {
		return nil, err
	}
	if resource.Kind == "http" && len(changes["upstream"]) == 1 && strings.HasPrefix(changes["upstream"][0], "https://") {
		expanded := map[string][]string{}
		for name, values := range changes {
			expanded[name] = values
		}
		changes = expanded
		for name, values := range map[string][]string{"upstream_tls_verify": {"on"}, "upstream_tls_sni": {"on"}, "upstream_tls_name": {"$proxy_host"}} {
			if _, changed := changes[name]; !changed && len(resource.Fields[name].Values) == 0 {
				changes[name] = values
			}
		}
	}
	edits := map[string][]Edit{}
	type insertion struct {
		file     string
		position int
		indent   string
	}
	inserts := map[insertion][]string{}
	if metadata != nil {
		if err := validateMetadata(*metadata); err != nil {
			return nil, err
		}
		if server.MetadataStart >= 0 {
			edits[doc.File.ID] = append(edits[doc.File.ID], Edit{server.MetadataStart, server.MetadataEnd, metadataLine(*metadata)})
		} else {
			pos := server.MarkerStart
			_, indent := blockInsertion(doc.File.Content, pos)
			edits[doc.File.ID] = append(edits[doc.File.ID], Edit{pos, pos, metadataLine(*metadata) + "\n" + indent})
		}
	}
	names := make([]string, 0, len(changes))
	for name := range changes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := changes[name]
		field, ok := resource.Fields[name]
		if !ok {
			return nil, fmt.Errorf("未知字段：%s", name)
		}
		if !field.Editable {
			return nil, fmt.Errorf("%s: %s", name, field.Reason)
		}
		if err := validateField(name, values, resource.Kind); err != nil {
			return nil, err
		}
		spec := specs(resource.Kind)[name]
		owner, target, reason := p.target(doc, server, resource.Kind, spec)
		if target == nil || reason != "" {
			return nil, fmt.Errorf("字段来源不明确：%s", reason)
		}
		directives := []*Node{}
		if spec.target == "prefix" {
			directives = append(directives, target)
		} else {
			for _, child := range target.Children {
				if child.Name == spec.directive && (name != "access_list" || p.knownAccessInclude(child)) {
					directives = append(directives, child)
				}
			}
		}
		if name == "access_list" && len(values) > 0 {
			found := false
			for _, list := range p.Tree.AccessLists {
				if list.ID == values[0] && list.Editable {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("访问列表未登记或不可可靠映射")
			}
			values = []string{accessListPath(values[0])}
		}
		rows := [][]string{}
		if spec.format == "lines" {
			for _, line := range values {
				args, err := lineTokens(line)
				if err != nil {
					return nil, err
				}
				rows = append(rows, args)
			}
		} else if len(values) > 0 {
			rows = append(rows, values)
		}
		for i, directive := range directives {
			if i >= len(rows) {
				edits[owner.File.ID] = append(edits[owner.File.ID], Edit{directive.Start, directive.End, ""})
				continue
			}
			if len(directive.Args) == 0 {
				return nil, fmt.Errorf("%s 缺少参数", spec.directive)
			}
			args := directive.Args
			edits[owner.File.ID] = append(edits[owner.File.ID], Edit{args[0].Start, args[len(args)-1].End, argsText(rows[i])})
		}
		if len(rows) > len(directives) {
			pos, indent := blockInsertion(owner.File.Content, target.Close)
			key := insertion{owner.File.ID, pos, indent}
			for _, row := range rows[len(directives):] {
				inserts[key] = append(inserts[key], indent+"    "+spec.directive+" "+argsText(row)+";\n")
			}
		}
	}
	for key, lines := range inserts {
		text := strings.Join(lines, "")
		if key.position > 0 && p.Documents[key.file].File.Content[key.position-1] != '\n' {
			text = "\n" + text
		}
		edits[key.file] = append(edits[key.file], Edit{key.position, key.position, text})
	}
	return p.editFiles(edits)
}
