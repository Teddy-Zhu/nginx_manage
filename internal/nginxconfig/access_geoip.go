package nginxconfig

import (
	"context"
	"errors"
	"net/netip"
	"path"
	"sort"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func accessGeoPath(id string) string { return "security/acl/" + id + "/http.conf" }
func accessGeoVar(id string) string  { return "$nginxpanel_acl_" + strings.ReplaceAll(id, "-", "") }

func hasGeoAccessList(tree Tree, id string) bool {
	for _, list := range tree.AccessLists {
		if list.ID == id {
			return len(list.Countries) > 0
		}
	}
	return false
}

// Country data is frozen into the same immutable revision as its site binding.
// Nginx uses its built-in radix lookup; no runtime downloads or module builds.
func accessGeoSource(id string, metadata accessMetadata, sources []string) (string, string) {
	var geo strings.Builder
	geo.WriteString("geo " + accessGeoVar(id) + " {\n    default 0;\n")
	for _, source := range sources {
		geo.WriteString("    " + source + " 1;\n")
	}
	geo.WriteString("}\n")
	match := "1"
	if metadata.Mode == "allowlist" {
		match = "0"
	}
	server := accessHeader(metadata) + "\nif (" + accessGeoVar(id) + " = " + match + ") { return 403; }\n"
	return geo.String(), server
}

func accessGeoDocument(out AccessList, metadata accessMetadata, server, geo File) AccessList {
	out.Mode, out.Entries, out.Countries, out.GeoIPUpdatedAt = metadata.Mode, metadata.Entries, metadata.Countries, metadata.GeoIPUpdatedAt
	if out.Entries == nil {
		out.Entries = []string{}
	}
	invalid := func() AccessList {
		out.Editable = false
		out.Reason = "国家访问规则存在自定义修改，请检查高级配置"
		return out
	}
	if metadata.Mode != "allowlist" && metadata.Mode != "denylist" || len(metadata.Entries) > 128 || len(metadata.Countries) > 250 || metadata.GeoIPUpdatedAt <= 0 {
		return invalid()
	}
	for _, country := range metadata.Countries {
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return invalid()
		}
	}
	for _, entry := range metadata.Entries {
		if validateField("trusted_sources", []string{entry}, "http") != nil {
			return invalid()
		}
	}
	nodes, err := sourceNodes(geo.Content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "geo" || len(nodes[0].Args) != 1 || nodes[0].Args[0].Value != accessGeoVar(out.ID) {
		return invalid()
	}
	sources := []string{}
	for i, node := range nodes[0].Children {
		if i == 0 && node.Name == "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(node.Name)
		if err != nil || prefix != prefix.Masked() || len(node.Args) != 1 || node.Args[0].Value != "1" || node.Open >= 0 {
			return invalid()
		}
		sources = append(sources, node.Name)
	}
	if len(sources) == 0 {
		return invalid()
	}
	expectedGeo, expectedServer := accessGeoSource(out.ID, metadata, sources)
	geoNodes, _ := sourceNodes(expectedGeo)
	serverNodes, err := sourceNodes(server.Content)
	expectedServerNodes, _ := sourceNodes(expectedServer)
	if err != nil || !sameNodes(nodes, geoNodes) || !sameNodes(serverNodes, expectedServerNodes) {
		return invalid()
	}
	// Manual entries must participate in the lookup as well as appear in the form.
	seen := map[string]bool{}
	for _, source := range sources {
		seen[source] = true
	}
	for _, entry := range metadata.Entries {
		prefix, err := accessPrefix(entry)
		if err != nil || !seen[prefix] {
			return invalid()
		}
	}
	return out
}

func accessPrefix(value string) (string, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(address, address.BitLen()).String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", errors.New("国家访问列表中的地址须为 IP 或 CIDR")
	}
	return prefix.Masked().String(), nil
}

func (s *Service) saveGeoAccessList(ctx context.Context, principal auth.Principal, requestID, key, id, action string, in AccessListRequest, tree Tree, index int, digest string) (SaveResult, error) {
	if action != "create" {
		for _, list := range tree.AccessLists {
			if list.ID == id && !list.Editable {
				return SaveResult{}, fault.Conflict(list.Reason)
			}
		}
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return SaveResult{}, err
	}
	edits := map[string][]Edit{}
	wasGeo := hasGeoAccessList(tree, id)
	// Remove the definition include when deleting or returning to an IP-only list.
	if wasGeo && (action == "delete" || len(in.Countries) == 0) {
		for _, doc := range parsed.Documents {
			if doc.File.Path == accessListPath(id) || doc.File.Path == accessGeoPath(id) {
				continue
			}
			var walk func([]*Node) error
			walk = func(nodes []*Node) error {
				for _, node := range nodes {
					if node.Name == "include" && len(node.Args) == 1 {
						pattern := node.Args[0].Value
						definition, _ := path.Match(pattern, accessGeoPath(id))
						binding, _ := path.Match(pattern, accessListPath(id))
						if binding && action == "delete" || definition && pattern != accessGeoPath(id) {
							return fault.Conflict("访问列表仍被引用，请先解除绑定")
						}
						if definition {
							edits[doc.File.ID] = append(edits[doc.File.ID], Edit{node.Start, node.End, ""})
						}
					} else {
						for _, arg := range node.Args {
							if strings.Contains(arg.Value, accessGeoVar(id)) {
								return fault.Conflict("国家访问变量仍被原生配置引用")
							}
						}
					}
					if err := walk(node.Children); err != nil {
						return err
					}
				}
				return nil
			}
			if err := walk(doc.Nodes); err != nil {
				return SaveResult{}, err
			}
		}
	}
	files, err := parsed.editFiles(edits)
	if err != nil {
		return SaveResult{}, err
	}
	kept := []File{}
	for _, file := range files {
		if file.Path == accessGeoPath(id) || action == "delete" && file.Path == accessListPath(id) {
			continue
		}
		kept = append(kept, file)
	}
	files = kept
	if action == "delete" {
		return s.save(ctx, principal, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
	}
	if len(in.Countries) == 0 {
		rule, last := "deny", "allow"
		if in.Mode == "allowlist" {
			rule, last = "allow", "deny"
		}
		body := accessHeader(accessMetadata{Name: in.Name, Notes: in.Notes}) + "\n"
		for _, entry := range in.Entries {
			body += rule + " " + quote(entry) + ";\n"
		}
		body += last + " all;\n"
		for i := range files {
			if files[i].Path == accessListPath(id) {
				files[i].Content = body
			}
		}
		return s.save(ctx, principal, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
	}
	if s.ResolveCountries == nil {
		return SaveResult{}, fault.Unavailable("国家 IP 数据服务未配置")
	}
	countries := map[string]bool{}
	for _, code := range in.Countries {
		countries[strings.ToUpper(strings.TrimSpace(code))] = true
	}
	in.Countries = []string{}
	for code := range countries {
		in.Countries = append(in.Countries, code)
	}
	sort.Strings(in.Countries)
	sources, updatedAt, err := s.ResolveCountries(ctx, in.Countries)
	if err != nil {
		return SaveResult{}, err
	}
	seen := map[string]bool{}
	for _, value := range append(sources, in.Entries...) {
		prefix, err := accessPrefix(value)
		if err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
		seen[prefix] = true
	}
	sources = []string{}
	for prefix := range seen {
		sources = append(sources, prefix)
	}
	sort.Strings(sources)
	geo, server := accessGeoSource(id, accessMetadata{Name: in.Name, Notes: in.Notes, Mode: in.Mode, Entries: in.Entries, Countries: in.Countries, GeoIPUpdatedAt: updatedAt}, sources)
	if action == "create" {
		files = append(files, File{ID: secure.ID(), Path: accessListPath(id), Content: server})
	} else {
		for i := range files {
			if files[i].Path == accessListPath(id) {
				files[i].Content = server
			}
		}
	}
	files = append(files, File{ID: secure.ID(), Path: accessGeoPath(id), Content: geo})
	if !wasGeo {
		for i := range files {
			if files[i].Path != "nginx.conf" {
				continue
			}
			doc := parsed.Documents[files[i].ID]
			var http *Node
			for _, node := range doc.Nodes {
				if node.Name == "http" {
					if http != nil {
						return SaveResult{}, fault.Conflict("需要唯一 HTTP 上下文")
					}
					http = node
				}
			}
			if http == nil {
				return SaveResult{}, fault.Conflict("需要主配置 HTTP 上下文")
			}
			at := http.Open + 1
			files[i].Content = files[i].Content[:at] + "\n    include " + accessGeoPath(id) + ";\n" + files[i].Content[at:]
		}
	}
	return s.save(ctx, principal, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}
