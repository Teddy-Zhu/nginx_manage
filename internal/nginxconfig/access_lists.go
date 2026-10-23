package nginxconfig

import (
	"context"
	"encoding/json"
	"io"
	"path"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const accessListPrefix = "# nginxpanel:access-list "

func accessListPath(id string) string { return "security/acl/" + id + ".conf" }

type AccessList struct {
	ID             string   `json:"id"`
	FileID         string   `json:"file_id"`
	Name           string   `json:"name"`
	Notes          string   `json:"notes"`
	Mode           string   `json:"mode"`
	Entries        []string `json:"entries"`
	Countries      []string `json:"countries"`
	GeoIPUpdatedAt int64    `json:"geoip_updated_at"`
	Editable       bool     `json:"editable"`
	Reason         string   `json:"reason"`
}
type AccessListRequest struct {
	BaseVersion int64    `json:"base_version"`
	Name        string   `json:"name"`
	Notes       string   `json:"notes"`
	Mode        string   `json:"mode"`
	Entries     []string `json:"entries"`
	Countries   []string `json:"countries"`
}
type accessMetadata struct {
	Name           string   `json:"name"`
	Notes          string   `json:"notes"`
	Mode           string   `json:"mode,omitempty"`
	Entries        []string `json:"entries,omitempty"`
	Countries      []string `json:"countries,omitempty"`
	GeoIPUpdatedAt int64    `json:"geoip_updated_at,omitempty"`
}

func accessHeader(in accessMetadata) string {
	b, _ := json.Marshal(in)
	return accessListPrefix + string(b)
}
func accessDocument(file File, geoFile File) (AccessList, []*Node, int, int) {
	id := strings.TrimSuffix(strings.TrimPrefix(file.Path, "security/acl/"), ".conf")
	r := AccessList{ID: id, FileID: file.ID, Name: id, Entries: []string{}, Countries: []string{}, Editable: true}
	var metadata accessMetadata
	start, end := -1, -1
	l := lexer{source: file.Content, line: 1}
	for {
		token, err := l.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			r.Editable = false
			r.Reason = "配置语法无效"
			return r, nil, start, end
		}
		if token.Kind == "comment" && strings.HasPrefix(token.Value, accessListPrefix) {
			d := json.NewDecoder(strings.NewReader(strings.TrimPrefix(token.Value, accessListPrefix)))
			d.DisallowUnknownFields()
			if start >= 0 || d.Decode(&metadata) != nil || d.Decode(new(any)) != io.EOF || validateMetadata(ResourceMetadata{Name: metadata.Name, Notes: metadata.Notes}) != nil {
				r.Editable = false
				r.Reason = "访问列表元信息无效"
				return r, nil, start, end
			}
			start, end = token.Start, token.End
			r.Name, r.Notes = metadata.Name, metadata.Notes
		}
	}
	if start < 0 {
		r.Editable = false
		r.Reason = "文件未登记为受管访问列表"
		return r, nil, start, end
	}
	if len(metadata.Countries) > 0 {
		return accessGeoDocument(r, metadata, file, geoFile), nil, start, end
	}
	l = lexer{source: file.Content, line: 1}
	nodes, _, err := l.nodes(0)
	if err != nil || len(nodes) == 0 {
		r.Editable = false
		r.Reason = "访问列表规则为空或语法无效"
		return r, nodes, start, end
	}
	last := nodes[len(nodes)-1]
	rule := ""
	if last.Name == "deny" {
		r.Mode = "allowlist"
		rule = "allow"
	} else if last.Name == "allow" {
		r.Mode = "denylist"
		rule = "deny"
	}
	if rule == "" || len(last.Args) != 1 || last.Args[0].Value != "all" || last.ArgumentComments || last.Open >= 0 {
		r.Editable = false
		r.Reason = "末条规则必须明确允许或拒绝其余地址"
		return r, nodes, start, end
	}
	for _, node := range nodes[:len(nodes)-1] {
		if node.Name != rule || node.Open >= 0 || node.ArgumentComments || len(node.Args) != 1 || validateField("trusted_sources", nodeValues(node), "http") != nil {
			r.Editable = false
			r.Reason = "规则混合或包含无法映射的条件，请使用原生配置"
			return r, nodes, start, end
		}
		r.Entries = append(r.Entries, node.Args[0].Value)
	}
	return r, nodes, start, end
}
func accessLists(files []File) []AccessList {
	out := []AccessList{}
	byPath := map[string]File{}
	for _, file := range files {
		byPath[file.Path] = file
	}
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "security/acl/") || !strings.HasSuffix(file.Path, ".conf") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(file.Path, "security/acl/"), ".conf")
		if !resourceID.MatchString(id) {
			continue
		}
		r, _, _, _ := accessDocument(file, byPath[accessGeoPath(id)])
		out = append(out, r)
	}
	return out
}
func (p *Parsed) knownAccessInclude(node *Node) bool {
	if node.Name != "include" || len(node.Args) != 1 {
		return false
	}
	for _, list := range p.Tree.AccessLists {
		if node.Args[0].Value == accessListPath(list.ID) && list.Editable {
			return true
		}
	}
	return false
}
func (s *Service) AccessList(ctx context.Context, p auth.Principal, requestID, key, id, action string, in AccessListRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets", "security.write"); err != nil {
		return SaveResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Action, ID string
		Input      AccessListRequest
	}{action, id, in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	if action != "create" && action != "update" && action != "delete" {
		return SaveResult{}, fault.Invalid("访问列表操作无效")
	}
	if action != "delete" {
		if err := validateMetadata(ResourceMetadata{Name: in.Name, Notes: in.Notes}); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
		if in.Mode != "allowlist" && in.Mode != "denylist" {
			return SaveResult{}, fault.Invalid("访问列表模式无效")
		}
		if len(in.Entries) > 128 {
			return SaveResult{}, fault.Invalid("地址数量超过 128")
		}
		for _, entry := range in.Entries {
			if err := validateField("trusted_sources", []string{entry}, "http"); err != nil {
				return SaveResult{}, fault.Invalid(err.Error())
			}
		}
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	files := append([]File(nil), tree.Files...)
	index := -1
	for i := range files {
		if files[i].Path == accessListPath(id) {
			index = i
			break
		}
	}
	if action == "create" {
		id = secure.ID()
	} else if !resourceID.MatchString(id) || index < 0 {
		return SaveResult{}, ErrNotFound
	}
	if action == "delete" && hasGeoAccessList(tree, id) {
		return s.saveGeoAccessList(ctx, p, requestID, key, id, action, in, tree, index, digest)
	}
	if action == "delete" {
		parsed, err := Parse(files, s.Policy)
		if err != nil {
			return SaveResult{}, err
		}
		referenced := false
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if node.Name == "include" && len(node.Args) == 1 {
					match, _ := path.Match(node.Args[0].Value, accessListPath(id))
					referenced = referenced || match
				}
				walk(node.Children)
			}
		}
		for _, doc := range parsed.Documents {
			walk(doc.Nodes)
		}
		if referenced {
			return SaveResult{}, fault.Conflict("访问列表仍被引用，请先解除绑定")
		}
		files = append(files[:index], files[index+1:]...)
	} else {
		return s.saveAccessList(ctx, p, requestID, key, id, action, in, tree, index, digest)
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}

func (s *Service) saveAccessList(ctx context.Context, p auth.Principal, requestID, key, id, action string, in AccessListRequest, tree Tree, index int, digest string) (SaveResult, error) {
	files := append([]File(nil), tree.Files...)
	if len(in.Countries) > 0 || index >= 0 && hasGeoAccessList(tree, id) {
		return s.saveGeoAccessList(ctx, p, requestID, key, id, action, in, tree, index, digest)
	}
	{
		rule, last := "deny", "allow"
		if in.Mode == "allowlist" {
			rule, last = "allow", "deny"
		}
		rows := []string{}
		for _, entry := range in.Entries {
			rows = append(rows, rule+" "+quote(entry)+";")
		}
		rows = append(rows, last+" all;")
		header := accessHeader(accessMetadata{Name: in.Name, Notes: in.Notes})
		if action == "create" {
			files = append(files, File{ID: secure.ID(), Path: accessListPath(id), Content: header + "\n" + strings.Join(rows, "\n") + "\n"})
		} else {
			list, nodes, start, end := accessDocument(files[index], File{})
			if !list.Editable {
				return SaveResult{}, fault.Conflict(list.Reason)
			}
			edits := []Edit{{start, end, header}}
			for i, node := range nodes {
				replacement := ""
				if i < len(rows) {
					replacement = rows[i]
				}
				edits = append(edits, Edit{node.Start, node.End, replacement})
			}
			if len(rows) > len(nodes) {
				at := nodes[len(nodes)-1].End
				edits = append(edits, Edit{at, at, "\n" + strings.Join(rows[len(nodes):], "\n")})
			}
			text, err := applyEdits(files[index].Content, edits)
			if err != nil {
				return SaveResult{}, err
			}
			files[index].Content = text
		}
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}
