package nginxconfig

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var httpFields = map[string]string{"domains": "server_name", "listen": "listen", "body_size": "client_max_body_size", "upstream": "proxy_pass", "connect_timeout": "proxy_connect_timeout", "read_timeout": "proxy_read_timeout"}
var streamFields = map[string]string{"listen": "listen", "upstream": "proxy_pass", "connect_timeout": "proxy_connect_timeout", "session_timeout": "proxy_timeout"}

func (p *Parsed) project() {
	seen := map[string]bool{}
	contexts, uses := p.includeContexts()
	for _, doc := range p.Documents {
		rootContext := ""
		for context := range contexts[doc.File.Path] {
			rootContext = context
		}
		var walk func([]*Node, string)
		walk = func(nodes []*Node, context string) {
			for _, n := range nodes {
				ctx := childContext(context, n.Name)
				if n.ResourceID != "" {
					if len(contexts[doc.File.Path]) != 1 || uses[doc.File.Path] > 1 {
						p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{doc.File.ID, n.Line, "mapping", "资源所在文件未唯一接入配置树，不能确定归属"})
						continue
					}
					if seen[n.ResourceID] {
						p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{doc.File.ID, n.Line, "resource_conflict", "同一资源 ID 出现多次"})
						continue
					}
					seen[n.ResourceID] = true
					if context != "http" && context != "stream" {
						p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{doc.File.ID, n.Line, "mapping", "资源必须位于 http 或 stream 上下文"})
						continue
					}
					r := Resource{ID: n.ResourceID, Kind: context, FileID: doc.File.ID, BlockKey: n.ResourceID, Line: n.Line, Fields: map[string]Field{}}
					fields := httpFields
					if context == "stream" {
						fields = streamFields
					}
					for field, directive := range fields {
						target, reason := fieldTarget(n, field, context)
						f := Field{Values: []string{}, Editable: reason == "", Reason: reason}
						if target != nil {
							for _, child := range target.Children {
								if child.Name == directive {
									for _, a := range child.Args {
										f.Values = append(f.Values, a.Value)
									}
								}
							}
						}
						for _, v := range f.Values {
							if strings.Contains(v, "$") {
								f.Editable = false
								f.Reason = "包含变量，需在原生配置中编辑"
							}
						}
						r.Fields[field] = f
					}
					p.Tree.Resources = append(p.Tree.Resources, r)
				}
				walk(n.Children, ctx)
			}
		}
		walk(doc.Nodes, rootContext)
	}
	sort.Slice(p.Tree.Resources, func(i, j int) bool { return p.Tree.Resources[i].ID < p.Tree.Resources[j].ID })
}

func fieldTarget(n *Node, field, kind string) (*Node, string) {
	target := n
	if kind == "http" && (field == "upstream" || field == "connect_timeout" || field == "read_timeout") {
		var locations []*Node
		for _, child := range n.Children {
			if child.Name == "location" && len(child.Args) == 1 && child.Args[0].Value == "/" {
				locations = append(locations, child)
			}
		}
		if len(locations) != 1 {
			return nil, "需要唯一的 location /，请使用原生配置"
		}
		target = locations[0]
	}
	fields := httpFields
	if kind == "stream" {
		fields = streamFields
	}
	count := 0
	for _, child := range target.Children {
		if child.Name == "include" {
			return target, "存在共享 include，字段来源无法唯一确定"
		}
		if child.Name == fields[field] {
			count++
		}
		if child.Name == fields[field] && child.ArgumentComments {
			return target, "参数中包含注释，请使用原生配置保留其位置"
		}
	}
	if count > 1 {
		return target, "存在重复指令，请使用原生配置明确修改目标"
	}
	return target, ""
}

func childContext(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

// Include files inherit their call site's exact context. A resource may never
// acquire identity from a guessed domain or from an ambiguous shared include.
func (p *Parsed) includeContexts() (map[string]map[string]bool, map[string]int) {
	byPath := map[string]*Document{}
	for _, doc := range p.Documents {
		byPath[doc.File.Path] = doc
	}
	contexts := map[string]map[string]bool{}
	uses := map[string]int{}
	var visit func(string, string)
	visit = func(name, context string) {
		uses[name]++
		if contexts[name] == nil {
			contexts[name] = map[string]bool{}
		}
		if contexts[name][context] {
			return
		}
		contexts[name][context] = true
		doc := byPath[name]
		if doc == nil {
			return
		}
		var walk func([]*Node, string)
		walk = func(nodes []*Node, parent string) {
			for _, n := range nodes {
				if n.Name == "include" && len(n.Args) == 1 {
					for candidate := range byPath {
						if matched, _ := path.Match(n.Args[0].Value, candidate); matched {
							visit(candidate, parent)
						}
					}
				}
				walk(n.Children, childContext(parent, n.Name))
			}
		}
		walk(doc.Nodes, context)
	}
	visit("nginx.conf", "")
	return contexts, uses
}

func (p *Parsed) Patch(id string, changes map[string][]string) ([]File, error) {
	var resource *Resource
	for i := range p.Tree.Resources {
		if p.Tree.Resources[i].ID == id {
			resource = &p.Tree.Resources[i]
			break
		}
	}
	if resource == nil {
		return nil, errors.New("资源不存在")
	}
	doc := p.Documents[resource.FileID]
	var block *Node
	var find func([]*Node)
	find = func(nodes []*Node) {
		for _, n := range nodes {
			if n.ResourceID == id {
				block = n
			}
			find(n.Children)
		}
	}
	find(doc.Nodes)
	edits := []Edit{}
	insertions := map[int][]string{}
	fields := httpFields
	if resource.Kind == "stream" {
		fields = streamFields
	}
	for field, values := range changes {
		f, ok := resource.Fields[field]
		if !ok {
			return nil, fmt.Errorf("未知字段：%s", field)
		}
		if !f.Editable {
			return nil, fmt.Errorf("%s: %s", field, f.Reason)
		}
		if err := validateField(field, values, resource.Kind); err != nil {
			return nil, err
		}
		target, _ := fieldTarget(block, field, resource.Kind)
		var directive *Node
		for _, child := range target.Children {
			if child.Name == fields[field] {
				directive = child
			}
		}
		quoted := make([]string, len(values))
		for i, v := range values {
			quoted[i] = quote(v)
		}
		if directive != nil {
			if len(values) == 0 {
				edits = append(edits, Edit{directive.Start, directive.End, ""})
			} else if len(directive.Args) > 0 {
				edits = append(edits, Edit{directive.Args[0].Start, directive.Args[len(directive.Args)-1].End, strings.Join(quoted, " ")})
			} else {
				return nil, errors.New("指令缺少参数，请使用原生配置修正")
			}
		} else if len(values) > 0 {
			pos, indent := blockInsertion(doc.File.Content, target.Close)
			insertions[pos] = append(insertions[pos], indent+"    "+fields[field]+" "+strings.Join(quoted, " ")+";\n")
		}
	}
	for pos, lines := range insertions {
		sort.Strings(lines)
		text := strings.Join(lines, "")
		if pos > 0 && doc.File.Content[pos-1] != '\n' {
			text = "\n" + text
		}
		edits = append(edits, Edit{pos, pos, text})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Start > edits[j].Start })
	content := doc.File.Content
	end := len(content) + 1
	for _, edit := range edits {
		if edit.End > end {
			return nil, errors.New("字段修改范围重叠，请使用原生配置")
		}
		content = content[:edit.Start] + edit.Text + content[edit.End:]
		end = edit.Start
	}
	files := append([]File(nil), p.Tree.Files...)
	for i := range files {
		if files[i].ID == resource.FileID {
			files[i].Content = content
		}
	}
	return files, nil
}

func blockInsertion(source string, close int) (int, string) {
	start := strings.LastIndexByte(source[:close], '\n') + 1
	indent := source[start:close]
	if strings.Trim(indent, " \t\r") == "" {
		return start, indent
	}
	return close, ""
}

var domain = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
var sizeValue = regexp.MustCompile(`^[1-9][0-9]{0,8}[kKmMgG]?$`)
var timeValue = regexp.MustCompile(`^[1-9][0-9]{0,6}(ms|s|m|h)?$`)

func validateField(field string, values []string, kind string) error {
	if len(values) > 32 {
		return errors.New("字段值数量超过限制")
	}
	for _, v := range values {
		if v == "" || len(v) > 1024 || strings.ContainsAny(v, "\x00\r\n;{}\\\"'$") {
			return fmt.Errorf("字段 %s 的值无效", field)
		}
	}
	if field != "domains" && len(values) > 1 {
		if field != "listen" {
			return errors.New("此字段只接受一个值")
		}
	}
	switch field {
	case "domains":
		if len(values) == 0 {
			return errors.New("至少需要一个域名")
		}
		for _, v := range values {
			if !domain.MatchString(v) {
				return errors.New("域名无效")
			}
		}
	case "listen":
		if len(values) == 0 {
			return errors.New("必须设置监听端口")
		}
		if err := validateListen(values, kind); err != nil {
			return err
		}
	case "upstream":
		if len(values) != 1 {
			return errors.New("必须设置上游地址")
		}
		if kind == "http" {
			u, err := url.Parse(values[0])
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return errors.New("HTTP 上游地址无效")
			}
		} else {
			if _, _, err := net.SplitHostPort(values[0]); err != nil {
				return errors.New("Stream 上游须使用主机:端口格式")
			}
		}
	case "body_size":
		if len(values) > 0 && !sizeValue.MatchString(values[0]) {
			return errors.New("请求体大小无效")
		}
	default:
		if len(values) > 0 && !timeValue.MatchString(values[0]) {
			return errors.New("超时时间无效")
		}
	}
	return nil
}

func validateListen(values []string, kind string) error {
	v := values[0]
	port := v
	if strings.Contains(v, ":") {
		host, p, err := net.SplitHostPort(v)
		if err != nil {
			return errors.New("监听须使用 IP 地址和端口")
		}
		if host != "" && net.ParseIP(host) == nil {
			return errors.New("监听地址必须是 IP 地址")
		}
		port = p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("监听端口无效")
	}
	for _, option := range values[1:] {
		if option != "ssl" && option != "http2" && option != "default_server" && option != "ipv6only=on" && option != "ipv6only=off" && !(kind == "stream" && (option == "udp" || option == "reuseport")) {
			return errors.New("监听选项不受支持")
		}
	}
	return nil
}

func quote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

func InitialFiles() []File {
	return []File{{ID: "main", Path: "nginx.conf", Content: "# NginxPanel managed instance\nworker_processes auto;\npid run/nginx.pid;\nerror_log logs/nginx-global/error.log warn;\nevents {\n    worker_connections 1024;\n}\nhttp {\n    default_type application/octet-stream;\n    include http/*.conf;\n}\n"}}
}
