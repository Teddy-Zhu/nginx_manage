package nginxconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/limits"
)

const wafPrefix = "# nginxpanel:waf "

var wafMethod = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)

type WAFPath struct {
	Match string `json:"match"`
	Path  string `json:"path"`
}
type WAFInput struct {
	BaseVersion int64 `json:"base_version"`
	WAFConfig
}
type WAFConfig struct {
	Metadata     ResourceMetadata `json:"metadata"`
	Rate         int              `json:"rate"`
	RateUnit     string           `json:"rate_unit"`
	Burst        int              `json:"burst"`
	Connections  int              `json:"connections"`
	RejectStatus int              `json:"reject_status"`
	Observe      bool             `json:"observe"`
	BodySize     string           `json:"body_size"`
	Methods      []string         `json:"methods"`
	DeniedPaths  []WAFPath        `json:"denied_paths"`
	ExemptPaths  []WAFPath        `json:"exempt_paths"`
}
type WAFPolicy struct {
	ID           string    `json:"id"`
	Resources    []string  `json:"resources"`
	HTTPFileID   string    `json:"http_file_id"`
	ServerFileID string    `json:"server_file_id"`
	Config       WAFConfig `json:"config"`
	Editable     bool      `json:"editable"`
	Reason       string    `json:"reason"`
}

func wafPath(id, kind string) string { return "security/waf/" + id + "/" + kind + ".conf" }
func wafVar(id, suffix string) string {
	return "$nginxpanel_waf_" + strings.ReplaceAll(id, "-", "") + "_" + suffix
}
func wafZone(id, suffix string) string {
	return "nginxpanel_waf_" + strings.ReplaceAll(id, "-", "") + "_" + suffix
}
func wafFileID(name string) (string, string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "security" || parts[1] != "waf" || !resourceID.MatchString(parts[2]) || (parts[3] != "http.conf" && parts[3] != "server.conf") {
		return "", "", false
	}
	return parts[2], strings.TrimSuffix(parts[3], ".conf"), true
}
func validateWAF(in WAFConfig) error {
	if err := validateMetadata(in.Metadata); err != nil {
		return err
	}
	if in.Rate < 0 || in.Rate > 100000 || in.Burst < 0 || in.Burst > 10000 || in.Connections < 0 || in.Connections > 65535 {
		return errors.New("限速、突发或并发数超出范围")
	}
	if in.RateUnit != "r/s" && in.RateUnit != "r/m" {
		return errors.New("限速单位须为 r/s 或 r/m")
	}
	if in.Rate == 0 && in.Burst != 0 {
		return errors.New("关闭限速时突发额度须为零")
	}
	if in.RejectStatus != 429 && in.RejectStatus != 503 {
		return errors.New("限流拒绝状态须为 429 或 503")
	}
	if in.BodySize != "" && !sizeValue.MatchString(in.BodySize) {
		return errors.New("请求体大小无效")
	}
	if len(in.Methods) > 16 {
		return errors.New("方法数量超过限制")
	}
	seen := map[string]bool{}
	for _, method := range in.Methods {
		if !wafMethod.MatchString(method) || seen[method] {
			return errors.New("方法须为不重复的大写名称")
		}
		seen[method] = true
	}
	for _, paths := range [][]WAFPath{in.DeniedPaths, in.ExemptPaths} {
		if len(paths) > limits.WAFPaths {
			return errors.New("路径规则数量超过限制")
		}
		seen := map[string]bool{}
		for _, item := range paths {
			if item.Match != "exact" && item.Match != "prefix" {
				return errors.New("路径匹配须为 exact 或 prefix")
			}
			if !utf8.ValidString(item.Path) || len(item.Path) > 512 || !strings.HasPrefix(item.Path, "/") || strings.ContainsAny(item.Path, "\x00\r\n\t ?#\\") {
				return errors.New("路径须为不含查询参数的绝对路径")
			}
			key := item.Match + ":" + item.Path
			if seen[key] {
				return errors.New("路径规则重复")
			}
			seen[key] = true
		}
	}
	return nil
}
func wafHeader(metadata ResourceMetadata) string {
	b, _ := json.Marshal(metadata)
	return wafPrefix + string(b)
}
func wafMetadata(content string) (ResourceMetadata, int, int, error) {
	var out ResourceMetadata
	start, end := -1, -1
	l := lexer{source: content, line: 1}
	for {
		token, err := l.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, start, end, err
		}
		if token.Kind == "comment" && strings.HasPrefix(token.Value, wafPrefix) {
			if start >= 0 {
				return out, start, end, errors.New("WAF 元信息重复")
			}
			value, err := decodeMetadata(strings.TrimPrefix(token.Value, wafPrefix))
			if err != nil {
				return out, start, end, err
			}
			out = value
			start, end = token.Start, token.End
		}
	}
	if start < 0 {
		return out, start, end, errors.New("文件未登记为受管 WAF 策略")
	}
	return out, start, end, nil
}
func pathPattern(item WAFPath) string {
	out := "~^" + regexp.QuoteMeta(item.Path)
	if item.Match == "exact" {
		out += "$"
	}
	return out
}
func readPathPattern(pattern string) (WAFPath, error) {
	if !strings.HasPrefix(pattern, "~^") {
		return WAFPath{}, errors.New("路径匹配不是受管表达式")
	}
	original := pattern
	pattern = strings.TrimPrefix(pattern, "~^")
	out := WAFPath{Match: "prefix"}
	slashes := 0
	for i := len(pattern) - 2; i >= 0 && pattern[i] == '\\'; i-- {
		slashes++
	}
	if strings.HasSuffix(pattern, "$") && slashes%2 == 0 {
		pattern = strings.TrimSuffix(pattern, "$")
		out.Match = "exact"
	}
	var value strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			i++
			if i == len(pattern) {
				return out, errors.New("路径表达式无效")
			}
		}
		value.WriteByte(pattern[i])
	}
	out.Path = value.String()
	if pathPattern(out) != original {
		return out, errors.New("路径包含非受管正则")
	}
	return out, nil
}
func wafSource(id string, in WAFConfig) (string, string) {
	var http, server strings.Builder
	emitMap := func(source, target string, rows [][2]string) {
		http.WriteString("map " + quote(source) + " " + target + " {\n    volatile;\n")
		for _, row := range rows {
			http.WriteString("    " + argsText([]string{row[0], row[1]}) + ";\n")
		}
		http.WriteString("}\n")
	}
	exempt, denied, key, method := wafVar(id, "exempt"), wafVar(id, "path"), wafVar(id, "key"), wafVar(id, "method")
	rows := [][2]string{{"default", "0"}}
	for _, item := range in.ExemptPaths {
		rows = append(rows, [2]string{pathPattern(item), "1"})
	}
	emitMap("$uri", exempt, rows)
	rows = [][2]string{{"default", "0"}}
	for _, item := range in.DeniedPaths {
		rows = append(rows, [2]string{pathPattern(item), "1"})
	}
	emitMap("$uri", denied, rows)
	emitMap(exempt, key, [][2]string{{"default", "$binary_remote_addr"}, {"1", ""}})
	rows = [][2]string{{"default", "0"}}
	if len(in.Methods) > 0 {
		rows = [][2]string{{"default", "1"}, {"~^1:", "0"}}
		for _, name := range in.Methods {
			rows = append(rows, [2]string{"~^0:" + name + "$", "0"})
		}
	}
	emitMap(exempt+":$request_method", method, rows)
	if in.Rate > 0 {
		http.WriteString(fmt.Sprintf("limit_req_zone %s zone=%s:1m rate=%d%s;\n", key, wafZone(id, "req"), in.Rate, in.RateUnit))
	}
	if in.Connections > 0 {
		http.WriteString("limit_conn_zone " + key + " zone=" + wafZone(id, "conn") + ":1m;\n")
	}
	server.WriteString(wafHeader(in.Metadata) + "\nset $nginxpanel_waf_policy " + quote(id) + ";\nset $nginxpanel_waf_reason \"\";\n")
	server.WriteString("if (" + denied + ") {\n    set $nginxpanel_waf_reason path;\n    return 403;\n}\nif (" + method + ") {\n    set $nginxpanel_waf_reason method;\n    return 405;\n}\n")
	if in.BodySize != "" {
		server.WriteString("client_max_body_size " + in.BodySize + ";\n")
	}
	observe := "off"
	if in.Observe {
		observe = "on"
	}
	if in.Rate > 0 {
		server.WriteString("limit_req zone=" + wafZone(id, "req"))
		if in.Burst > 0 {
			server.WriteString(fmt.Sprintf(" burst=%d nodelay", in.Burst))
		}
		server.WriteString(fmt.Sprintf(";\nlimit_req_status %d;\nlimit_req_log_level warn;\nlimit_req_dry_run %s;\n", in.RejectStatus, observe))
	}
	if in.Connections > 0 {
		server.WriteString(fmt.Sprintf("limit_conn %s %d;\nlimit_conn_status %d;\nlimit_conn_log_level warn;\nlimit_conn_dry_run %s;\n", wafZone(id, "conn"), in.Connections, in.RejectStatus, observe))
	}
	return http.String(), server.String()
}
func sourceNodes(source string) ([]*Node, error) {
	l := lexer{source: source, line: 1}
	nodes, _, err := l.nodes(0)
	return nodes, err
}
func sameNodes(left, right []*Node) bool {
	if len(left) != len(right) {
		return false
	}
	for i, node := range left {
		other := right[i]
		if node.Name != other.Name || node.ArgumentComments || len(node.Args) != len(other.Args) || (node.Open >= 0) != (other.Open >= 0) {
			return false
		}
		for j, arg := range node.Args {
			if arg.Value != other.Args[j].Value {
				return false
			}
		}
		if !sameNodes(node.Children, other.Children) {
			return false
		}
	}
	return true
}
func wafDocument(id string, httpFile, serverFile File) (WAFPolicy, error) {
	out := WAFPolicy{ID: id, Resources: []string{}, HTTPFileID: httpFile.ID, ServerFileID: serverFile.ID, Editable: true, Config: WAFConfig{RateUnit: "r/s", RejectStatus: 429, Methods: []string{}, DeniedPaths: []WAFPath{}, ExemptPaths: []WAFPath{}}}
	metadata, _, _, err := wafMetadata(serverFile.Content)
	out.Config.Metadata = metadata
	if err != nil {
		return out, err
	}
	httpNodes, err := sourceNodes(httpFile.Content)
	if err != nil {
		return out, err
	}
	serverNodes, err := sourceNodes(serverFile.Content)
	if err != nil {
		return out, err
	}
	for _, node := range httpNodes {
		if node.Name == "map" && len(node.Args) == 2 {
			switch node.Args[1].Value {
			case wafVar(id, "exempt"), wafVar(id, "path"):
				for _, row := range node.Children {
					if row.Name == "default" || row.Name == "volatile" {
						continue
					}
					item, err := readPathPattern(row.Name)
					if err != nil {
						return out, err
					}
					if node.Args[1].Value == wafVar(id, "exempt") {
						out.Config.ExemptPaths = append(out.Config.ExemptPaths, item)
					} else {
						out.Config.DeniedPaths = append(out.Config.DeniedPaths, item)
					}
				}
			case wafVar(id, "method"):
				for _, row := range node.Children {
					if strings.HasPrefix(row.Name, "~^0:") && strings.HasSuffix(row.Name, "$") {
						out.Config.Methods = append(out.Config.Methods, strings.TrimSuffix(strings.TrimPrefix(row.Name, "~^0:"), "$"))
					}
				}
			}
		}
		if node.Name == "limit_req_zone" {
			for _, arg := range node.Args {
				if strings.HasPrefix(arg.Value, "rate=") {
					rate := strings.TrimPrefix(arg.Value, "rate=")
					if len(rate) < 4 {
						return out, errors.New("限速参数无效")
					}
					out.Config.RateUnit = rate[len(rate)-3:]
					out.Config.Rate, _ = strconv.Atoi(rate[:len(rate)-3])
				}
			}
		}
	}
	for _, node := range serverNodes {
		if len(node.Args) == 0 {
			continue
		}
		value := node.Args[len(node.Args)-1].Value
		switch node.Name {
		case "client_max_body_size":
			out.Config.BodySize = value
		case "limit_conn":
			out.Config.Connections, _ = strconv.Atoi(value)
		case "limit_req_status", "limit_conn_status":
			out.Config.RejectStatus, _ = strconv.Atoi(value)
		case "limit_req_dry_run", "limit_conn_dry_run":
			out.Config.Observe = value == "on"
		case "limit_req":
			for _, arg := range node.Args {
				if strings.HasPrefix(arg.Value, "burst=") {
					out.Config.Burst, _ = strconv.Atoi(strings.TrimPrefix(arg.Value, "burst="))
				}
			}
		}
	}
	if err := validateWAF(out.Config); err != nil {
		return out, err
	}
	expectedHTTP, expectedServer := wafSource(id, out.Config)
	expectedHTTPNodes, _ := sourceNodes(expectedHTTP)
	expectedServerNodes, _ := sourceNodes(expectedServer)
	if !sameNodes(httpNodes, expectedHTTPNodes) || !sameNodes(serverNodes, expectedServerNodes) {
		return out, errors.New("存在非受管指令、参数注释或冲突定义，请使用原生配置")
	}
	return out, nil
}
func (p *Parsed) projectWAF() {
	byID := map[string]map[string]File{}
	order := []string{}
	for _, file := range p.Tree.Files {
		id, kind, ok := wafFileID(file.Path)
		if !ok {
			continue
		}
		if byID[id] == nil {
			byID[id] = map[string]File{}
			order = append(order, id)
		}
		byID[id][kind] = file
	}
	contexts, uses := p.includeContexts()
	p.Tree.WAFPolicies = []WAFPolicy{}
	if len(order) > limits.WAFPolicies {
		for _, file := range p.Tree.Files {
			if file.Path == "nginx.conf" {
				p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{FileID: file.ID, Line: 1, Code: "waf_limit", Message: "WAF 策略数量超过限制"})
				break
			}
		}
	}
	for _, id := range order {
		files := byID[id]
		item, err := wafDocument(id, files["http"], files["server"])
		if err != nil {
			item.Editable = false
			item.Reason = err.Error()
		}
		if files["http"].ID == "" || files["server"].ID == "" {
			item.Editable = false
			item.Reason = "策略配置文件不完整"
		}
		if len(contexts[wafPath(id, "http")]) != 1 || !contexts[wafPath(id, "http")]["http"] || uses[wafPath(id, "http")] != 1 {
			item.Editable = false
			item.Reason = "策略定义须唯一接入 HTTP 上下文"
		}
		for context := range contexts[wafPath(id, "server")] {
			if context != "http/server" {
				item.Editable = false
				item.Reason = "WAF 只允许绑定 HTTP 站点"
			}
		}
		p.Tree.WAFPolicies = append(p.Tree.WAFPolicies, item)
	}
	p.projectWAFBindings()
}
func (p *Parsed) knownWAFInclude(node *Node) bool {
	if node.Name != "include" || len(node.Args) != 1 {
		return false
	}
	for _, policy := range p.Tree.WAFPolicies {
		if policy.Editable && node.Args[0].Value == wafPath(policy.ID, "server") {
			return true
		}
	}
	return false
}

// Disabled policies retain their native source in the revision. The runtime
// excludes both definition and binding files, including their module needs.
func (p *Parsed) DisabledWAFFiles() map[string]bool {
	out := map[string]bool{}
	for _, file := range p.Tree.Files {
		id, kind, ok := wafFileID(file.Path)
		if !ok || kind != "server" {
			continue
		}
		metadata, _, _, err := wafMetadata(file.Content)
		if err == nil && !metadata.Enabled {
			out[wafPath(id, "http")] = true
			out[file.Path] = true
		}
	}
	return out
}
func (p *Parsed) RuntimeFileEnabled(name string) bool { return !p.runtimeExcluded[name] }
func (p *Parsed) matchesField(node *Node, name string, spec fieldSpec) bool {
	if node.Name != spec.directive {
		return false
	}
	if name == "access_list" {
		return p.knownAccessInclude(node)
	}
	if name == "waf_policy" {
		return p.knownWAFInclude(node)
	}
	return true
}
func (p *Parsed) projectWAFBindings() {
	if len(p.Tree.WAFPolicies) == 0 {
		return
	}
	byPath := map[string]*Document{}
	for _, doc := range p.Documents {
		byPath[doc.File.Path] = doc
	}
	known := map[string]map[string]bool{}
	unknown := map[string]bool{}
	count := 0
	var walk func([]*Node, string, int) error
	walk = func(nodes []*Node, owner string, depth int) error {
		if depth > limits.Depth {
			return fmt.Errorf("WAF 引用展开超过层级限制")
		}
		for _, node := range nodes {
			count++
			if count > limits.Directives {
				return fmt.Errorf("WAF 引用展开超过指令限制")
			}
			nextOwner := owner
			if node.Name == "server" && node.Open >= 0 {
				nextOwner = node.ResourceID
			}
			if node.Name == "include" && len(node.Args) == 1 {
				for name, doc := range byPath {
					matched, _ := path.Match(node.Args[0].Value, name)
					if !matched {
						continue
					}
					id, kind, managed := wafFileID(name)
					if managed && kind == "server" {
						if owner == "" {
							unknown[id] = true
						} else {
							if known[id] == nil {
								known[id] = map[string]bool{}
							}
							known[id][owner] = true
						}
					}
					if err := walk(doc.Nodes, owner, depth+1); err != nil {
						return err
					}
				}
			}
			if err := walk(node.Children, nextOwner, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	main := byPath["nginx.conf"]
	err := walk(main.Nodes, "", 0)
	for i := range p.Tree.WAFPolicies {
		item := &p.Tree.WAFPolicies[i]
		item.Resources = []string{}
		for id := range known[item.ID] {
			item.Resources = append(item.Resources, id)
		}
		sort.Strings(item.Resources)
		if unknown[item.ID] {
			item.Editable = false
			item.Reason = "存在未登记资源标记的站点引用，请使用原生配置"
		}
		if err != nil {
			item.Editable = false
			item.Reason = err.Error()
		}
	}
}
