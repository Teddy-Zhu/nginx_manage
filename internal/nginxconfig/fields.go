package nginxconfig

import (
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type fieldSpec struct {
	directive, target, format string
	multiple                  bool
}

var httpFields = map[string]fieldSpec{
	"access_list":    {"include", "server", "value", false},
	"waf_policy":     {"include", "waf", "value", false},
	"https_redirect": {"if", "redirect", "value", false},
	"hsts":           {"add_header", "hsts", "value", false},
	"domains":        {"server_name", "server", "tokens", false}, "listeners": {"listen", "server", "lines", true},
	"upstream": {"proxy_pass", "location", "value", false}, "upstream_servers": {"server", "group", "lines", true}, "location_prefix": {"location", "prefix", "value", false},
	"body_size": {"client_max_body_size", "server", "value", false}, "connect_timeout": {"proxy_connect_timeout", "location", "value", false}, "read_timeout": {"proxy_read_timeout", "location", "value", false}, "send_timeout": {"proxy_send_timeout", "location", "value", false},
	"http_version": {"proxy_http_version", "location", "value", false}, "buffering": {"proxy_buffering", "location", "value", false}, "request_buffering": {"proxy_request_buffering", "location", "value", false},
	"request_headers": {"proxy_set_header", "location", "lines", true}, "response_headers": {"add_header", "server", "lines", true},
	"upstream_tls_verify": {"proxy_ssl_verify", "location", "value", false}, "upstream_tls_sni": {"proxy_ssl_server_name", "location", "value", false}, "upstream_tls_name": {"proxy_ssl_name", "location", "value", false}, "upstream_tls_ca": {"proxy_ssl_trusted_certificate", "location", "value", false},
	"certificate": {"ssl_certificate", "server", "value", false}, "certificate_key": {"ssl_certificate_key", "server", "value", false}, "tls_protocols": {"ssl_protocols", "server", "tokens", false},
	"access_log": {"access_log", "server", "lines", false}, "error_log": {"error_log", "server", "lines", false}, "cache": {"proxy_cache", "location", "value", false},
	"trusted_sources": {"set_real_ip_from", "server", "lines", true}, "real_ip_header": {"real_ip_header", "server", "value", false}, "real_ip_recursive": {"real_ip_recursive", "server", "value", false},
}
var streamFields = map[string]fieldSpec{
	"listeners": {"listen", "server", "lines", true}, "upstream": {"proxy_pass", "server", "value", false}, "upstream_servers": {"server", "group", "lines", true},
	"connect_timeout": {"proxy_connect_timeout", "server", "value", false}, "session_timeout": {"proxy_timeout", "server", "value", false}, "responses": {"proxy_responses", "server", "value", false},
	"access_log": {"access_log", "server", "lines", false}, "error_log": {"error_log", "server", "lines", false},
}

func specs(kind string) map[string]fieldSpec {
	if kind == "stream" {
		return streamFields
	}
	return httpFields
}
func nodeValues(n *Node) []string {
	out := []string{}
	for _, arg := range n.Args {
		out = append(out, arg.Value)
	}
	return out
}
func quote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}
func argsText(values []string) string {
	parts := make([]string, len(values))
	for i, v := range values {
		if strings.ContainsAny(v, " \t\r\n;{}#\"'\\") || v == "" {
			parts[i] = quote(v)
		} else {
			parts[i] = v
		}
	}
	return strings.Join(parts, " ")
}
func lineTokens(line string) ([]string, error) {
	l := lexer{source: line, line: 1}
	values := []string{}
	for {
		t, err := l.next()
		if err == io.EOF {
			break
		}
		if err != nil || t.Kind != "" || strings.ContainsAny(t.Value, "\x00\r\n") {
			return nil, errors.New("参数行无效")
		}
		values = append(values, t.Value)
	}
	if len(values) == 0 || len(values) > 32 {
		return nil, errors.New("参数行为空或参数过多")
	}
	return values, nil
}
func (p *Parsed) resource(id string) (*Resource, *Document, *Node, error) {
	for i := range p.Tree.Resources {
		r := &p.Tree.Resources[i]
		if r.ID != id {
			continue
		}
		doc := p.Documents[r.FileID]
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
		if block == nil {
			return nil, nil, nil, errors.New("资源绑定失效")
		}
		return r, doc, block, nil
	}
	return nil, nil, nil, ErrNotFound
}
func (p *Parsed) target(doc *Document, server *Node, kind string, spec fieldSpec) (*Document, *Node, string) {
	target := server
	if spec.target == "redirect" {
		return doc, server, p.redirectTargetReason(server)
	}
	if spec.target == "hsts" {
		if reason := p.hstsTargetReason(server); reason != "" {
			return doc, server, reason
		}
	}
	if spec.target == "waf" {
		return doc, server, p.wafBindingReason(server)
	}
	if spec.directive == "include" {
		var conflict bool
		var walk func([]*Node, bool)
		walk = func(nodes []*Node, direct bool) {
			for _, node := range nodes {
				if node.Name == "allow" || node.Name == "deny" || node.Name == "satisfy" && (len(node.Args) != 1 || node.Args[0].Value != "all") || node.Name == "include" && (!direct || !p.knownAccessInclude(node) && !p.knownWAFInclude(node)) {
					conflict = true
				}
				walk(node.Children, false)
			}
		}
		walk(server.Children, true)
		if conflict {
			return doc, target, "原生访问规则或子路径覆盖了准入语义，请使用原生配置"
		}
	}
	for _, child := range server.Children {
		if child.Name == "include" && !p.knownAccessInclude(child) && !p.knownWAFInclude(child) {
			return doc, target, "存在共享 include，字段来源无法唯一确定"
		}
		if spec.directive == "client_max_body_size" && p.knownWAFInclude(child) {
			return doc, target, "请求体限制由 WAF 策略管理"
		}
	}
	if spec.target == "location" || spec.target == "prefix" || spec.target == "group" && kind == "http" {
		candidates := []*Node{}
		for _, child := range server.Children {
			if child.Name != "location" {
				continue
			}
			for _, leaf := range child.Children {
				if leaf.Name == "proxy_pass" {
					candidates = append(candidates, child)
					break
				}
			}
		}
		if len(candidates) != 1 {
			return doc, nil, "需要唯一且直接包含 proxy_pass 的转发 location"
		}
		target = candidates[0]
		if len(target.Args) != 1 || !strings.HasPrefix(target.Args[0].Value, "/") {
			return doc, nil, "正则或条件 location 需使用原生配置"
		}
	}
	if spec.target == "group" {
		return p.upstreamGroup(doc, target, kind)
	}
	for _, child := range target.Children {
		if child.Name == "include" && !p.knownAccessInclude(child) && !p.knownWAFInclude(child) {
			return doc, target, "存在共享 include，字段来源无法唯一确定"
		}
	}
	return doc, target, ""
}
func upstreamName(value, kind string) string {
	if kind == "stream" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return u.Host
}
func (p *Parsed) upstreamGroup(doc *Document, proxy *Node, kind string) (*Document, *Node, string) {
	passes := []*Node{}
	for _, n := range proxy.Children {
		if n.Name == "proxy_pass" {
			passes = append(passes, n)
		}
	}
	if len(passes) != 1 || len(passes[0].Args) != 1 {
		return doc, nil, "需要唯一的 proxy_pass"
	}
	name := upstreamName(passes[0].Args[0].Value, kind)
	if !groupName.MatchString(name) {
		return doc, nil, "当前使用单一上游地址"
	}
	contexts, uses := p.includeContexts()
	var owner *Document
	var group *Node
	definitions, references := 0, 0
	uncertainReferences := false
	for _, candidate := range p.Documents {
		var walk func([]*Node, string)
		walk = func(nodes []*Node, context string) {
			for _, n := range nodes {
				if n.Name == "upstream" && context == kind && len(n.Args) == 1 && n.Args[0].Value == name {
					definitions++
					group = n
					owner = candidate
					if len(contexts[candidate.File.Path]) != 1 || uses[candidate.File.Path] > 1 {
						definitions++
					}
				}
				if n.Name == "proxy_pass" && strings.HasPrefix(context, kind+"/") {
					if len(n.Args) != 1 || strings.Contains(n.Args[0].Value, "$") {
						uncertainReferences = true
					} else if upstreamName(n.Args[0].Value, kind) == name {
						references++
					}
				}
				walk(n.Children, childContext(context, n.Name))
			}
		}
		root := ""
		for context := range contexts[candidate.File.Path] {
			root = context
		}
		walk(candidate.Nodes, root)
	}
	if definitions != 1 || references != 1 || uncertainReferences {
		return doc, nil, "上游组被共享或包含无法确定的引用，需使用原生配置"
	}
	for _, child := range group.Children {
		if child.Name == "include" {
			return owner, group, "上游组包含共享 include"
		}
	}
	return owner, group, ""
}

var groupName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)
var domain = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
var sizeValue = regexp.MustCompile(`^(0|[1-9][0-9]{0,8}[kKmMgG]?)$`)
var timeValue = regexp.MustCompile(`^[0-9]{1,7}(ms|s|m|h)?$`)
var headerName = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~a-zA-Z0-9-]{1,64}$`)
var variable = regexp.MustCompile(`\$\{?([a-zA-Z0-9_]+)\}?`)
var knownVariables = map[string]bool{"host": true, "http_host": true, "remote_addr": true, "proxy_add_x_forwarded_for": true, "scheme": true, "http_upgrade": true, "proxy_host": true, "request_uri": true, "uri": true, "request_method": true, "server_port": true, "server_name": true, "http_authorization": true, "http_cookie": true}

func formVariables(field string, values []string) bool {
	for _, value := range values {
		if strings.Contains(value, "$") {
			if field != "request_headers" && field != "response_headers" && field != "upstream_tls_name" {
				return false
			}
			stripped := variable.ReplaceAllString(value, "")
			if strings.Contains(stripped, "$") {
				return false
			}
			for _, match := range variable.FindAllStringSubmatch(value, -1) {
				if !knownVariables[match[1]] {
					return false
				}
			}
		}
	}
	return true
}
func validAddress(value string, portRequired bool) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return !portRequired && groupName.MatchString(value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" {
		return false
	}
	return net.ParseIP(host) != nil || domain.MatchString(host) && !strings.Contains(host, "*")
}
func validateField(field string, values []string, kind string) error {
	spec, ok := specs(kind)[field]
	if !ok {
		return errors.New("未知字段")
	}
	if len(values) > 128 || !formVariables(field, values) {
		return errors.New("字段值过多或包含无法映射的变量")
	}
	if spec.format != "tokens" && !spec.multiple && len(values) > 1 {
		return errors.New("此字段只接受一个值")
	}
	for _, v := range values {
		if len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("字段值无效")
		}
	}
	if len(values) == 0 {
		if field == "listeners" || field == "upstream" || field == "domains" || field == "location_prefix" || field == "upstream_servers" {
			return errors.New("字段不能为空")
		}
		return nil
	}
	for _, v := range values {
		switch field {
		case "https_redirect":
			number, err := strconv.Atoi(v)
			if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != v {
				return errors.New("HTTPS 跳转端口须为 1–65535")
			}
		case "hsts":
			if err := validateHSTS(v); err != nil {
				return err
			}
		case "access_list", "waf_policy":
			if !resourceID.MatchString(v) {
				return errors.New("规则资源 ID 无效")
			}
		case "domains":
			if !domain.MatchString(v) {
				return errors.New("域名无效")
			}
		case "listeners":
			args, err := lineTokens(v)
			if err != nil {
				return err
			}
			if err := validateListen(args, kind); err != nil {
				return err
			}
		case "upstream":
			if kind == "http" {
				u, err := url.Parse(v)
				if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(v, "\x00\r\n\"'{};$\\") {
					return errors.New("HTTP 上游地址无效")
				}
			} else if !validAddress(v, false) {
				return errors.New("Stream 上游地址无效")
			}
		case "upstream_servers":
			args, err := lineTokens(v)
			if err != nil {
				return err
			}
			if !validAddress(args[0], true) {
				return errors.New("上游组成员须使用主机:端口")
			}
			for _, option := range args[1:] {
				key, value, found := strings.Cut(option, "=")
				if option == "backup" {
					continue
				}
				if !found {
					return errors.New("不支持的上游选项")
				}
				switch key {
				case "weight":
					n, err := strconv.Atoi(value)
					if err != nil || n < 1 || n > 256 {
						return errors.New("权重范围为 1–256")
					}
				case "max_fails":
					n, err := strconv.Atoi(value)
					if err != nil || n < 0 || n > 100 {
						return errors.New("失败次数无效")
					}
				case "fail_timeout":
					if !timeValue.MatchString(value) {
						return errors.New("失败超时无效")
					}
				default:
					return errors.New("不支持的上游选项")
				}
			}
		case "location_prefix":
			if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, " \t\"'{};$\\?#") {
				return errors.New("路径前缀须为不含变量的绝对路径")
			}
		case "body_size":
			if !sizeValue.MatchString(v) {
				return errors.New("请求体大小无效")
			}
		case "connect_timeout", "read_timeout", "send_timeout", "session_timeout":
			if !timeValue.MatchString(v) {
				return errors.New("超时无效")
			}
		case "buffering", "request_buffering", "upstream_tls_verify", "upstream_tls_sni", "real_ip_recursive":
			if v != "on" && v != "off" {
				return errors.New("请选择 on 或 off")
			}
		case "cache":
			if v != "off" && v != "nginxpanel_http" {
				return errors.New("请选择 off 或 nginxpanel_http")
			}
		case "http_version":
			if v != "1.0" && v != "1.1" {
				return errors.New("上游 HTTP 版本无效")
			}
		case "request_headers", "response_headers":
			args, err := lineTokens(v)
			if err != nil {
				return err
			}
			if len(args) < 2 || len(args) > 3 || !headerName.MatchString(args[0]) || (field == "request_headers" && len(args) != 2) || (len(args) == 3 && args[2] != "always") {
				return errors.New("头字段格式为名称、带引号的值及可选 always")
			}
		case "certificate", "certificate_key", "upstream_tls_ca":
			if !cleanRelative(v) || !strings.HasPrefix(v, "certificates/") || strings.Contains(v, "$") {
				return errors.New("请选择受管不可变证书路径")
			}
		case "upstream_tls_name":
			if v != "$proxy_host" && (!domain.MatchString(v) || strings.Contains(v, "*")) && net.ParseIP(v) == nil {
				return errors.New("TLS 校验名称无效")
			}
		case "tls_protocols":
			if v != "TLSv1.2" && v != "TLSv1.3" {
				return errors.New("只开放 TLSv1.2 和 TLSv1.3")
			}
		case "trusted_sources":
			if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil {
				return errors.New("可信来源须为 IP 或 CIDR")
			}
		case "real_ip_header":
			if !headerName.MatchString(v) {
				return errors.New("真实 IP 头无效")
			}
		case "responses":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 1024 {
				return errors.New("UDP 响应次数无效")
			}
		case "access_log", "error_log":
			args, err := lineTokens(v)
			if err != nil {
				return err
			}
			if field == "access_log" && len(args) == 1 && args[0] == "off" {
				continue
			}
			if field == "error_log" && len(args) == 2 && args[0] == "/dev/null" {
				continue
			}
			if !cleanRelative(args[0]) || !(strings.HasPrefix(args[0], "logs/nginx/") || strings.HasPrefix(args[0], "logs/stream/")) || strings.Contains(args[0], "$") {
				return errors.New("日志须使用受管路径")
			}
			if len(args) > 2 {
				return errors.New("日志参数过多")
			}
			if field == "access_log" && kind == "stream" && len(args) != 2 {
				return errors.New("Stream 访问日志须指定格式")
			}
		}
	}
	return nil
}
func validateListen(values []string, kind string) error {
	if len(values) == 0 {
		return errors.New("监听不能为空")
	}
	port := values[0]
	if strings.Contains(port, ":") {
		host, p, err := net.SplitHostPort(port)
		if err != nil || host != "" && net.ParseIP(host) == nil {
			return errors.New("监听须使用 IP 地址和端口")
		}
		port = p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("监听端口无效")
	}
	seen := map[string]bool{}
	for _, option := range values[1:] {
		if seen[option] {
			return errors.New("监听选项重复")
		}
		seen[option] = true
		if option != "default_server" && option != "ipv6only=on" && option != "ipv6only=off" && !(kind == "http" && (option == "ssl" || option == "http2")) && !(kind == "stream" && (option == "udp" || option == "reuseport")) {
			return errors.New("监听选项不受支持")
		}
	}
	return nil
}
func applyEdits(source string, edits []Edit) (string, error) {
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].Start == edits[j].Start {
			return edits[i].End > edits[j].End
		}
		return edits[i].Start > edits[j].Start
	})
	end := len(source) + 1
	for _, edit := range edits {
		if edit.Start < 0 || edit.End < edit.Start || edit.End > len(source) || edit.End > end {
			return "", errors.New("修改范围重叠或资源绑定失效")
		}
		source = source[:edit.Start] + edit.Text + source[edit.End:]
		end = edit.Start
	}
	return source, nil
}
func blockInsertion(source string, close int) (int, string) {
	start := strings.LastIndexByte(source[:close], '\n') + 1
	indent := source[start:close]
	if strings.Trim(indent, " \t\r") == "" {
		return start, indent
	}
	return close, ""
}
