package nginxconfig

import (
	"path"
	"sort"
	"strings"
)

// Policy additions are supplied by local trusted setup, never by API or import.
// Unknown directives are preserved in drafts but cannot enter desired state.
type Policy struct {
	Version         string   `json:"version"`
	ExtraDirectives []string `json:"extra_directives"`
}

func DefaultPolicy() Policy { return Policy{Version: PolicyVersion, ExtraDirectives: []string{}} }

var safeDirectives = strings.Fields(`worker_processes worker_connections events http stream server upstream location
listen server_name proxy_pass proxy_http_version proxy_set_header proxy_hide_header proxy_buffering proxy_request_buffering
proxy_connect_timeout proxy_read_timeout proxy_send_timeout proxy_timeout proxy_responses proxy_next_upstream proxy_next_upstream_tries
proxy_next_upstream_timeout proxy_ssl_server_name proxy_ssl_name proxy_ssl_verify proxy_ssl_verify_depth proxy_ssl_trusted_certificate
proxy_cache proxy_cache_valid proxy_cache_key proxy_cache_bypass proxy_no_cache
keepalive keepalive_timeout keepalive_requests sendfile tcp_nopush tcp_nodelay default_type types charset
client_max_body_size client_body_timeout client_header_timeout send_timeout large_client_header_buffers
ssl_certificate ssl_certificate_key ssl_protocols ssl_ciphers ssl_prefer_server_ciphers ssl_session_cache ssl_session_timeout
ssl_session_tickets ssl_stapling ssl_stapling_verify ssl_trusted_certificate
access_log error_log log_format pid include resolver resolver_timeout
return rewrite try_files index add_header expires gzip gzip_types gzip_vary
map geo split_clients least_conn ip_hash hash zone backup max_fails fail_timeout
allow deny satisfy set_real_ip_from real_ip_header real_ip_recursive
limit_req_zone limit_req limit_req_status limit_req_log_level limit_req_dry_run
limit_conn_zone limit_conn limit_conn_status limit_conn_log_level limit_conn_dry_run
limit_except if set uninitialized_variable_warn reset_timedout_connection server_tokens`)

var securityDirectives = strings.Fields(`allow deny satisfy set_real_ip_from real_ip_header real_ip_recursive limit_req_zone limit_req limit_req_status limit_req_log_level limit_req_dry_run limit_conn_zone limit_conn limit_conn_status limit_conn_log_level limit_conn_dry_run limit_except geo map if set return`)

func (p *Parsed) validate(policy Policy, files map[string]File) {
	allowed := map[string]bool{}
	for _, name := range safeDirectives {
		allowed[name] = true
	}
	// Root extensions cannot enable executable directives or arbitrary path writers.
	for _, name := range policy.ExtraDirectives {
		if !forbidden(name) {
			allowed[name] = true
		}
	}
	security := map[string]bool{}
	for _, name := range securityDirectives {
		security[name] = true
	}
	scopes := map[string]bool{}
	edges := map[string][]string{}
	for _, doc := range p.Documents {
		var walk func([]*Node, string)
		walk = func(nodes []*Node, parent string) {
			for _, n := range nodes {
				add := func(code, message string) {
					p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{doc.File.ID, n.Line, code, message})
				}
				if parent == "map" || parent == "geo" || parent == "types" || parent == "split_clients" {
					if n.Open >= 0 {
						add("unsafe_directive", "映射表中不允许嵌套块")
					}
					continue
				}
				if forbidden(n.Name) || !allowed[n.Name] {
					add("unsafe_directive", "未批准的指令："+n.Name)
				}
				if security[n.Name] {
					scopes["security.write"] = true
				}
				switch n.Name {
				case "log_format":
					if len(n.Args) > 0 && strings.HasPrefix(n.Args[0].Value, "nginxpanel_") {
						add("reserved_name", "nginxpanel_ 日志格式由受管执行器定义")
					}
				case "include":
					if len(n.Args) != 1 {
						add("include", "include 必须有一个受管相对路径")
						break
					}
					pattern := n.Args[0].Value
					if !cleanRelative(pattern) || strings.Contains(pattern, "$") {
						add("unsafe_path", "include 只能引用受管配置树")
						break
					}
					matches := []string{}
					for name := range files {
						match, err := path.Match(pattern, name)
						if err != nil {
							add("include", "无效 include 模式")
							break
						}
						if match {
							matches = append(matches, name)
						}
					}
					if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
						add("include", "include 文件不存在")
					}
					edges[doc.File.Path] = append(edges[doc.File.Path], matches...)
				case "pid":
					if len(n.Args) != 1 || n.Args[0].Value != "run/nginx.pid" {
						add("unsafe_path", "PID 必须使用 run/nginx.pid")
					}
				case "access_log", "error_log":
					if len(n.Args) < 1 {
						add("unsafe_path", "缺少日志路径")
						break
					}
					v := n.Args[0].Value
					if n.Name == "access_log" && v == "off" || n.Name == "error_log" && v == "/dev/null" {
						break
					}
					if !cleanRelative(v) || !(strings.HasPrefix(v, "logs/nginx/") || strings.HasPrefix(v, "logs/stream/") || strings.HasPrefix(v, "logs/nginx-global/")) || strings.Contains(v, "$") {
						add("unsafe_path", "日志只能写入受管日志目录")
					}
				case "ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate", "proxy_ssl_trusted_certificate":
					if len(n.Args) != 1 || !cleanRelative(n.Args[0].Value) || !strings.HasPrefix(n.Args[0].Value, "certificates/") || strings.Contains(n.Args[0].Value, "$") {
						add("unsafe_path", "证书路径必须引用受管不可变版本")
					}
				case "proxy_cache":
					if len(n.Args) != 1 || n.Args[0].Value != "off" && n.Args[0].Value != "nginxpanel_http" {
						add("unsafe_path", "只能使用受管缓存区域")
					}
				}
				walk(n.Children, n.Name)
			}
		}
		walk(doc.Nodes, "")
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(name string) bool {
		if visiting[name] {
			return false
		}
		if visited[name] {
			return true
		}
		visiting[name] = true
		for _, next := range edges[name] {
			if !visit(next) {
				return false
			}
		}
		visiting[name] = false
		visited[name] = true
		return true
	}
	for name := range files {
		if !visit(name) {
			p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{files[name].ID, 1, "include_cycle", "include 存在循环引用"})
			break
		}
	}
	for scope := range scopes {
		p.RequiredScopes = append(p.RequiredScopes, scope)
	}
	sort.Strings(p.RequiredScopes)
	sort.Slice(p.Tree.Diagnostics, func(i, j int) bool {
		a, b := p.Tree.Diagnostics[i], p.Tree.Diagnostics[j]
		if a.FileID == b.FileID {
			return a.Line < b.Line
		}
		return a.FileID < b.FileID
	})
}

func cleanRelative(v string) bool {
	return v != "" && !path.IsAbs(v) && path.Clean(v) == v && v != ".." && !strings.HasPrefix(v, "../") && !strings.ContainsAny(v, "\\\x00\r\n")
}
func forbidden(name string) bool {
	return name == "load_module" || name == "env" || name == "user" || name == "root" || name == "alias" || name == "perl" || name == "perl_require" || strings.Contains(name, "lua") || strings.HasPrefix(name, "js_") || strings.Contains(name, "_temp_path") || strings.Contains(name, "_cache_path") || strings.HasPrefix(name, "dav_") || name == "auth_basic_user_file"
}
