package nginxconfig

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// PortableFiles builds a new tree from typed projections. No raw source text,
// comments, arbitrary header values, URL paths or user metadata are copied.
// All sites remain disabled because omitted native directives may enforce access.
func (p *Parsed) PortableFiles() ([]File, []string) {
	files := []File{}
	add := func(id, name, content string) {
		files = append(files, File{ID: id, Path: name, Content: content, SHA256: secure.Hash([]byte(content))})
	}
	acls, wafs := map[string]bool{}, map[string]bool{}
	geoACLs := false
	for _, list := range p.Tree.AccessLists {
		if !list.Editable {
			continue
		}
		if len(list.Countries) > 0 {
			for _, file := range p.Tree.Files {
				if file.Path != accessGeoPath(list.ID) {
					continue
				}
				nodes, _ := sourceNodes(file.Content)
				sources := []string{}
				for _, node := range nodes[0].Children[1:] {
					sources = append(sources, node.Name)
				}
				geo, server := accessGeoSource(list.ID, accessMetadata{Name: list.ID, Mode: list.Mode, Entries: list.Entries, Countries: list.Countries, GeoIPUpdatedAt: list.GeoIPUpdatedAt}, sources)
				add("acl-geo-"+list.ID, accessGeoPath(list.ID), geo)
				add("acl-"+list.ID, accessListPath(list.ID), server)
				acls[list.ID], geoACLs = true, true
			}
			continue
		}
		var body strings.Builder
		body.WriteString(accessHeader(accessMetadata{Name: list.ID}) + "\n")
		rule, last := "allow", "deny"
		if list.Mode == "denylist" {
			rule, last = "deny", "allow"
		}
		for _, entry := range list.Entries {
			body.WriteString(rule + " " + argsText([]string{entry}) + ";\n")
		}
		body.WriteString(last + " all;\n")
		add("acl-"+list.ID, accessListPath(list.ID), body.String())
		acls[list.ID] = true
	}
	for _, policy := range p.Tree.WAFPolicies {
		if !policy.Editable {
			continue
		}
		cfg := policy.Config
		cfg.Metadata = ResourceMetadata{Name: policy.ID, Enabled: cfg.Metadata.Enabled}
		cfg.DeniedPaths, cfg.ExemptPaths = []WAFPath{}, []WAFPath{}
		cfg.Methods = []string{}
		for _, method := range policy.Config.Methods {
			switch method {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT":
				cfg.Methods = append(cfg.Methods, method)
			}
		}
		http, server := wafSource(policy.ID, cfg)
		add("waf-http-"+policy.ID, wafPath(policy.ID, "http"), http)
		add("waf-server-"+policy.ID, wafPath(policy.ID, "server"), server)
		wafs[policy.ID] = true
	}
	resources := append([]Resource(nil), p.Tree.Resources...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	count := 0
	var httpSites, streamSites strings.Builder
	for _, resource := range resources {
		body, ok := portableResource(resource, acls, wafs)
		if !ok {
			continue
		}
		if resource.Kind == "http" {
			httpSites.WriteString(body)
		} else {
			streamSites.WriteString(body)
		}
		count++
	}
	main := InitialFiles()[0].Content
	httpBody := ""
	if geoACLs {
		httpBody = "    include security/acl/*/http.conf;\n"
	}
	if len(wafs) > 0 {
		httpBody += "    include security/waf/*/http.conf;\n"
	}
	if httpSites.Len() > 0 {
		httpBody += "    " + strings.ReplaceAll(strings.TrimSuffix(httpSites.String(), "\n"), "\n", "\n    ") + "\n"
	}
	main = strings.Replace(main, "    include http/*.conf;\n", httpBody, 1)
	if streamSites.Len() > 0 {
		main += "\nstream {\n    " + strings.ReplaceAll(strings.TrimSuffix(streamSites.String(), "\n"), "\n", "\n    ") + "\n}\n"
	}
	add("main", "nginx.conf", main)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	unmanaged := 0
	var countUnmanaged func([]*Node)
	countUnmanaged = func(nodes []*Node) {
		for _, node := range nodes {
			if node.Name == "server" && node.Open >= 0 && node.ResourceID == "" {
				unmanaged++
			}
			countUnmanaged(node.Children)
		}
	}
	for _, document := range p.Documents {
		countUnmanaged(document.Nodes)
	}
	omissions := []string{
		fmt.Sprintf("仅重建 %d 个受管站点，%d 个无法可靠重建监听、根路径或上游的站点未导出", count, len(resources)-count),
		fmt.Sprintf("全部 %d 个源文件的原文均未导出；%d 个未登记的 server 块不进入可移植配置", len(p.Tree.Files), unmanaged),
		"所有迁入站点停用；原生认证、附加路径与全局指令可能省略，须检查并补齐保护后再启用",
		"原文、注释、名称备注、任意头常量、URL 路径与动态引用、HTTP-01、客户端拒绝入口、源模块路径及本机全局调优未导出",
		fmt.Sprintf("重建 %d 个 IP 访问列表及 %d 个基础 WAF；不可编辑策略、WAF 自定义路径与非标准方法未导出", len(acls), len(wafs)),
		"证书仅保留已识别的逻辑引用，目标须映射或补齐；不包含证书私钥、DNS/ACME/通知凭据及其他可选配置",
	}
	return files, omissions
}

func portableResource(r Resource, acls, wafs map[string]bool) (string, bool) {
	if !resourceID.MatchString(r.ID) || (r.Kind != "http" && r.Kind != "stream") {
		return "", false
	}
	values := func(name string) []string {
		f := r.Fields[name]
		if !f.Editable || validateField(name, f.Values, r.Kind) != nil {
			return nil
		}
		return f.Values
	}
	listeners, upstream := values("listeners"), values("upstream")
	if len(listeners) == 0 || len(upstream) != 1 {
		return "", false
	}
	if r.Kind == "http" {
		prefix := values("location_prefix")
		u, err := url.Parse(upstream[0])
		if len(prefix) != 1 || prefix[0] != "/" || err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return "", false
		}
	}
	var group, server, location strings.Builder
	write := func(out *strings.Builder, name string, args []string) {
		out.WriteString("    " + name + " " + argsText(args) + ";\n")
	}
	servers := values("upstream_servers")
	if len(servers) > 0 {
		name := "nginxpanel_up_" + strings.ReplaceAll(r.ID, "-", "")
		group.WriteString("upstream " + name + " {\n")
		for _, line := range servers {
			args, _ := lineTokens(line)
			write(&group, "server", args)
		}
		group.WriteString("}\n")
		if r.Kind == "http" {
			u, _ := url.Parse(upstream[0])
			u.Host = name
			upstream = []string{u.String()}
		} else {
			upstream = []string{name}
		}
	} else if groupName.MatchString(upstreamName(upstream[0], r.Kind)) {
		return "", false
	}
	for _, line := range listeners {
		args, _ := lineTokens(line)
		write(&server, "listen", args)
	}
	if r.Kind == "http" {
		domains := values("domains")
		if len(domains) == 0 {
			return "", false
		}
		write(&server, "server_name", domains)
		write(&server, "access_log", []string{"logs/nginx/" + r.ID + "/access.log", "nginxpanel_http"})
	} else {
		write(&server, "access_log", []string{"logs/stream/" + r.ID + "/access.log", "nginxpanel_stream"})
	}
	logPath := "logs/nginx/"
	if r.Kind == "stream" {
		logPath = "logs/stream/"
	}
	write(&server, "error_log", []string{logPath + r.ID + "/error.log", "warn"})
	proxy := &server
	if r.Kind == "http" {
		proxy = &location
	}
	write(proxy, "proxy_pass", upstream)
	// Every scalar here has a numeric, enum, network or logical-reference validator.
	fields := []string{"body_size", "connect_timeout", "read_timeout", "send_timeout", "session_timeout", "responses", "http_version", "buffering", "request_buffering", "upstream_tls_verify", "upstream_tls_sni", "tls_protocols", "trusted_sources", "real_ip_recursive"}
	for _, name := range fields {
		args := values(name)
		if len(args) == 0 {
			continue
		}
		spec := specs(r.Kind)[name]
		out := &server
		if spec.target == "location" {
			out = proxy
		}
		if spec.format == "lines" {
			for _, line := range args {
				tokens, _ := lineTokens(line)
				write(out, spec.directive, tokens)
			}
		} else {
			write(out, spec.directive, args)
		}
	}
	for _, name := range []string{"certificate", "certificate_key", "upstream_tls_ca"} {
		args := values(name)
		if len(args) != 1 {
			continue
		}
		if _, _, _, ok := certificates.Reference(args[0]); !ok {
			continue
		}
		out := &server
		if name == "upstream_tls_ca" {
			out = proxy
		}
		write(out, specs(r.Kind)[name].directive, args)
	}
	if args := values("upstream_tls_name"); len(args) == 1 && (args[0] == "$proxy_host" || domain.MatchString(args[0])) {
		write(proxy, "proxy_ssl_name", args)
	}
	if args := values("real_ip_header"); len(args) == 1 {
		switch args[0] {
		case "X-Forwarded-For", "X-Real-IP", "proxy_protocol":
			write(&server, "real_ip_header", args)
		}
	}
	for _, line := range values("request_headers") {
		args, err := lineTokens(line)
		if err != nil || len(args) != 2 {
			continue
		}
		allowed := map[string]string{"Host": "$host", "X-Real-IP": "$remote_addr", "X-Forwarded-For": "$proxy_add_x_forwarded_for", "X-Forwarded-Proto": "$scheme", "Upgrade": "$http_upgrade", "Authorization": "$http_authorization", "Cookie": "$http_cookie"}
		if value, known := allowed[args[0]]; known && value == args[1] {
			write(proxy, "proxy_set_header", args)
		}
	}
	for _, binding := range []struct {
		name      string
		available map[string]bool
		path      func(string) string
	}{
		{"access_list", acls, accessListPath}, {"waf_policy", wafs, func(id string) string { return wafPath(id, "server") }},
	} {
		if args := values(binding.name); len(args) == 1 && binding.available[args[0]] {
			write(&server, "include", []string{binding.path(args[0])})
		}
	}
	if args := values("hsts"); len(args) == 1 {
		write(&server, "add_header", []string{"Strict-Transport-Security", args[0], "always"})
	}
	if args := values("https_redirect"); len(args) == 1 {
		server.WriteString("    if ($scheme = http) {\n        return 308 " + httpsRedirectURL(args[0]) + ";\n    }\n")
	}
	if r.Kind == "http" {
		server.WriteString("    location / {\n    " + strings.ReplaceAll(strings.TrimSuffix(location.String(), "\n"), "\n", "\n    ") + "\n    }\n")
	}
	metadata := ResourceMetadata{Name: r.ID, Enabled: false}
	return group.String() + metadataLine(metadata) + "\n# nginxpanel:resource " + r.ID + "\nserver {\n" + server.String() + "}\n", true
}

// A plain import must be exactly reproducible from the same typed projection.
// A manifest's mode flag alone never authorizes arbitrary unencrypted native text.
func ValidatePortableFiles(files []File) error {
	p, err := Parse(files, DefaultPolicy())
	if err != nil || len(p.Tree.Diagnostics) != 0 {
		return fault.Invalid("可移植配置结构无法解析")
	}
	expected, _ := p.PortableFiles()
	actual := append([]File(nil), files...)
	sort.Slice(actual, func(i, j int) bool { return actual[i].Path < actual[j].Path })
	if len(expected) != len(actual) {
		return fault.Invalid("可移植配置包含未声明的原生内容")
	}
	for i := range expected {
		if expected[i] != actual[i] {
			return fault.Invalid("可移植配置只能包含规范化受管字段，站点必须停用")
		}
	}
	return nil
}
