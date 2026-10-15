package agent

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

func (n *Nginx) renderHTTP01(p *nginxconfig.Parsed) (map[string][]nginxconfig.Edit, string, map[string][]listener, error) {
	edits := map[string][]nginxconfig.Edit{}
	bindings := map[string][]listener{}
	servers, err := p.HTTP01Servers()
	if err != nil {
		return nil, "", nil, err
	}
	if len(servers) == 0 {
		return edits, "", bindings, nil
	}
	used := map[string]bool{}
	var scan func([]*nginxconfig.Node) error
	scan = func(nodes []*nginxconfig.Node) error {
		expanded, err := p.ExpandNodes(nodes, 0)
		if err != nil {
			return err
		}
		for _, node := range expanded {
			if node.ResourceID != "" && !node.Enabled() {
				continue
			}
			used[node.Name] = true
			if err := scan(node.Children); err != nil {
				return err
			}
		}
		return nil
	}
	var root []*nginxconfig.Node
	for _, doc := range p.Documents {
		if doc.File.Path == "nginx.conf" {
			root = doc.Nodes
		}
	}
	if err := scan(root); err != nil {
		return nil, "", nil, err
	}
	controls := ""
	if used["limit_req"] || used["limit_conn"] {
		controls += "    map $request_uri $nginxpanel_http01_empty { default \"\"; }\n"
	}
	if used["limit_req"] {
		controls += "    limit_req_zone $nginxpanel_http01_empty zone=nginxpanel_http01_req:1m rate=1r/s;\n"
	}
	if used["limit_conn"] {
		controls += "    limit_conn_zone $nginxpanel_http01_empty zone=nginxpanel_http01_conn:1m;\n"
	}
	enabled := map[*nginxconfig.Node]bool{}
	for _, server := range servers {
		enabled[server.Server] = true
		var body strings.Builder
		identity := secure.Hash([]byte(server.FileID + ":" + strconv.Itoa(server.Server.Start)))
		body.WriteString("location ^~ " + nginxconfig.HTTP01Prefix + " {\n        # Order-owned HTTP-01 responder: " + identity + "\n        if ($request_method !~ ^(GET|HEAD)$) { return 405; }\n")
		if used["allow"] || used["deny"] {
			body.WriteString("        allow all;\n        satisfy any;\n")
		}
		if used["auth_basic"] {
			body.WriteString("        auth_basic off;\n")
		}
		if used["auth_request"] {
			body.WriteString("        auth_request off;\n")
		}
		if used["limit_req"] {
			body.WriteString("        limit_req zone=nginxpanel_http01_req;\n")
		}
		if used["limit_conn"] {
			body.WriteString("        limit_conn nginxpanel_http01_conn 1;\n")
		}
		if used["proxy_cache"] {
			body.WriteString("        proxy_cache off;\n")
		}
		body.WriteString("        client_max_body_size 1k;\n        proxy_pass_request_body off;\n        proxy_pass_request_headers off;\n        proxy_set_header Host $host;\n        proxy_set_header Content-Length \"\";\n        proxy_connect_timeout 2s;\n        proxy_read_timeout 5s;\n        proxy_intercept_errors off;\n        proxy_pass " + nginxQuote("http://unix:"+n.http01Socket()+":") + ";\n    }")
		edits[server.FileID] = append(edits[server.FileID], nginxconfig.Edit{Start: server.Location.Start, End: server.Location.End, Text: body.String()}, nginxconfig.Edit{Start: server.Server.Open + 1, End: server.Server.Open + 1, Text: "\n    rewrite \"^/\\\\.well-known/acme-challenge/[A-Za-z0-9_-]{22,256}$\" $uri break;\n"})
	}
	// Exact native server_name entries have precedence over wildcard/regex
	// names. Repeated exact names are deliberately not guessed across servers.
	counts := map[string]int{}
	expanded, err := p.ExpandNodes(root, 0)
	if err != nil {
		return nil, "", nil, err
	}
	pairs := 0
	for _, block := range expanded {
		if block.Name != "http" {
			continue
		}
		nodes, err := p.ExpandNodes(block.Children, 0)
		if err != nil {
			return nil, "", nil, err
		}
		for _, server := range nodes {
			if server.Name != "server" || !server.Enabled() {
				continue
			}
			directives, err := p.ExpandNodes(server.Children, 0)
			if err != nil {
				return nil, "", nil, err
			}
			names := map[string]bool{}
			listeners := []listener{}
			for _, node := range directives {
				if node.Name == "server_name" {
					for _, arg := range node.Args {
						name := strings.ToLower(arg.Value)
						if http01Domain(name) {
							names[name] = true
						}
					}
				}
				if node.Name != "listen" {
					continue
				}
				entry, ssl, err := parseListener(node.Args, "http")
				if err != nil {
					return nil, "", nil, err
				}
				if entry.Port != 80 {
					continue
				}
				if enabled[server] {
					if ssl {
						return nil, "", nil, errors.New("HTTP-01 requires a plain HTTP port 80 listener")
					}
					for _, arg := range node.Args {
						if arg.Value == "proxy_protocol" {
							return nil, "", nil, errors.New("HTTP-01 port 80 does not support proxy_protocol")
						}
					}
				}
				listeners = append(listeners, entry)
			}
			if len(listeners) == 0 {
				if enabled[server] {
					return nil, "", nil, errors.New("HTTP-01 requires an explicit port 80 listener")
				}
				continue
			}
			for name := range names {
				counts[name]++
				if enabled[server] {
					bindings[name] = append(bindings[name], listeners...)
					pairs += len(listeners)
				}
			}
			if pairs > limits.NginxListeners {
				return nil, "", nil, errors.New("HTTP-01 listener verification limit reached")
			}
		}
	}
	for name, count := range counts {
		if count != 1 {
			delete(bindings, name)
		}
	}
	return edits, controls, bindings, nil
}

func validHTTP01Bindings(bindings map[string][]listener) bool {
	count := 0
	for name, entries := range bindings {
		if !http01Domain(name) || len(entries) == 0 {
			return false
		}
		for _, entry := range entries {
			count++
			ip := net.ParseIP(entry.IP)
			if entry.Port != 80 || ip == nil || (entry.Network != "tcp4" && entry.Network != "tcp6") || (entry.Network == "tcp4") != (ip.To4() != nil) {
				return false
			}
		}
	}
	return count <= limits.NginxListeners
}
