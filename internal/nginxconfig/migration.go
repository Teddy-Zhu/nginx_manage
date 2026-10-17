package nginxconfig

import (
	"context"
	"database/sql"
	"path"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// MigrationFiles rebinds recognized argument spans or explicitly removes a
// load_module directive. Mappings cannot add directives, rewrite arbitrary text,
// or supply the target's execution policy.
func MigrationFiles(files []File, policy Policy, mappings map[string]string, ids, versions map[string]string) ([]File, error) {
	out, err := mapMigrationFiles(files, policy, mappings, ids, versions)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].ID = secure.ID()
	}
	return out, nil
}

// RestorationFiles maps a complete database's retained resources without
// changing file identities that are still referenced by its revision history.
func RestorationFiles(files []File, policy Policy, mappings map[string]string) ([]File, error) {
	return mapMigrationFiles(files, policy, mappings, nil, nil)
}

func mapMigrationFiles(files []File, policy Policy, mappings map[string]string, ids, versions map[string]string) ([]File, error) {
	if len(mappings) > 256 {
		return nil, fault.Invalid("迁移映射超过 256 项")
	}
	p, err := Parse(files, policy)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	out := append([]File{}, files...)
	for i := range out {
		doc := p.Documents[out[i].ID]
		if doc == nil {
			return nil, fault.Invalid("迁移配置无法建立文件映射")
		}
		edits := []Edit{}
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if node.Name == "load_module" && node.Open < 0 && len(node.Args) == 1 {
					value := node.Args[0].Value
					if replacement, exists := mappings[value]; exists && replacement == "" {
						edits = append(edits, Edit{node.Start, node.End, ""})
						used[value] = true
						continue
					}
				}
				for _, arg := range node.Args {
					value := arg.Value
					if id, version, kind, ok := certificates.Reference(value); ok && ids[id] != "" && versions[version] != "" {
						edits = append(edits, Edit{arg.Start, arg.End, quote(certificates.Path(ids[id], versions[version], kind))})
						continue
					}
					if replacement, exists := mappings[value]; exists {
						switch node.Name {
						case "listen", "server_name", "proxy_pass", "server", "resolver", "ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate", "proxy_ssl_trusted_certificate", "load_module":
							if replacement != "" && len(replacement) <= 2048 && !strings.ContainsAny(replacement, "\x00\r\n") {
								edits = append(edits, Edit{arg.Start, arg.End, quote(replacement)})
								used[value] = true
							}
						}
					}
				}
				walk(node.Children)
			}
		}
		walk(doc.Nodes)
		out[i].Content, err = applyEdits(out[i].Content, edits)
		if err != nil {
			return nil, err
		}
		out[i].SHA256 = ""
	}
	for key := range mappings {
		if !used[key] {
			return nil, fault.Invalid("映射必须对应配置中的监听、域名、上游、解析器、信任证书或模块参数")
		}
	}
	return out, nil
}

func (p *Parsed) MigrationFeatures() []string {
	// Managed publications add HTTP log/proxy controls, an authentication-presence
	// map and a revision probe, even when the business tree only uses Stream.
	features := map[string]bool{"http": true, "http_proxy": true, "http_log": true, "rewrite": true, "map": true}
	for _, resource := range p.Tree.Resources {
		if resource.Metadata.Enabled && resource.Metadata.ClientDeny {
			features["real_ip"], features["map_volatile"], features["http_geo"] = true, true, true
		}
	}
	visited := p.walkMigrationRuntime(func(n *Node, kind, table string) {
		if table == "" && (n.Name == "http" || n.Name == "stream") {
			features[kind] = true
			if kind == "stream" {
				features["stream_log"] = true
			}
		}
		family := func(http, stream string) {
			if kind == "stream" {
				features[stream] = true
			} else if kind == "http" {
				features[http] = true
			}
		}
		// Map/geo/type/split rows are data, including when supplied by
		// an include. Only map's volatile parameter adds a capability.
		if table != "" {
			if table == "map" && n.Name == "volatile" && n.Open < 0 && len(n.Args) == 0 {
				family("map_volatile", "stream_map_volatile")
			}
			return
		}
		if kind == "http" && IsHTTP01(n) {
			features["http01"] = true
		}
		if strings.HasPrefix(n.Name, "proxy_") {
			family("http_proxy", "stream")
		}
		if n.Name == "proxy_ssl" || strings.HasPrefix(n.Name, "proxy_ssl_") || strings.HasPrefix(n.Name, "ssl_") && !strings.HasPrefix(n.Name, "ssl_preread") {
			family("tls", "stream_tls")
		}
		if n.Name == "limit_conn" || strings.HasPrefix(n.Name, "limit_conn_") {
			family("limit_conn", "stream_limit_conn")
		}
		if n.Name == "limit_req" || strings.HasPrefix(n.Name, "limit_req_") {
			features["limit_req"] = true
		}
		switch n.Name {
		case "proxy_pass":
			if kind == "http" && len(n.Args) == 1 && strings.HasPrefix(n.Args[0].Value, "https://") {
				features["tls"] = true
			}
		case "listen":
			for _, a := range n.Args {
				if a.Value == "ssl" {
					family("tls", "stream_tls")
				}
			}
		case "set_real_ip_from", "real_ip_header", "real_ip_recursive":
			family("real_ip", "stream_real_ip")
		case "ssl_preread":
			features["stream_ssl_preread"] = true
		case "map":
			family("map", "stream_map")
		case "geo":
			family("http_geo", "stream_geo")
		case "split_clients":
			family("http_split_clients", "stream_split_clients")
		case "allow", "deny":
			family("http_access", "stream_access")
		case "log_format", "access_log":
			family("http_log", "stream_log")
		case "add_header", "expires":
			features["http_headers"] = true
		case "charset":
			features["http_charset"] = true
		case "gzip", "gzip_types", "gzip_vary":
			features["http_gzip"] = true
		case "limit_req_dry_run":
			features["limit_req_observe"] = true
		case "limit_conn_dry_run":
			family("limit_conn_observe", "stream_limit_conn_observe")
		case "return":
			family("rewrite", "stream_return")
		case "set":
			family("rewrite", "stream_set")
		case "rewrite", "if", "uninitialized_variable_warn":
			features["rewrite"] = true
		}
	})
	for _, w := range p.Tree.WAFPolicies {
		doc := p.Documents[w.HTTPFileID]
		if doc == nil || !visited[[3]string{doc.File.Path, "http", ""}] {
			continue
		}
		for _, name := range w.Config.RequiredFeatures() {
			features[name] = true
		}
	}
	out := []string{}
	for name := range features {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// walkMigrationRuntime resolves only the active include graph, preserving HTTP,
// Stream and table-data contexts across shared files. Dependency checks use this
// same graph so orphan files and literal table rows cannot add prerequisites.
func (p *Parsed) walkMigrationRuntime(inspect func(*Node, string, string)) map[[3]string]bool {
	byPath := map[string]*Document{}
	for _, doc := range p.Documents {
		byPath[doc.File.Path] = doc
	}
	visited, active := map[[3]string]bool{}, map[string]bool{}
	var visit func(string, string, string)
	visit = func(name, scope, table string) {
		key := [3]string{name, scope, table}
		if visited[key] || active[name] || p.runtimeExcluded[name] {
			return
		}
		doc := byPath[name]
		if doc == nil {
			return
		}
		visited[key], active[name] = true, true
		defer delete(active, name)
		var walk func([]*Node, string, string)
		walk = func(nodes []*Node, scope, table string) {
			for _, node := range nodes {
				if !node.Enabled() {
					continue
				}
				kind := scope
				if table == "" && (node.Name == "http" || node.Name == "stream") {
					kind = node.Name
				}
				inspect(node, kind, table)
				if node.Name == "include" && len(node.Args) == 1 {
					for candidate := range byPath {
						if matched, _ := path.Match(node.Args[0].Value, candidate); matched {
							visit(candidate, kind, table)
						}
					}
				}
				if table != "" {
					continue
				}
				nextTable := ""
				if node.Name == "map" || node.Name == "geo" || node.Name == "types" || node.Name == "split_clients" {
					nextTable = node.Name
				}
				walk(node.Children, kind, nextTable)
			}
		}
		walk(doc.Nodes, scope, table)
	}
	visit("nginx.conf", "", "")
	return visited
}

func (p *Parsed) MigrationLocalDependencies() []string {
	seen := map[string]bool{}
	p.walkMigrationRuntime(func(node *Node, scope, table string) {
		if table != "" || (scope != "http" && scope != "stream") || node.Open >= 0 || len(node.Args) != 1 {
			return
		}
		if node.Name == "ssl_trusted_certificate" || node.Name == "proxy_ssl_trusted_certificate" {
			if name := node.Args[0].Value; certificates.IsSystemCA(name) {
				seen[name] = true
			}
		}
	})
	out := []string{}
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// CompensateImport restores the previous immutable head after runtime recovery.
// A separate head generation invalidates stale clients without rewriting history.
func (s *Service) CompensateImport(ctx context.Context, tx *sql.Tx, imported, basis, principal, requestID string) error {
	var desired, applied sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT desired_revision,applied_revision FROM config_head WHERE id=1").Scan(&desired, &applied); err != nil {
		return err
	}
	if desired.String != imported || applied.String != basis {
		return fault.Conflict("迁移的期望或运行修订已变化，不能自动补偿")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE config_head SET desired_revision=NULLIF(?,''),version=version+1 WHERE id=1", basis); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'rolled_back',?)", secure.ID(), requestID, principal, "migration.compensate", imported, time.Now().Unix())
	return err
}
