package nginxconfig

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// MigrationFiles rebinds only recognized argument spans. Mappings cannot add
// directives, rewrite arbitrary text, or supply the target's execution policy.
func MigrationFiles(files []File, policy Policy, mappings map[string]string, ids, versions map[string]string) ([]File, error) {
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
		out[i].ID = secure.ID()
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
	features := map[string]bool{"http": true}
	for _, doc := range p.Documents {
		var walk func([]*Node, string)
		walk = func(nodes []*Node, parent string) {
			for _, n := range nodes {
				if !n.Enabled() {
					continue
				}
				kind := parent
				if n.Name == "http" || n.Name == "stream" {
					kind = n.Name
				}
				switch n.Name {
				case "server":
					if parent == "stream" {
						features["stream"] = true
					}
				case "ssl_certificate", "ssl_certificate_key":
					if kind == "stream" {
						features["stream_tls"] = true
					} else {
						features["tls"] = true
					}
				case "listen":
					for _, a := range n.Args {
						if a.Value == "ssl" {
							if kind == "stream" {
								features["stream_tls"] = true
							} else {
								features["tls"] = true
							}
						}
					}
				case "set_real_ip_from", "real_ip_header", "real_ip_recursive":
					if kind == "stream" {
						features["stream_real_ip"] = true
					} else {
						features["real_ip"] = true
					}
				case "ssl_preread":
					features["stream_ssl_preread"] = true
				case "map":
					features["map"] = true
				case "volatile":
					features["map_volatile"] = true
				case "limit_req", "limit_req_zone":
					features["limit_req"] = true
				case "limit_conn", "limit_conn_zone":
					features["limit_conn"] = true
				case "limit_req_dry_run":
					features["limit_req_observe"] = true
				case "limit_conn_dry_run":
					features["limit_conn_observe"] = true
				case "rewrite", "return", "if":
					features["rewrite"] = true
				}
				walk(n.Children, kind)
			}
		}
		walk(doc.Nodes, "")
	}
	for _, w := range p.Tree.WAFPolicies {
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

func (p *Parsed) MigrationLocalDependencies() []string {
	seen := map[string]bool{}
	for _, doc := range p.Documents {
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if !node.Enabled() {
					continue
				}
				for _, arg := range node.Args {
					if certificates.IsSystemCA(arg.Value) {
						seen[arg.Value] = true
					}
				}
				walk(node.Children)
			}
		}
		walk(doc.Nodes)
	}
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
