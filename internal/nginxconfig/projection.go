package nginxconfig

import (
	"path"
	"strings"
)

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

func InitialFiles() []File {
	return []File{{ID: "main", Path: "nginx.conf", Content: "# NginxPanel managed instance\nworker_processes auto;\npid run/nginx.pid;\nerror_log logs/nginx-global/error.log warn;\nevents {\n    worker_connections 1024;\n}\nhttp {\n    default_type application/octet-stream;\n    include http/*.conf;\n}\n"}}
}
