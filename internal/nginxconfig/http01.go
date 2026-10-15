package nginxconfig

import (
	"errors"
	"strings"
)

const HTTP01Prefix = "/.well-known/acme-challenge/"
const HTTP01Placeholder = "location ^~ /.well-known/acme-challenge/ { return 404; }"

type HTTP01Server struct {
	FileID           string
	Server, Location *Node
	Directives       []*Node
}

// The logical placeholder exposes no host path. Only the Agent supplies its
// fixed responder socket when rendering an immutable runtime revision.
func IsHTTP01(node *Node) bool {
	return node.Name == "location" && len(node.Args) == 2 && node.Args[0].Value == "^~" && node.Args[1].Value == HTTP01Prefix && len(node.Children) == 1 && node.Children[0].Name == "return" && len(node.Children[0].Args) == 1 && node.Children[0].Args[0].Value == "404" && node.Children[0].Open < 0
}
func http01Path(node *Node) string {
	if node.Name != "location" || len(node.Args) == 0 {
		return ""
	}
	return node.Args[len(node.Args)-1].Value
}
func (p *Parsed) http01Reason(server *Node) string {
	nodes, err := p.ExpandNodes(server.Children, 0)
	if err != nil {
		return "无法解析站点 include"
	}
	count := 0
	for _, node := range nodes {
		if IsHTTP01(node) {
			count++
			found := false
			for _, direct := range server.Children {
				found = found || direct == node
			}
			if !found {
				return "验证入口位于共享 include，请通过原生配置明确归属"
			}
			continue
		}
		var conflict func([]*Node) bool
		conflict = func(items []*Node) bool {
			for _, item := range items {
				if strings.HasPrefix(http01Path(item), HTTP01Prefix) || conflict(item.Children) {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(http01Path(node), HTTP01Prefix) || conflict(node.Children) {
			return "验证路径存在原生覆盖，请先整理原生配置"
		}
	}
	if count > 1 {
		return "HTTP-01 验证入口重复"
	}
	return ""
}
func (p *Parsed) HTTP01Servers() ([]HTTP01Server, error) {
	owners := map[*Node]string{}
	for id, doc := range p.Documents {
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				owners[node] = id
				walk(node.Children)
			}
		}
		walk(doc.Nodes)
	}
	out := []HTTP01Server{}
	for _, doc := range p.Documents {
		if doc.File.Path != "nginx.conf" {
			continue
		}
		root, err := p.ExpandNodes(doc.Nodes, 0)
		if err != nil {
			return nil, err
		}
		for _, block := range root {
			if block.Name != "http" {
				continue
			}
			nodes, err := p.ExpandNodes(block.Children, 0)
			if err != nil {
				return nil, err
			}
			for _, server := range nodes {
				if server.Name != "server" || !server.Enabled() {
					continue
				}
				directives, err := p.ExpandNodes(server.Children, 0)
				if err != nil {
					return nil, err
				}
				for _, node := range directives {
					if !IsHTTP01(node) {
						continue
					}
					if reason := p.http01Reason(server); reason != "" {
						return nil, errors.New(reason)
					}
					out = append(out, HTTP01Server{owners[server], server, node, directives})
				}
			}
		}
	}
	return out, nil
}
