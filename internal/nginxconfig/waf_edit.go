package nginxconfig

import (
	"errors"
	"path"
	"strings"
)

func managedNodeKey(n *Node) string {
	key := n.Name
	if n.Name == "map" && len(n.Args) == 2 {
		return key + ":" + n.Args[1].Value
	}
	if (n.Name == "if" || n.Name == "set") && len(n.Args) > 0 {
		return key + ":" + n.Args[0].Value
	}
	return key
}

// Only canonical, previously projected nodes reach this editor. It patches
// tokens and child rows; comments and unrelated source bytes remain in place.
func patchWAFSource(source, desired string) (string, error) {
	oldNodes, err := sourceNodes(source)
	if err != nil {
		return "", err
	}
	newNodes, err := sourceNodes(desired)
	if err != nil {
		return "", err
	}
	edits := []Edit{}
	var patchNode func(*Node, *Node) error
	patchNode = func(old, next *Node) error {
		if old.ArgumentComments || (old.Open >= 0) != (next.Open >= 0) {
			return errors.New("策略原文已无法可靠映射")
		}
		if old.Name != next.Name {
			l := lexer{source: source[old.Start:], line: 1}
			token, err := l.next()
			if err != nil {
				return err
			}
			edits = append(edits, Edit{old.Start, old.Start + token.End, argsText([]string{next.Name})})
		}
		equal := len(old.Args) == len(next.Args)
		if equal {
			for i, arg := range old.Args {
				if arg.Value != next.Args[i].Value {
					equal = false
				}
			}
		}
		if !equal {
			if len(old.Args) == 0 || len(next.Args) == 0 {
				return errors.New("策略参数结构已变化")
			}
			edits = append(edits, Edit{old.Args[0].Start, old.Args[len(old.Args)-1].End, argsText(nodeValues(next))})
		}
		for i, child := range old.Children {
			if i < len(next.Children) {
				if err := patchNode(child, next.Children[i]); err != nil {
					return err
				}
			} else {
				edits = append(edits, Edit{child.Start, child.End, ""})
			}
		}
		if len(next.Children) > len(old.Children) {
			pos, indent := blockInsertion(source, old.Close)
			text := ""
			for _, child := range next.Children[len(old.Children):] {
				text += indent + "    " + desired[child.Start:child.End] + "\n"
			}
			if pos > 0 && source[pos-1] != '\n' {
				text = "\n" + text
			}
			edits = append(edits, Edit{pos, pos, text})
		}
		return nil
	}
	oldByKey := map[string]*Node{}
	newByKey := map[string]*Node{}
	for _, node := range oldNodes {
		key := managedNodeKey(node)
		if oldByKey[key] != nil {
			return "", errors.New("策略存在重复定义")
		}
		oldByKey[key] = node
	}
	for _, node := range newNodes {
		newByKey[managedNodeKey(node)] = node
	}
	for key, node := range oldByKey {
		if next := newByKey[key]; next != nil {
			if err := patchNode(node, next); err != nil {
				return "", err
			}
		} else {
			edits = append(edits, Edit{node.Start, node.End, ""})
		}
	}
	insertions := map[int]string{}
	for i, node := range newNodes {
		if oldByKey[managedNodeKey(node)] != nil {
			continue
		}
		pos := len(source)
		indent := ""
		for _, later := range newNodes[i+1:] {
			if existing := oldByKey[managedNodeKey(later)]; existing != nil {
				pos = existing.Start
				_, indent = blockInsertion(source, pos)
				break
			}
		}
		text := desired[node.Start:node.End] + "\n" + indent
		if pos == len(source) && pos > 0 && source[pos-1] != '\n' && insertions[pos] == "" {
			text = "\n" + text
		}
		insertions[pos] += text
	}
	for pos, text := range insertions {
		edits = append(edits, Edit{pos, pos, text})
	}
	_, start, end, err := wafMetadata(desired)
	if err == nil {
		_, oldStart, oldEnd, err := wafMetadata(source)
		if err != nil {
			return "", err
		}
		edits = append(edits, Edit{oldStart, oldEnd, desired[start:end]})
	}
	return applyEdits(source, edits)
}
func (p *Parsed) wafBindingReason(server *Node) string {
	reason := p.wafHTTPBindingReason()
	bindings := 0
	var walk func([]*Node, bool)
	walk = func(nodes []*Node, direct bool) {
		for _, node := range nodes {
			if _, known := httpsRedirect(node); known && direct {
				continue
			}
			if node.Name == "include" {
				if direct && p.knownWAFInclude(node) {
					bindings++
					if bindings > 1 {
						reason = "站点存在多个 WAF 引用，请先整理原生配置"
					}
				} else if !direct || !p.knownAccessInclude(node) {
					reason = "存在共享 include 或子路径规则，无法确认 WAF 叠加行为"
				}
				continue
			}
			if strings.HasPrefix(node.Name, "limit_req") || strings.HasPrefix(node.Name, "limit_conn") || node.Name == "client_max_body_size" || node.Name == "if" || node.Name == "return" || node.Name == "rewrite" || node.Name == "set" && len(node.Args) > 0 && strings.HasPrefix(node.Args[0].Value, "$nginxpanel_waf_") {
				reason = "原生限流、请求体或重写指令与 WAF 策略重叠，请使用原生配置"
			}
			walk(node.Children, false)
		}
	}
	walk(server.Children, true)
	return reason
}

// Server-level limits replace inherited HTTP limits. Refuse form binding when
// it would silently change an existing native protection boundary.
func (p *Parsed) wafHTTPBindingReason() string {
	visited := map[string]bool{}
	reason := ""
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if node.Name == "client_max_body_size" || strings.HasPrefix(node.Name, "limit_req") && node.Name != "limit_req_zone" || strings.HasPrefix(node.Name, "limit_conn") && node.Name != "limit_conn_zone" {
				reason = "HTTP 上下文存在继承的原生限流或请求体规则，请使用原生配置"
				return
			}
			if node.Name == "include" && len(node.Args) == 1 {
				for _, doc := range p.Documents {
					matched, _ := path.Match(node.Args[0].Value, doc.File.Path)
					if matched && !visited[doc.File.Path] {
						visited[doc.File.Path] = true
						walk(doc.Nodes)
					}
				}
			}
		}
	}
	for _, doc := range p.Documents {
		if doc.File.Path == "nginx.conf" {
			for _, node := range doc.Nodes {
				if node.Name == "http" && node.Open >= 0 {
					walk(node.Children)
				}
			}
			break
		}
	}
	return reason
}
