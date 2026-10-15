package nginxconfig

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var hstsValue = regexp.MustCompile(`^max-age=(0|[1-9][0-9]*)(; includeSubDomains)?(; preload)?$`)

func validateHSTS(value string) error {
	matches := hstsValue.FindStringSubmatch(value)
	if len(matches) != 4 {
		return errors.New("HSTS 须使用 max-age，并可选 includeSubDomains 与 preload")
	}
	seconds, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || seconds > 63072000 {
		return errors.New("HSTS max-age 允许 0–63072000 秒")
	}
	if matches[3] != "" && (seconds < 31536000 || matches[2] == "") {
		return errors.New("preload 需要至少一年 max-age 和 includeSubDomains")
	}
	return nil
}
func isHSTS(node *Node) bool {
	return node.Name == "add_header" && len(node.Args) > 0 && strings.EqualFold(node.Args[0].Value, "Strict-Transport-Security")
}
func httpsRedirectURL(port string) string {
	if port == "443" {
		return "https://$host$request_uri"
	}
	return "https://$host:" + port + "$request_uri"
}
func httpsRedirect(node *Node) (string, bool) {
	if node.Name != "if" || node.Open < 0 || len(node.Args) != 3 || node.Args[0].Value != "($scheme" || node.Args[1].Value != "=" || node.Args[2].Value != "http)" || len(node.Children) != 1 {
		return "", false
	}
	child := node.Children[0]
	if child.Name != "return" || child.Open >= 0 || len(child.Args) != 2 || child.Args[0].Value != "308" {
		return "", false
	}
	url := child.Args[1].Value
	if url == httpsRedirectURL("443") {
		return "443", true
	}
	port := strings.TrimSuffix(strings.TrimPrefix(url, "https://$host:"), "$request_uri")
	number, err := strconv.Atoi(port)
	return port, err == nil && number > 0 && number <= 65535 && httpsRedirectURL(port) == url
}
func sslPorts(nodes []*Node) map[string]bool {
	ports := map[string]bool{}
	for _, node := range nodes {
		if node.Name != "listen" || len(node.Args) < 2 {
			continue
		}
		ssl := false
		for _, arg := range node.Args[1:] {
			ssl = ssl || arg.Value == "ssl"
		}
		if !ssl {
			continue
		}
		address := node.Args[0].Value
		port := address
		if _, value, err := net.SplitHostPort(address); err == nil {
			port = value
		}
		if number, err := strconv.Atoi(port); err == nil && number > 0 && number <= 65535 {
			ports[strconv.Itoa(number)] = true
		}
	}
	return ports
}
func (p *Parsed) redirectTargetReason(server *Node) string {
	nodes, err := p.ExpandNodes(server.Children, 0)
	if err != nil {
		return "无法确定站点的 HTTPS 监听"
	}
	ports := sslPorts(nodes)
	if len(ports) == 0 {
		return "请先为当前站点保存 HTTPS 监听和证书"
	}
	for _, node := range server.Children {
		if port, known := httpsRedirect(node); known {
			if !ports[port] {
				return "原生跳转目标不属于当前站点 HTTPS 监听"
			}
			continue
		}
		if node.Name == "if" || node.Name == "return" || node.Name == "rewrite" || node.Name == "include" && !p.knownAccessInclude(node) && !p.knownWAFInclude(node) {
			return "存在原生跳转、条件或共享 include，请使用原生配置"
		}
	}
	return ""
}
func (p *Parsed) hstsTargetReason(server *Node) string {
	var overrides func([]*Node) bool
	overrides = func(nodes []*Node) bool {
		for _, node := range nodes {
			if node.Name == "add_header" || node.Name == "include" || overrides(node.Children) {
				return true
			}
		}
		return false
	}
	for _, node := range server.Children {
		if overrides(node.Children) {
			return "子路径响应头或 include 可能覆盖 HSTS，请通过原生配置明确继承"
		}
	}
	for _, node := range server.Children {
		if node.Name == "add_header" {
			return ""
		}
	}
	for _, doc := range p.Documents {
		if doc.File.Path != "nginx.conf" {
			continue
		}
		for _, block := range doc.Nodes {
			if block.Name != "http" {
				continue
			}
			nodes, err := p.ExpandNodes(block.Children, 0)
			if err != nil {
				return "无法核对继承的响应头"
			}
			for _, node := range nodes {
				if node.Name == "add_header" {
					return "HTTP 上下文存在继承的响应头，请通过原生配置明确 HSTS 与响应头继承"
				}
			}
		}
	}
	return ""
}
