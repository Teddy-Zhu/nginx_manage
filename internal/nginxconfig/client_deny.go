package nginxconfig

import (
	"errors"
	"net/netip"
	"sort"
	"strings"

	"nginxpanel/internal/limits"
)

const ClientDenyVariablePrefix = "nginxpanel_client_deny"

// ClientDenyBindings declares an entry point; runtime addresses are never part
// of the editable source tree. Each entry belongs to one explicit HTTP server.
func (p *Parsed) ClientDenyBindings() (map[string][]string, error) {
	out := map[string][]string{}
	budget := 0
	for _, resource := range p.Tree.Resources {
		if !resource.Metadata.ClientDeny {
			continue
		}
		if resource.Kind != "http" {
			return nil, errors.New("客户端拒绝入口仅用于 HTTP 站点")
		}
		if !resource.Metadata.Enabled {
			continue
		}
		_, _, server, err := p.resource(resource.ID)
		if err != nil {
			return nil, err
		}
		if server.Name != "server" {
			return nil, errors.New("客户端拒绝入口只能绑定 HTTP server")
		}
		nodes, err := p.ExpandNodes(server.Children, 0)
		if err != nil {
			return nil, err
		}
		header, recursive := "", false
		trusted := map[string]bool{}
		for _, node := range nodes {
			budget++
			if budget > limits.Directives {
				return nil, errors.New("客户端拒绝入口的配置展开超过数量限制")
			}
			switch node.Name {
			case "set_real_ip_from":
				if len(node.Args) != 1 {
					return nil, errors.New("客户端拒绝入口需要明确的可信代理 CIDR")
				}
				prefix, err := netip.ParsePrefix(node.Args[0].Value)
				if err != nil {
					ip, parseErr := netip.ParseAddr(node.Args[0].Value)
					if parseErr != nil || ip.Zone() != "" {
						return nil, errors.New("客户端拒绝入口的可信代理不能使用主机名或 Unix Socket")
					}
					prefix = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
				}
				if prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
					return nil, errors.New("客户端拒绝入口不能信任所有来源或使用非规范代理网段")
				}
				trusted[prefix.Masked().String()] = true
			case "real_ip_header":
				if len(node.Args) != 1 || header != "" {
					return nil, errors.New("客户端拒绝入口需要唯一的真实 IP 请求头")
				}
				header = strings.ToLower(node.Args[0].Value)
			case "real_ip_recursive":
				if len(node.Args) != 1 || node.Args[0].Value != "on" || recursive {
					return nil, errors.New("客户端拒绝入口需要唯一的 real_ip_recursive on")
				}
				recursive = true
			}
			overridden, err := p.clientDenyRealIPOverride(node.Children, 0, &budget)
			if err != nil {
				return nil, err
			}
			if overridden {
				return nil, errors.New("客户端拒绝入口不接受下级位置覆盖真实 IP 配置")
			}
		}
		if len(trusted) == 0 || len(trusted) > 64 || !recursive || header != "x-forwarded-for" && header != "x-real-ip" && header != "cf-connecting-ip" {
			return nil, errors.New("客户端拒绝入口需要在站点明确配置可信代理、真实 IP 请求头和递归恢复")
		}
		prefixes := []string{}
		for prefix := range trusted {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		out[resource.ID] = prefixes
		if len(out) > 32 {
			return nil, errors.New("客户端拒绝入口最多支持 32 个站点")
		}
	}
	return out, nil
}

func (p *Parsed) clientDenyRealIPOverride(nodes []*Node, depth int, budget *int) (bool, error) {
	if len(nodes) == 0 {
		return false, nil
	}
	if depth > limits.Depth {
		return false, errors.New("客户端拒绝入口的下级配置超过深度限制")
	}
	expanded, err := p.ExpandNodes(nodes, depth)
	if err != nil {
		return false, err
	}
	for _, node := range expanded {
		*budget++
		if *budget > limits.Directives {
			return false, errors.New("客户端拒绝入口的配置展开超过数量限制")
		}
		if node.Name == "set_real_ip_from" || node.Name == "real_ip_header" || node.Name == "real_ip_recursive" {
			return true, nil
		}
		if found, err := p.clientDenyRealIPOverride(node.Children, depth+1, budget); found || err != nil {
			return found, err
		}
	}
	return false, nil
}
