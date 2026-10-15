package nginxconfig

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

func (in WAFConfig) RequiredFeatures() []string {
	if !in.Metadata.Enabled {
		return nil
	}
	out := []string{"http", "map", "map_volatile", "rewrite"}
	if in.Rate > 0 {
		out = append(out, "limit_req", "limit_req_status")
		if in.Observe {
			out = append(out, "limit_req_observe")
		}
	}
	if in.Connections > 0 {
		out = append(out, "limit_conn", "limit_conn_status")
		if in.Observe {
			out = append(out, "limit_conn_observe")
		}
	}
	return out
}
func (s *Service) WAF(ctx context.Context, p auth.Principal, requestID, key, id, action string, in WAFInput) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets", "security.write"); err != nil {
		return SaveResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Action, ID string
		Input      WAFInput
	}{action, id, in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	if action != "create" && action != "update" && action != "delete" {
		return SaveResult{}, fault.Invalid("WAF 策略操作无效")
	}
	if action != "delete" {
		if err := validateWAF(in.WAFConfig); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
		if features := in.RequiredFeatures(); len(features) > 0 {
			if s.RequireFeatures == nil {
				return SaveResult{}, fault.Unavailable("尚未连接 Nginx 模块能力探测")
			}
			if err := s.RequireFeatures(ctx, features); err != nil {
				return SaveResult{}, err
			}
		}
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	parsed, err := Parse(tree.Files, s.Policy)
	if err != nil {
		return SaveResult{}, err
	}
	var policy *WAFPolicy
	for i := range parsed.Tree.WAFPolicies {
		if parsed.Tree.WAFPolicies[i].ID == id {
			policy = &parsed.Tree.WAFPolicies[i]
		}
	}
	if action == "create" {
		if len(parsed.Tree.WAFPolicies) >= limits.WAFPolicies {
			return SaveResult{}, fault.Conflict("WAF 策略数量已达上限")
		}
		id = secure.ID()
	} else {
		if policy == nil {
			return SaveResult{}, ErrNotFound
		}
		if !policy.Editable {
			return SaveResult{}, fault.Conflict(policy.Reason)
		}
	}
	edits := map[string][]Edit{}
	files := append([]File(nil), tree.Files...)
	if action == "delete" {
		var reject bool
		var walk func(string, []*Node)
		walk = func(fileID string, nodes []*Node) {
			for _, node := range nodes {
				if node.Name == "include" && len(node.Args) == 1 {
					pattern := node.Args[0].Value
					binding, _ := path.Match(pattern, wafPath(id, "server"))
					definition, _ := path.Match(pattern, wafPath(id, "http"))
					if binding || definition && pattern != wafPath(id, "http") {
						reject = true
					}
					if definition && pattern == wafPath(id, "http") {
						edits[fileID] = append(edits[fileID], Edit{node.Start, node.End, ""})
					}
				} else {
					for _, arg := range node.Args {
						if strings.Contains(arg.Value, "nginxpanel_waf_"+strings.ReplaceAll(id, "-", "")) {
							reject = true
						}
					}
				}
				walk(fileID, node.Children)
			}
		}
		for _, doc := range parsed.Documents {
			if doc.File.ID != policy.HTTPFileID && doc.File.ID != policy.ServerFileID {
				walk(doc.File.ID, doc.Nodes)
			}
		}
		if reject {
			return SaveResult{}, fault.Conflict("策略仍被站点或原生指令引用，请先解除绑定")
		}
		files, err = parsed.editFiles(edits)
		if err != nil {
			return SaveResult{}, err
		}
		kept := []File{}
		for _, file := range files {
			if file.ID != policy.HTTPFileID && file.ID != policy.ServerFileID {
				kept = append(kept, file)
			}
		}
		files = kept
	} else {
		httpText, serverText := wafSource(id, in.WAFConfig)
		if action == "create" {
			if len(files)+2 > limits.Files {
				return SaveResult{}, fault.Conflict("配置文件数量已达上限")
			}
			files = append(files, File{ID: secure.ID(), Path: wafPath(id, "http"), Content: httpText}, File{ID: secure.ID(), Path: wafPath(id, "server"), Content: serverText})
			var main *Document
			for _, doc := range parsed.Documents {
				if doc.File.Path == "nginx.conf" {
					main = doc
				}
			}
			var http *Node
			for _, node := range main.Nodes {
				if node.Name == "http" {
					if http != nil {
						return SaveResult{}, fault.Conflict("需要唯一 HTTP 上下文")
					}
					http = node
				}
			}
			if http == nil {
				return SaveResult{}, fault.Conflict("需要主配置 HTTP 上下文")
			}
			for i := range files {
				if files[i].ID == main.File.ID {
					at := http.Open + 1
					files[i].Content = files[i].Content[:at] + "\n    include " + wafPath(id, "http") + ";\n" + files[i].Content[at:]
				}
			}
		} else {
			for i := range files {
				next := ""
				if files[i].ID == policy.HTTPFileID {
					next = httpText
				} else if files[i].ID == policy.ServerFileID {
					next = serverText
				} else {
					continue
				}
				text, err := patchWAFSource(files[i].Content, next)
				if err != nil {
					return SaveResult{}, fault.Conflict(err.Error())
				}
				files[i].Content = text
			}
		}
		next, err := Parse(files, s.Policy)
		if err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
		if len(next.Tree.Diagnostics) > 0 {
			return SaveResult{Tree: next.Tree}, ErrInvalid
		}
		for _, candidate := range next.Tree.WAFPolicies {
			if candidate.ID == id && !candidate.Editable {
				return SaveResult{}, fault.Conflict(candidate.Reason)
			}
		}
		for _, candidate := range next.Tree.WAFPolicies {
			if candidate.ID != id {
				continue
			}
			for _, resourceID := range candidate.Resources {
				_, _, server, err := next.resource(resourceID)
				if err != nil {
					return SaveResult{}, fault.Conflict("站点绑定来源不唯一")
				}
				if reason := next.wafBindingReason(server); reason != "" {
					return SaveResult{}, fault.Conflict(reason)
				}
			}
		}
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}
