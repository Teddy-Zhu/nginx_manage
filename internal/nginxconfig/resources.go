package nginxconfig

import (
	"context"
	"encoding/json"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type CreateRequest struct {
	BaseVersion int64    `json:"base_version"`
	Kind        string   `json:"kind"`
	Listen      []string `json:"listen"`
	Domains     []string `json:"domains"`
	Upstream    string   `json:"upstream"`
}

func (s *Service) CreateResource(ctx context.Context, p auth.Principal, requestID, key string, in CreateRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	encoded, err := json.Marshal(struct {
		Action string
		Input  CreateRequest
	}{"create", in})
	if err != nil {
		return SaveResult{}, err
	}
	digest := secure.Hash(encoded)
	if result, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return result, err
	}
	if in.Kind != "http" && in.Kind != "stream" {
		return SaveResult{}, fault.Invalid("资源类型须为 http 或 stream")
	}
	for field, values := range map[string][]string{"listen": in.Listen, "upstream": {in.Upstream}} {
		if err := validateField(field, values, in.Kind); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
	}
	if in.Kind == "http" {
		if err := validateField("domains", in.Domains, in.Kind); err != nil {
			return SaveResult{}, fault.Invalid(err.Error())
		}
	} else if len(in.Domains) > 0 {
		return SaveResult{}, fault.Invalid("Stream 不使用 HTTP 域名")
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
	var main *Document
	for _, doc := range parsed.Documents {
		if doc.File.Path == "nginx.conf" {
			main = doc
		}
	}
	var contextBlock *Node
	for _, n := range main.Nodes {
		if n.Name == in.Kind {
			if contextBlock != nil {
				return SaveResult{}, fault.Conflict("主配置存在多个同类上下文，请先整理原生配置")
			}
			contextBlock = n
		}
	}
	id := secure.ID()
	var block strings.Builder
	block.WriteString("\n    # nginxpanel:resource " + id + "\n    server {\n        listen ")
	for i, value := range in.Listen {
		if i > 0 {
			block.WriteByte(' ')
		}
		block.WriteString(quote(value))
	}
	block.WriteString(";\n")
	if in.Kind == "http" {
		block.WriteString("        server_name ")
		for i, value := range in.Domains {
			if i > 0 {
				block.WriteByte(' ')
			}
			block.WriteString(quote(value))
		}
		block.WriteString(";\n        location / {\n            proxy_pass " + quote(in.Upstream) + ";\n            proxy_http_version 1.1;\n            proxy_set_header Host $host;\n            proxy_set_header X-Real-IP $remote_addr;\n            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n            proxy_set_header X-Forwarded-Proto $scheme;\n        }\n")
	} else {
		block.WriteString("        proxy_pass " + quote(in.Upstream) + ";\n        proxy_connect_timeout 10s;\n        proxy_timeout 60s;\n")
	}
	block.WriteString("    }\n")
	content := main.File.Content
	if contextBlock != nil {
		content = content[:contextBlock.Close] + block.String() + content[contextBlock.Close:]
	} else {
		content += "\n" + in.Kind + " {" + block.String() + "}\n"
	}
	for i := range tree.Files {
		if tree.Files[i].ID == main.File.ID {
			tree.Files[i].Content = content
		}
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: tree.Files}, digest)
}
