package nginxconfig

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type NativeModulesRequest struct {
	BaseVersion int64    `json:"base_version"`
	Paths       []string `json:"paths"`
}

func (in *NativeModulesRequest) UnmarshalJSON(data []byte) error {
	var request struct {
		BaseVersion *int64    `json:"base_version"`
		Paths       *[]string `json:"paths"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.BaseVersion == nil || request.Paths == nil {
		return errors.New("模块请求须明确提供基础版本和 paths 数组")
	}
	in.BaseVersion = *request.BaseVersion
	in.Paths = *request.Paths
	return nil
}

// Module selection changes only top-level load_module spans. The source tree
// remains authoritative and uses the ordinary revision, scope and apply flow.
func (s *Service) SetNativeModules(ctx context.Context, p auth.Principal, requestID, key string, in NativeModulesRequest) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets", "security.write"); err != nil {
		return SaveResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Action string
		Input  NativeModulesRequest
	}{"native_modules", in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	if in.BaseVersion < 0 || in.Paths == nil || len(in.Paths) > limits.NginxModules {
		return SaveResult{}, fault.Invalid("模块基础版本或选择数组无效")
	}
	selected := map[string]bool{}
	approved := map[string]bool{}
	for _, name := range s.Policy.ModulePaths {
		approved[name] = true
	}
	for _, name := range in.Paths {
		if !approved[name] || selected[name] {
			return SaveResult{}, fault.Invalid("模块路径未获本机批准或存在重复")
		}
		selected[name] = true
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
	edits := map[string][]Edit{}
	for _, doc := range parsed.Documents {
		if doc.File.Path == "nginx.conf" {
			main = doc
		}
		var walk func([]*Node, string) error
		walk = func(nodes []*Node, parent string) error {
			for _, node := range nodes {
				if parent == "map" || parent == "geo" || parent == "types" || parent == "split_clients" {
					continue
				}
				if node.Name == "load_module" {
					if doc.File.Path != "nginx.conf" || parent != "" || node.Open >= 0 || len(node.Args) != 1 || node.ArgumentComments {
						return fault.Conflict("现有模块指令包含复杂结构或参数注释，请先通过原文整理")
					}
					edits[doc.File.ID] = append(edits[doc.File.ID], Edit{Start: node.Start, End: node.End})
				}
				if err := walk(node.Children, node.Name); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(doc.Nodes, ""); err != nil {
			return SaveResult{}, err
		}
	}
	if main == nil {
		return SaveResult{}, fault.Invalid("缺少主配置")
	}
	var source strings.Builder
	for _, name := range s.Policy.ModulePaths {
		if selected[name] {
			source.WriteString("load_module " + name + ";\n")
		}
	}
	at := 0
	if len(main.Nodes) > 0 {
		at = main.Nodes[0].Start
	}
	if source.Len() > 0 {
		edits[main.File.ID] = append(edits[main.File.ID], Edit{Start: at, End: at, Text: source.String()})
	}
	files, err := parsed.editFiles(edits)
	if err != nil {
		return SaveResult{}, err
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files}, digest)
}
