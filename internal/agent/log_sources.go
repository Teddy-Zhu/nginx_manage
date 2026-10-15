package agent

import (
	"errors"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

type logSource struct {
	Source logs.Source `json:"source"`
	Path   string      `json:"path"`
}

func collectLogSources(p *nginxconfig.Parsed) ([]logSource, error) {
	names := map[string]string{}
	for _, resource := range p.Tree.Resources {
		names[resource.ID] = resource.Metadata.Name
	}
	found := map[string]logSource{}
	var walk func([]*nginxconfig.Node) error
	walk = func(nodes []*nginxconfig.Node) error {
		expanded, err := p.ExpandNodes(nodes, 0)
		if err != nil {
			return err
		}
		for _, node := range expanded {
			if !node.Enabled() {
				continue
			}
			if (node.Name == "access_log" || node.Name == "error_log") && len(node.Args) > 0 && node.Args[0].Value != "off" && node.Args[0].Value != "/dev/null" {
				name := node.Args[0].Value
				kind, id, ok := nginxconfig.ManagedLogPath(name)
				if !ok {
					return errors.New("unmanaged log path")
				}
				format, category := "text", "http_access"
				if kind == "stream" {
					category = "stream"
				}
				if kind == "global" {
					category = "global"
				}
				if node.Name == "error_log" {
					category = "http_error"
					if kind == "stream" {
						category = "stream_error"
					}
					if kind == "global" {
						category = "global_error"
					}
				} else if len(node.Args) > 1 && (node.Args[1].Value == "nginxpanel_http" || node.Args[1].Value == "nginxpanel_stream") {
					format = node.Args[1].Value
				}
				label := names[id]
				if label == "" {
					label = id
				}
				if label == "" {
					label = "Nginx 全局"
				}
				source := logSource{Path: name, Source: logs.Source{ID: secure.Hash([]byte(name)), ResourceID: id, Category: category, Label: label + " · " + path.Base(name), Format: format, Sensitive: format == "text", Active: true}}
				if old, ok := found[name]; ok && old.Source.Format != format {
					return errors.New("one log path uses conflicting formats")
				}
				found[name] = source
				if len(found) > limits.PublishedLogSources {
					return errors.New("log source limit reached")
				}
			}
			if err := walk(node.Children); err != nil {
				return err
			}
		}
		return nil
	}
	for _, doc := range p.Documents {
		if doc.File.Path == "nginx.conf" {
			if err := walk(doc.Nodes); err != nil {
				return nil, err
			}
		}
	}
	// The renderer supplies this default when native HTTP configuration omits
	// access_log, so Nginx's combined-format fallback cannot collect queries.
	for _, doc := range p.Documents {
		if doc.File.Path == "nginx.conf" {
			root, err := p.ExpandNodes(doc.Nodes, 0)
			if err != nil {
				return nil, err
			}
			hasRootErrorLog := false
			for _, node := range root {
				hasRootErrorLog = hasRootErrorLog || node.Name == "error_log"
				if node.Name == "http" {
					children, err := p.ExpandNodes(node.Children, 0)
					if err != nil {
						return nil, err
					}
					hasLog := false
					for _, child := range children {
						hasLog = hasLog || child.Name == "access_log"
					}
					if !hasLog {
						name := "logs/nginx-global/access.log"
						if old, exists := found[name]; exists && old.Source.Format != "nginxpanel_http" {
							return nil, errors.New("default access log conflicts with a native log format")
						}
						found[name] = logSource{Path: name, Source: logs.Source{ID: secure.Hash([]byte(name)), Category: "global", Label: "Nginx 全局 · access.log", Format: "nginxpanel_http", Active: true}}
					}
				}
			}
			if !hasRootErrorLog {
				name := "logs/nginx-global/error.log"
				found[name] = logSource{Path: name, Source: logs.Source{ID: secure.Hash([]byte(name)), Category: "global_error", Label: "Nginx 全局 · error.log", Format: "text", Sensitive: true, Active: true}}
			}
		}
	}
	out := make([]logSource, 0, len(found))
	for _, source := range found {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if !validLogSources(out) {
		return nil, errors.New("invalid managed log source metadata")
	}
	return out, nil
}

func validLogSources(sources []logSource) bool {
	if len(sources) > limits.PublishedLogSources {
		return false
	}
	seen := map[string]bool{}
	for _, source := range sources {
		kind, id, ok := nginxconfig.ManagedLogPath(source.Path)
		value := source.Source
		if !ok || value.ID != secure.Hash([]byte(source.Path)) || value.ResourceID != id || seen[source.Path] || len(value.Label) > 256 || !utf8.ValidString(value.Label) || strings.ContainsAny(value.Label, "\x00\r\n") {
			return false
		}
		category := "http_access"
		if kind == "stream" {
			category = "stream"
		}
		if kind == "global" {
			category = "global"
		}
		if path.Base(source.Path) == "error.log" {
			category = "http_error"
			if kind == "stream" {
				category = "stream_error"
			}
			if kind == "global" {
				category = "global_error"
			}
			if value.Format != "text" {
				return false
			}
		}
		if value.Category != category || value.Sensitive != (value.Format == "text") || value.Format != "text" && (kind == "stream" && value.Format != "nginxpanel_stream" || kind != "stream" && value.Format != "nginxpanel_http") {
			return false
		}
		seen[source.Path] = true
	}
	return true
}
