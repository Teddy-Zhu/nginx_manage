package panelruntime

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"nginxpanel/internal/secure"
)

// FrontendEntrypoints identifies module, stylesheet and preload references in signed HTML.
// Browsers compare these with the document they loaded, including across the
// first version poll, rather than treating the first poll as their UI version.
func FrontendEntrypoints(s FrontendSnapshot) ([]string, error) {
	f, ok := s.Files["index.html"]
	if !ok {
		return nil, errors.New("前端缺少入口清单")
	}
	raw, err := secure.ReadRootFile(filepath.Join(s.Directory, "index.html"), WebFileLimit)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != f.Size || secure.Hash(raw) != f.SHA256 {
		return nil, errors.New("前端入口与批准清单不一致")
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	scripts := map[string]bool{}
	modules := 0
	for {
		typeOf := z.Next()
		if typeOf == html.ErrorToken {
			if z.Err() != io.EOF {
				return nil, z.Err()
			}
			break
		}
		if typeOf != html.StartTagToken && typeOf != html.SelfClosingTagToken {
			continue
		}
		t := z.Token()
		if t.Data == "base" {
			return nil, errors.New("独立前端不能重定义页面基础路径")
		}
		if t.Data != "script" && t.Data != "link" {
			continue
		}
		attrs := map[string]string{}
		for _, a := range t.Attr {
			if _, found := attrs[a.Key]; found {
				return nil, errors.New("前端入口包含重复资源属性")
			}
			attrs[a.Key] = a.Val
		}
		var src string
		module := t.Data == "script" && attrs["type"] == "module"
		rels := strings.Fields(attrs["rel"])
		if t.Data == "script" {
			src = attrs["src"]
		} else if slices.Contains(rels, "stylesheet") || slices.Contains(rels, "modulepreload") || slices.Contains(rels, "icon") {
			src = attrs["href"]
		}
		if src == "" {
			if module {
				return nil, errors.New("前端入口须引用独立模块文件")
			}
			continue
		}
		u, e := url.Parse(src)
		if e != nil || u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(src, "/") || strings.HasPrefix(src, "//") || path.Clean(src) != src {
			return nil, errors.New("前端入口资源须使用本站绝对路径")
		}
		if _, found := s.Files[strings.TrimPrefix(src, "/")]; !found {
			return nil, errors.New("前端入口引用了签名清单外的文件")
		}
		if module {
			modules++
		}
		if module || t.Data == "link" {
			scripts[src] = true
		}
	}
	if modules == 0 || modules > 16 || len(scripts) > 64 {
		return nil, errors.New("前端入口资源数量无效")
	}
	result := make([]string, 0, len(scripts))
	for src := range scripts {
		result = append(result, src)
	}
	sort.Strings(result)
	return result, nil
}
