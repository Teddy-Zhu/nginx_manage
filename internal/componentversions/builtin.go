package componentversions

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"nginxpanel/internal/secure"
)

//go:embed builtin.json
var bundledVersions []byte

const BuiltinCatalogURL = "https://raw.githubusercontent.com/Teddy-Zhu/nginx_manage/main/internal/componentversions/builtin.json"

// Image is private adapter metadata. Third-party software source JSON never
// describes containers, mounts, capabilities or port mappings.
type BuiltinRelease struct {
	Version
	Image string `json:"image"`
}
type BuiltinDocument struct {
	Schema       int                         `json:"schema"`
	Applications map[string][]BuiltinRelease `json:"applications"`
}

func parseBuiltin(raw []byte) (BuiltinDocument, error) {
	var document BuiltinDocument
	if err := json.Unmarshal(raw, &document); err != nil || document.Schema != 1 {
		return document, errors.New("内置组件版本目录无效")
	}
	if len(document.Applications) != 2 || len(document.Applications["frps"]) == 0 || len(document.Applications["fail2ban"]) == 0 {
		return document, errors.New("内置组件版本目录缺少软件")
	}
	for app, versions := range document.Applications {
		prefix := ""
		switch app {
		case "frps":
			prefix = "ghcr.io/fatedier/frps@sha256:"
		case "fail2ban":
			prefix = "docker.io/crazymax/fail2ban@sha256:"
		default:
			return document, errors.New("内置组件标识无效")
		}
		if len(versions) > 1000 {
			return document, errors.New("内置组件版本过多")
		}
		seen := map[string]bool{}
		for _, release := range versions {
			if err := release.Version.Validate(); err != nil {
				return document, err
			}
			digest, ok := strings.CutPrefix(release.Image, prefix)
			if !ok || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" || seen[release.ID] {
				return document, errors.New("内置组件版本镜像身份无效或版本重复")
			}
			seen[release.ID] = true
		}
	}
	return document, nil
}

func Builtin(ctx context.Context, data string, refresh bool) (BuiltinDocument, bool, error) {
	fallback, err := parseBuiltin(bundledVersions)
	if err != nil {
		return fallback, false, err
	}
	name := filepath.Join(data, "agent", "component-versions", "builtin-source.json")
	if raw, readErr := secure.ReadRootFile(name, 512<<10); readErr == nil {
		cached, parseErr := parseBuiltin(raw)
		if parseErr != nil {
			return fallback, false, parseErr
		}
		fallback = cached
	} else if !os.IsNotExist(readErr) {
		return fallback, false, readErr
	}
	if !refresh {
		return fallback, true, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, BuiltinCatalogURL, nil)
	if err != nil {
		return fallback, true, err
	}
	client := http.Client{Timeout: 30e9, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("版本目录不允许重定向") }}
	response, err := client.Do(request)
	if err != nil {
		return fallback, true, errors.New("无法刷新内置版本目录，请检查网络")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fallback, true, errors.New("内置版本目录返回 " + response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
	if err != nil || len(raw) > 512<<10 {
		return fallback, true, errors.New("内置版本目录读取中断或超过大小限制")
	}
	document, err := parseBuiltin(raw)
	if err != nil {
		return fallback, true, err
	}
	if err = WriteFile(name, document); err != nil {
		return fallback, true, err
	}
	return document, false, nil
}
