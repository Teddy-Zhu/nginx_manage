package componentversions

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

//go:embed builtin.json
var bundledVersions []byte

type BuiltinRelease struct {
	Version
	Image string `json:"image"`
}

type BuiltinDocument struct {
	Schema       int                         `json:"schema"`
	Applications map[string][]BuiltinRelease `json:"applications"`
}

func Builtin() (BuiltinDocument, error) {
	var document BuiltinDocument
	dec := json.NewDecoder(bytes.NewReader(bundledVersions))
	dec.DisallowUnknownFields()
	if dec.Decode(&document) != nil || dec.Decode(new(any)) != io.EOF || document.Schema != 1 || len(document.Applications) != 2 {
		return document, errors.New("内置组件版本目录无效")
	}
	for app, versions := range document.Applications {
		var prefix string
		switch app {
		case "frps":
			prefix = "ghcr.io/fatedier/frps@sha256:"
		case "fail2ban":
			prefix = "docker.io/crazymax/fail2ban@sha256:"
		default:
			return document, errors.New("内置组件标识无效")
		}
		if len(versions) == 0 {
			return document, errors.New("内置组件缺少可用版本")
		}
		seen := map[string]bool{}
		for _, release := range versions {
			if err := release.Version.Validate(); err != nil {
				return document, err
			}
			digest, ok := strings.CutPrefix(release.Image, prefix)
			if !ok || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" || seen[release.ID] {
				return document, errors.New("内置组件镜像摘要无效或版本重复")
			}
			seen[release.ID] = true
		}
	}
	return document, nil
}
