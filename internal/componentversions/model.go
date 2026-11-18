// Package componentversions defines version metadata for built-in components.
package componentversions

import (
	"errors"
	"runtime"
	"slices"
	"strings"

	"nginxpanel/internal/releases"
)

const BundledNginxID = "bundled-nginx"

type Version struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	SoftwareVersion string   `json:"software_version,omitempty"`
	Channel         string   `json:"channel"`
	PublishedAt     int64    `json:"published_at,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	Architectures   []string `json:"architectures,omitempty"`
	MinimumCore     string   `json:"minimum_core,omitempty"`
	Unavailable     string   `json:"unavailable,omitempty"`
}

type Query struct {
	AppID   string `json:"app_id"`
	Channel string `json:"channel"`
	Page    int    `json:"page"`
	Refresh bool   `json:"refresh"`
}

type State struct {
	Current       *Version `json:"current,omitempty"`
	Previous      *Version `json:"previous,omitempty"`
	Image         string   `json:"image,omitempty"`
	PreviousImage string   `json:"previous_image,omitempty"`
	UpdatedAt     int64    `json:"updated_at,omitempty"`
}

type Catalog struct {
	AppID     string    `json:"app_id"`
	Channel   string    `json:"channel"`
	Page      int       `json:"page"`
	HasMore   bool      `json:"has_more"`
	Versions  []Version `json:"versions"`
	Current   *Version  `json:"current,omitempty"`
	Previous  *Version  `json:"previous,omitempty"`
	CheckedAt int64     `json:"checked_at"`
	Cached    bool      `json:"cached"`
	Error     string    `json:"error,omitempty"`
}

func (q Query) Validate() error {
	if !Identifier(q.AppID) || q.Channel != "stable" && q.Channel != "beta" || q.Page < 1 || q.Page > 1000 {
		return errors.New("版本查询参数无效")
	}
	return nil
}

func Identifier(value string) bool {
	if len(value) < 1 || len(value) > 40 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (v Version) Validate() error {
	if len(v.ID) < 1 || len(v.ID) > 128 || strings.ContainsAny(v.ID, " \t\r\n/\\\x00") || !releases.ValidChannel(v.Version, v.Channel) || len(v.SoftwareVersion) > 128 || len(v.Notes) > 8192 || len(v.Architectures) > 8 || len(v.Unavailable) > 1024 || v.PublishedAt < 0 {
		return errors.New("组件版本信息无效")
	}
	if v.MinimumCore != "" {
		if _, err := releases.CompareVersions(v.MinimumCore, v.MinimumCore); err != nil {
			return errors.New("最低面板版本无效")
		}
	}
	for _, arch := range v.Architectures {
		if arch != "amd64" && arch != "arm64" {
			return errors.New("版本架构无效")
		}
	}
	return nil
}

// ApplyAvailability checks host requirements, never the direction of a version
// change. Older application versions remain selectable.
func ApplyAvailability(v Version, core string) Version {
	if v.Unavailable != "" {
		return v
	}
	if len(v.Architectures) > 0 && !slices.Contains(v.Architectures, runtime.GOARCH) {
		v.Unavailable = "此版本不支持当前服务器架构"
	}
	if v.MinimumCore != "" {
		if comparison, err := releases.CompareVersions(core, v.MinimumCore); err != nil || comparison < 0 {
			v.Unavailable = "请先升级管理面板至 " + v.MinimumCore + " 或更高版本"
		}
	}
	return v
}

func Sort(versions []Version) {
	slices.SortStableFunc(versions, func(a, b Version) int {
		if comparison, err := releases.CompareVersions(a.Version, b.Version); err == nil && comparison != 0 {
			return -comparison
		}
		return strings.Compare(b.ID, a.ID)
	})
}
