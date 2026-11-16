package releases

import (
	"encoding/json"
	"errors"
	"strings"
)

// SelectionTag keeps component releases out of the core's latest release.
func SelectionTag(version string, selected []string) string {
	if len(selected) == 1 && selected[0] == "image-nginx" {
		return "nginx-v" + version
	}
	return "v" + version
}

func ManifestTag(m Manifest) string {
	if len(m.Assets) == 0 && len(m.Images) == 1 && m.Images[0].ID == "nginx" {
		return SelectionTag(m.Version, []string{"image-nginx"})
	}
	return SelectionTag(m.Version, nil)
}

func (in OnlineInput) imageChannel() bool {
	return len(in.Components) == 1 && in.Components[0] == "nginx" || len(in.Assets) == 1 && in.Assets[0] == "image-nginx"
}

func (in OnlineInput) tagPrefix() string {
	if in.imageChannel() {
		return "nginx-v"
	}
	return "v"
}

func (in OnlineInput) metadataEndpoint() string {
	if in.Tag == "" && in.imageChannel() {
		return "?per_page=100"
	}
	return tagEndpoint(in.Tag)
}

// GitHub's latest endpoint is reserved for the core. Image discovery uses one
// bounded page; older component releases remain available by explicit tag.
func discoverRelease(raw []byte, in OnlineInput) (githubRelease, error) {
	if in.Tag != "" || !in.imageChannel() {
		return parseGithubRelease(raw, in)
	}
	var candidates []json.RawMessage
	if err := decodeJSON(raw, &candidates, false); err != nil || len(candidates) > 100 {
		return githubRelease{}, errors.New("GitHub 组件发行列表无效或超过 100 项")
	}
	var selected githubRelease
	for _, candidate := range candidates {
		var identity githubRelease
		if err := json.Unmarshal(candidate, &identity); err != nil {
			return githubRelease{}, errors.New("GitHub 组件发行元数据无效")
		}
		if identity.Draft || identity.Prerelease || !strings.HasPrefix(identity.Tag, in.tagPrefix()) {
			continue
		}
		release, err := parseGithubRelease(candidate, in)
		if err != nil {
			return githubRelease{}, err
		}
		if selected.ID == 0 || release.PublishedAt.After(selected.PublishedAt) {
			selected = release
		}
	}
	if selected.ID == 0 {
		return githubRelease{}, errors.New("最近 100 个发行中没有 Nginx 稳定版，请指定 nginx-v 开头的发行标签")
	}
	return selected, nil
}
