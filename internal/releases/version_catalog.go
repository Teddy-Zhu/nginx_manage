package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type VersionSummary struct {
	Tag         string
	Version     string
	Channel     string
	PublishedAt int64
	Notes       string
}

// ImageVersions lists published component releases without treating editable
// GitHub metadata as authority to install. Selection still requires Online's
// signature, source, platform and immutable image validation.
func ImageVersions(ctx context.Context, trustPath, tokenPath string, page int) ([]VersionSummary, bool, error) {
	if page < 1 || page > 1000 {
		return nil, false, errors.New("版本页码无效")
	}
	publisher, err := readTrust(trustPath)
	if err != nil {
		return nil, false, err
	}
	token, _, err := readGithubToken(tokenPath)
	if err != nil {
		return nil, false, err
	}
	client, transport := githubHTTP()
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=100&page=%d", publisher.trust.Repository, page), nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "nginxpanel-component-versions")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, false, errors.New("无法读取 Nginx 发行列表，请检查网络")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("Nginx 发行列表返回 HTTP %d", response.StatusCode)
	}
	var entries []struct {
		Tag         string    `json:"tag_name"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Body        string    `json:"body"`
		Assets      []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxManifestBytes+1))
	if err != nil || len(raw) > MaxManifestBytes {
		return nil, false, errors.New("Nginx 发行列表超过大小限制或读取中断")
	}
	if err = json.Unmarshal(raw, &entries); err != nil || len(entries) > 100 {
		return nil, false, errors.New("Nginx 发行列表无效")
	}
	out := []VersionSummary{}
	for _, entry := range entries {
		version, ok := strings.CutPrefix(entry.Tag, "nginx-v")
		if !ok || entry.Draft || entry.PublishedAt.IsZero() || !validVersion(version) || entry.Prerelease != (VersionChannel(version) == "beta") {
			continue
		}
		manifest, signature := false, false
		for _, asset := range entry.Assets {
			manifest = manifest || asset.Name == "release-manifest.json"
			signature = signature || asset.Name == "release-manifest.sig"
		}
		if !manifest || !signature {
			continue
		}
		notes := []rune(entry.Body)
		if len(notes) > 2000 {
			notes = notes[:2000]
		}
		out = append(out, VersionSummary{Tag: entry.Tag, Version: version, Channel: VersionChannel(version), PublishedAt: entry.PublishedAt.Unix(), Notes: string(notes)})
	}
	return out, len(entries) == 100, nil
}
