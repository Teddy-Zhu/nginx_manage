package software

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/secure"
)

type versionDocument struct {
	Schema   int                         `json:"schema"`
	Versions []componentversions.Version `json:"versions"`
}
type versionSnapshot struct {
	URL       string                      `json:"url"`
	CheckedAt int64                       `json:"checked_at"`
	Versions  []componentversions.Version `json:"versions"`
}

func validateVersions(versions []componentversions.Version) error {
	if len(versions) > 1000 {
		return errors.New("软件版本数量超过限制")
	}
	seen := map[string]bool{}
	for _, version := range versions {
		if err := version.Validate(); err != nil {
			return err
		}
		if seen[version.ID] {
			return errors.New("软件版本标识重复")
		}
		seen[version.ID] = true
	}
	return nil
}

func FindApplication(c Catalog, sourceID, appID string) (Application, *Installation, error) {
	var installed *Installation
	for _, item := range c.Installed {
		if item.SourceID == sourceID && item.Application.ID == appID {
			copy := item
			installed = &copy
			break
		}
	}
	for _, source := range c.Sources {
		if source.ID == sourceID {
			for _, app := range source.Applications {
				if app.ID == appID {
					return app, installed, nil
				}
			}
		}
	}
	if installed != nil {
		return installed.Application, installed, nil
	}
	return Application{}, nil, errors.New("软件不存在")
}

func applicationVersions(ctx context.Context, data, source string, app Application, refresh bool) (versionSnapshot, bool, error) {
	now := time.Now().Unix()
	if app.VersionsURL == "" {
		if len(app.Versions) == 0 {
			return versionSnapshot{}, false, errors.New("软件源尚未提供版本列表")
		}
		return versionSnapshot{Versions: slices.Clone(app.Versions), CheckedAt: now}, false, nil
	}
	dir, err := componentversions.Directory(data, source, app.ID)
	if err != nil {
		return versionSnapshot{}, false, err
	}
	name := filepath.Join(dir, "source-versions.json")
	var cached versionSnapshot
	raw, err := secure.ReadRootFile(name, 1<<20)
	if err == nil {
		if err = json.Unmarshal(raw, &cached); err != nil {
			return cached, false, errors.New("软件版本缓存损坏")
		}
		if err = validateVersions(cached.Versions); err != nil {
			return cached, false, err
		}
		if cached.URL != app.VersionsURL {
			cached = versionSnapshot{}
		}
	} else if !os.IsNotExist(err) {
		return cached, false, err
	}
	if !refresh && cached.CheckedAt > now-600 {
		return cached, true, nil
	}
	versions, fetchErr := fetchVersions(ctx, app.VersionsURL)
	if fetchErr != nil {
		return cached, cached.CheckedAt != 0, fetchErr
	}
	next := versionSnapshot{URL: app.VersionsURL, CheckedAt: now, Versions: versions}
	if err = componentversions.WriteFile(name, next); err != nil {
		return next, false, err
	}
	return next, false, nil
}

func fetchVersions(ctx context.Context, rawURL string) ([]componentversions.Version, error) {
	u, err := sourceURL(rawURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("版本目录重定向过多")
		}
		_, err := sourceURL(r.URL.String())
		return err
	}}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(r)
	if err != nil {
		return nil, errors.New("无法读取软件版本目录：" + err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("软件版本目录返回 " + response.Status)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, (512<<10)+1))
	decoder.DisallowUnknownFields()
	var document versionDocument
	if err = decoder.Decode(&document); err != nil {
		return nil, errors.New("软件版本目录格式无效")
	}
	if decoder.Decode(new(any)) != io.EOF || document.Schema != 1 {
		return nil, errors.New("软件版本目录格式无效")
	}
	return document.Versions, validateVersions(document.Versions)
}

func Versions(ctx context.Context, data, core string, q componentversions.Query) (componentversions.Catalog, error) {
	out := componentversions.Catalog{SourceID: q.SourceID, AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}}
	if err := q.Validate(); err != nil {
		return out, err
	}
	catalog, err := Read(data)
	if err != nil {
		return out, err
	}
	app, installed, err := FindApplication(catalog, q.SourceID, q.AppID)
	if err != nil {
		return out, err
	}
	if installed != nil {
		out.Current, out.Previous = installed.Version, installed.Previous
	}
	snapshot, cached, err := applicationVersions(ctx, data, q.SourceID, app, q.Refresh)
	out.CheckedAt, out.Cached = snapshot.CheckedAt, cached
	if err != nil {
		out.Error = err.Error()
	}
	for _, version := range snapshot.Versions {
		if version.Channel == q.Channel {
			out.Versions = append(out.Versions, componentversions.ApplyAvailability(version, core))
		}
	}
	for _, history := range []*componentversions.Version{out.Current, out.Previous} {
		if history == nil || history.Channel != q.Channel {
			continue
		}
		found := false
		for _, v := range out.Versions {
			if v.ID == history.ID {
				found = true
				break
			}
		}
		if !found {
			out.Versions = append(out.Versions, componentversions.ApplyAvailability(*history, core))
		}
	}
	componentversions.Sort(out.Versions)
	start := min((q.Page-1)*20, len(out.Versions))
	end := min(start+20, len(out.Versions))
	out.HasMore, out.Versions = end < len(out.Versions), out.Versions[start:end]
	return out, nil
}

func resolveVersion(ctx context.Context, data, source string, app Application, installed *Installation, id string) (*componentversions.Version, error) {
	if id == "" {
		if len(app.Versions) > 0 || app.VersionsURL != "" || installed != nil && installed.Version != nil {
			return nil, errors.New("请选择需要安装的软件版本")
		}
		return nil, nil
	}
	snapshot, _, err := applicationVersions(ctx, data, source, app, false)
	for _, version := range snapshot.Versions {
		if version.ID == id {
			if version.Unavailable != "" {
				return nil, errors.New(version.Unavailable)
			}
			return &version, nil
		}
	}
	if installed != nil {
		for _, version := range []*componentversions.Version{installed.Previous, installed.Version} {
			if version != nil && version.ID == id {
				return version, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("所选版本已不在软件源中，请刷新版本列表")
}
