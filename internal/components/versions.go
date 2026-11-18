package components

import (
	"context"
	"errors"
	"os"
	"time"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/software"
)

func (s *Service) Versions(ctx context.Context, q componentversions.Query) (componentversions.Catalog, error) {
	if err := q.Validate(); err != nil {
		return componentversions.Catalog{}, fault.Invalid(err.Error())
	}
	host, ok := s.Agent.(interface {
		ComponentVersions(context.Context, componentversions.Query) (componentversions.Catalog, error)
	})
	if !ok {
		return componentversions.Catalog{}, fault.Unavailable("组件版本服务不可用")
	}
	return host.ComponentVersions(ctx, q)
}

func NginxVersion(binding nginxcontainer.Binding) *componentversions.Version {
	// For a bundled image the approval's version identifies the core installer.
	if binding.SignedImage.LocalBuild {
		return nil
	}
	version := binding.SignedImage.Version
	channel := releases.VersionChannel(version)
	if channel == "" {
		return nil
	}
	return &componentversions.Version{
		ID: "nginx-v" + version, Version: version, Channel: channel,
		SoftwareVersion: binding.Capabilities.Version,
	}
}

func (m *Manager) Versions(ctx context.Context, q componentversions.Query) (componentversions.Catalog, error) {
	if err := q.Validate(); err != nil {
		return componentversions.Catalog{}, err
	}
	if q.SourceID != "builtin" {
		return software.Versions(ctx, m.DataDir, m.Version, q)
	}
	if q.AppID != "nginx" {
		if m.BuiltinVersions == nil {
			return componentversions.Catalog{}, errors.New("内置组件版本服务不可用")
		}
		return m.BuiltinVersions(ctx, q)
	}
	out := componentversions.Catalog{SourceID: q.SourceID, AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}}
	if binding, err := nginxcontainer.Read(m.DataDir); err == nil {
		out.Current = NginxVersion(binding)
	} else if !os.IsNotExist(err) {
		return out, err
	}
	state, stateErr := componentversions.ReadState(m.DataDir, "builtin", "nginx")
	if stateErr != nil {
		return out, stateErr
	}
	if state.Current != nil && out.Current != nil && state.Current.ID == out.Current.ID {
		out.Previous = state.Previous
	}
	cached, cacheErr := componentversions.ReadCatalog(m.DataDir, q)
	if cacheErr == nil && !q.Refresh && cached.CheckedAt > time.Now().Unix()-600 {
		cached.Current, cached.Previous, cached.Cached = out.Current, out.Previous, true
		return cached, nil
	}
	entries, more, err := releases.ImageVersions(ctx, m.TrustPath, m.TokenPath, q.Page)
	if err != nil {
		if cacheErr == nil {
			cached.Current, cached.Previous, cached.Cached, cached.Error = out.Current, out.Previous, true, err.Error()
			return cached, nil
		}
		out.Error = err.Error()
		return out, nil
	}
	out.CheckedAt, out.HasMore = time.Now().Unix(), more
	for _, entry := range entries {
		if entry.Channel == q.Channel {
			out.Versions = append(out.Versions, componentversions.Version{ID: entry.Tag, Version: entry.Version, SoftwareVersion: entry.SoftwareVersion, Channel: entry.Channel, PublishedAt: entry.PublishedAt, Notes: entry.Notes})
		}
	}
	componentversions.Sort(out.Versions)
	if err = componentversions.SaveCatalog(m.DataDir, q, out); err != nil {
		return out, err
	}
	return out, nil
}
