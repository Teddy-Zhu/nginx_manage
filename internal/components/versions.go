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

func (m *Manager) Versions(ctx context.Context, q componentversions.Query) (catalog componentversions.Catalog, resultErr error) {
	if err := q.Validate(); err != nil {
		return componentversions.Catalog{}, err
	}
	if q.AppID == "fail2ban" || q.AppID == "frps" {
		if m.BuiltinVersions == nil {
			return componentversions.Catalog{}, errors.New("内置组件版本服务不可用")
		}
		return m.BuiltinVersions(ctx, q)
	}
	if q.AppID != "nginx" {
		return componentversions.Catalog{}, fault.NotFound("系统组件不存在")
	}
	out := componentversions.Catalog{AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}}
	var bundled *componentversions.Version
	if m.BundledNginxVersion != nil {
		var err error
		bundled, err = m.BundledNginxVersion()
		if err != nil {
			return out, err
		}
		if bundled != nil && q.Channel == "stable" && q.Page == 1 {
			// Bundled metadata belongs to this installation, not the registry cache.
			defer func() {
				if resultErr == nil {
					catalog.Versions = append([]componentversions.Version{*bundled}, catalog.Versions...)
				}
			}()
		}
	}
	// A first-install binding can exist before the container actually starts.
	if bundled == nil {
		if binding, err := nginxcontainer.Read(m.DataDir); err == nil {
			out.Current = NginxVersion(binding)
		} else if !os.IsNotExist(err) {
			return out, err
		}
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
