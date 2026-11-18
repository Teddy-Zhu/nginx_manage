package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fail2bancontainer"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/frpscontainer"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/software"
)

func builtinImage(data, app string) (string, bool, error) {
	switch app {
	case "frps":
		c, installed, err := frpscontainer.Configuration(data)
		return c.Image, installed, err
	case "fail2ban":
		c, installed, err := fail2bancontainer.Configuration(data)
		return c.Image, installed, err
	default:
		return "", false, errors.New("该组件不支持版本切换")
	}
}

func (s *Server) builtinVersions(_ context.Context, q componentversions.Query) (componentversions.Catalog, error) {
	out := componentversions.Catalog{AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}}
	image, installed, err := builtinImage(s.DataDir, q.AppID)
	if err != nil {
		return out, err
	}
	document, err := componentversions.Builtin()
	if err != nil {
		return out, err
	}
	return s.componentVersions(q, image, installed, document)
}

func (s *Server) componentVersions(q componentversions.Query, image string, installed bool, document componentversions.BuiltinDocument) (componentversions.Catalog, error) {
	out := componentversions.Catalog{AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}, CheckedAt: time.Now().Unix()}
	state, err := componentversions.ReadState(s.DataDir, "builtin", q.AppID)
	if err != nil {
		return out, err
	}
	if installed && state.Image == image {
		out.Current = state.Current
		out.Previous = state.Previous
	}
	var versions []componentversions.Version
	for _, release := range document.Applications[q.AppID] {
		if installed && out.Current == nil && release.Image == image {
			v := release.Version
			out.Current = &v
		}
		if release.Channel != q.Channel {
			continue
		}
		v := release.Version
		v = componentversions.ApplyAvailability(v, s.ProgramVersion)
		versions = append(versions, v)
	}
	// Retain installed versions after a catalog update.
	for _, previous := range []*componentversions.Version{out.Current, out.Previous} {
		if previous == nil || previous.Channel != q.Channel {
			continue
		}
		found := false
		for _, v := range versions {
			if v.ID == previous.ID {
				found = true
				break
			}
		}
		if !found {
			versions = append(versions, *previous)
		}
	}
	componentversions.Sort(versions)
	start := (q.Page - 1) * 20
	if start < len(versions) {
		end := start + 20
		if end > len(versions) {
			end = len(versions)
		}
		out.Versions = versions[start:end]
		out.HasMore = end < len(versions)
	}
	return out, nil
}

func (s *Server) appendBuiltinVersions(out *components.Overview, protectionImage string) {
	document, err := componentversions.Builtin()
	if err != nil {
		out.ComponentError = err.Error()
		return
	}
	record := func(app, image string) {
		q := componentversions.Query{AppID: app, Channel: "stable", Page: 1}
		catalog, err := s.componentVersions(q, image, true, document)
		if err != nil {
			if out.ComponentError == "" {
				out.ComponentError = err.Error()
			}
		} else if catalog.Current != nil {
			out.Versions[app] = *catalog.Current
		}
	}
	if out.Frps != nil && out.Frps.Installed {
		record("frps", out.Frps.Config.Image)
	}
	if out.Fail2ban != nil && out.Fail2ban.Installed {
		record("fail2ban", protectionImage)
	}
}

func (s *Server) manageBuiltinComponent(ctx context.Context, r software.Request, progress software.Progress) (out software.Result, err error) {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return out, fault.Unavailable("当前环境不允许管理组件")
	}
	if r.AppID == "fail2ban" && s.MetricsScope != "host" {
		return out, fault.Unavailable("当前环境不允许管理宿主机登录防护")
	}
	defer func() { out.AppID = r.AppID }()
	if r.Action == "install" || r.Action == "update" {
		return s.manageComponentVersion(ctx, r, progress)
	}
	switch r.AppID {
	case "frps":
		return frpscontainer.Run(ctx, s.DataDir, frps.Request{Action: r.Action}, progress)
	case "fail2ban":
		return fail2bancontainer.Run(ctx, s.DataDir, fail2ban.ContainerRequest{Action: r.Action}, progress)
	default:
		return out, fault.NotFound("内置组件不存在")
	}
}

func (s *Server) manageComponentVersion(ctx context.Context, r software.Request, progress software.Progress) (software.Result, error) {
	var out software.Result
	app, action := r.AppID, r.Action
	image, installed, err := builtinImage(s.DataDir, app)
	if err != nil {
		return out, err
	}
	if action == "update" && !installed {
		return out, fault.Invalid("请先安装软件")
	}
	if action == "install" && installed {
		return out, fault.Conflict("软件已安装，请使用切换版本")
	}
	document, err := componentversions.Builtin()
	if err != nil {
		return out, err
	}
	state, err := componentversions.ReadState(s.DataDir, "builtin", app)
	if err != nil {
		return out, err
	}
	if !installed || state.Image != image {
		state = componentversions.State{}
	}
	if installed && state.Current == nil {
		for _, candidate := range document.Applications[app] {
			if candidate.Image == image {
				v := candidate.Version
				state.Current = &v
				state.Image = image
				break
			}
		}
	}
	var selected *componentversions.BuiltinRelease
	if r.Version == "" {
		tag := r.ImageTag
		if tag == "" {
			tag = componentversions.LatestImageTag
		}
		ref, pullErr := software.PullBuiltinTag(ctx, app, tag, progress)
		if pullErr != nil {
			return out, pullErr
		}
		_, digest, _ := strings.Cut(ref, "@sha256:")
		selected = &componentversions.BuiltinRelease{
			Version: componentversions.Version{ID: "image-" + digest, Version: tag, ImageTag: tag, Channel: "stable"},
			Image:   ref,
		}
	} else {
		for _, candidate := range document.Applications[app] {
			if candidate.ID == r.Version {
				release := candidate
				selected = &release
				break
			}
		}
		if selected == nil && state.Previous != nil && state.Previous.ID == r.Version && state.PreviousImage != "" {
			selected = &componentversions.BuiltinRelease{Version: *state.Previous, Image: state.PreviousImage}
		}
	}
	if selected == nil {
		return out, fault.Invalid("请选择可用的软件版本")
	}
	selected.Version = componentversions.ApplyAvailability(selected.Version, s.ProgramVersion)
	if selected.Unavailable != "" {
		return out, fault.Invalid(selected.Unavailable)
	}
	if state.Current != nil && state.Current.ID == selected.ID && state.Image != selected.Image {
		return out, errors.New("同一版本的镜像摘要已改变")
	}
	if state.Current != nil && state.Current.ImageTag == "" && selected.ImageTag == "" {
		if direction, compareErr := releases.CompareVersions(selected.Version.Version, state.Current.Version); compareErr == nil && direction < 0 {
			progress("正在降级，现有配置或数据可能与目标版本不兼容")
		}
	}
	label := "版本 " + selected.Version.Version
	if selected.ImageTag != "" {
		label = "镜像标签 " + selected.ImageTag
	}
	progress("正在切换到" + label)
	var restore func(context.Context) error
	switch app {
	case "frps":
		old, _, readErr := frpscontainer.Configuration(s.DataDir)
		if readErr != nil {
			return out, readErr
		}
		config := old
		if r.Frps != nil && r.Frps.Config != nil {
			config = *r.Frps.Config
		}
		config.Image = selected.Image
		out, err = frpscontainer.Run(ctx, s.DataDir, frps.Request{Action: action, Config: &config}, progress)
		restore = func(recovery context.Context) error {
			_, e := frpscontainer.Run(recovery, s.DataDir, frps.Request{Action: "update", Config: &old}, progress)
			return e
		}
	case "fail2ban":
		old, _, readErr := fail2bancontainer.Configuration(s.DataDir)
		if readErr != nil {
			return out, readErr
		}
		config := old
		if r.AutoStart != nil {
			config.AutoStart = *r.AutoStart
		}
		config.Image = selected.Image
		out, err = fail2bancontainer.Run(ctx, s.DataDir, fail2ban.ContainerRequest{Action: action, Config: &config}, progress)
		restore = func(recovery context.Context) error {
			current, _, e := fail2bancontainer.Configuration(s.DataDir)
			if e != nil {
				return e
			}
			old.Revision = current.Revision
			_, e = fail2bancontainer.Run(recovery, s.DataDir, fail2ban.ContainerRequest{Action: "update", Config: &old}, progress)
			return e
		}
	default:
		return out, fault.Invalid("该组件不支持版本切换")
	}
	if err != nil {
		return out, err
	}
	next := componentversions.State{Current: &selected.Version, Image: selected.Image, UpdatedAt: time.Now().Unix()}
	if installed && state.Current != nil && state.Current.ID != selected.ID {
		next.Previous = state.Current
		next.PreviousImage = image
	} else {
		next.Previous = state.Previous
		next.PreviousImage = state.PreviousImage
	}
	if err = componentversions.SaveState(s.DataDir, "builtin", app, next); err != nil {
		if installed && restore != nil {
			recovery, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if restoreErr := restore(recovery); restoreErr != nil {
				return out, fmt.Errorf("记录安装版本失败：%w；恢复原版本失败：%v", err, restoreErr)
			}
			return out, fmt.Errorf("记录安装版本失败，已恢复原版本：%w", err)
		}
		return out, fmt.Errorf("软件已安装，但记录版本失败：%w", err)
	}
	out.Version = &selected.Version
	out.Message = "已切换到" + label
	return out, nil
}
