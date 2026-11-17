package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

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

func (s *Server) builtinVersions(ctx context.Context, q componentversions.Query) (componentversions.Catalog, error) {
	out := componentversions.Catalog{SourceID: "builtin", AppID: q.AppID, Channel: q.Channel, Page: q.Page, Versions: []componentversions.Version{}}
	image, installed, err := builtinImage(s.DataDir, q.AppID)
	if err != nil {
		return out, err
	}
	document, cached, loadErr := componentversions.Builtin(ctx, s.DataDir, q.Refresh)
	out.Cached = cached
	if loadErr != nil {
		out.Error = loadErr.Error()
	}
	if !cached {
		out.CheckedAt = time.Now().Unix()
	}
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
	// Retain a formerly installed version even after it leaves the remote list.
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

func (s *Server) manageComponentVersion(ctx context.Context, r software.Request, progress software.Progress) (software.Result, error) {
	var out software.Result
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return out, fault.Unavailable("当前环境不允许管理组件")
	}
	app, action := r.AppID, r.Action
	if r.Frps != nil {
		app = "frps"
		action = r.Frps.Action
	}
	if r.Fail2ban != nil {
		app = "fail2ban"
		action = r.Fail2ban.Action
	}
	if action != "install" && action != "update" {
		return out, fault.Invalid("该操作不支持选择版本")
	}
	image, installed, err := builtinImage(s.DataDir, app)
	if err != nil {
		return out, err
	}
	if action == "update" && !installed {
		return out, fault.Invalid("请先安装软件")
	}
	document, _, err := componentversions.Builtin(ctx, s.DataDir, false)
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
	if selected == nil {
		return out, fault.Invalid("请选择可用的软件版本")
	}
	selected.Version = componentversions.ApplyAvailability(selected.Version, s.ProgramVersion)
	if selected.Unavailable != "" {
		return out, fault.Invalid(selected.Unavailable)
	}
	if state.Current != nil && state.Current.ID == selected.ID && state.Image != selected.Image {
		return out, errors.New("同一版本的镜像身份已改变，请检查软件源")
	}
	if state.Current != nil {
		if direction, compareErr := releases.CompareVersions(selected.Version.Version, state.Current.Version); compareErr == nil && direction < 0 {
			progress("正在降级，现有配置或数据可能与目标版本不兼容")
		}
	}
	progress("正在切换到组件版本 " + selected.Version.Version)
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
		if !installed {
			action = "install"
		}
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
		if r.Fail2ban != nil && r.Fail2ban.Config != nil {
			config = *r.Fail2ban.Config
		}
		config.Image = selected.Image
		if !installed {
			action = "install"
		}
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
	out.Message = "已切换到版本 " + selected.Version.Version
	return out, nil
}
