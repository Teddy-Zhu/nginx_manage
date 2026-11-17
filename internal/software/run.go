package software

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/releases"
)

type Progress func(string)

func Run(ctx context.Context, data string, r Request, progress Progress) (Result, error) {
	return RunWithCore(ctx, data, "", r, progress)
}
func RunWithCore(ctx context.Context, data, core string, r Request, progress Progress) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	out := Result{SourceID: r.SourceID, AppID: r.AppID}
	if err := r.Validate(); err != nil {
		return out, err
	}
	c, err := Read(data)
	if err != nil {
		return out, err
	}
	sourceIndex := slices.IndexFunc(c.Sources, func(s Source) bool { return s.ID == r.SourceID })
	switch r.Action {
	case "import", "refresh":
		var source Source
		if r.Action == "refresh" {
			if sourceIndex < 0 || c.Sources[sourceIndex].URL == "" {
				return out, errors.New("此软件源没有远程更新地址")
			}
			r.URL = c.Sources[sourceIndex].URL
		}
		if r.Source != nil {
			source = *r.Source
		} else {
			progress("正在读取软件源")
			source, err = fetch(ctx, r.URL)
			if err != nil {
				return out, err
			}
		}
		sourceIndex = slices.IndexFunc(c.Sources, func(s Source) bool { return s.ID == source.ID })
		if r.Action == "refresh" && source.ID != r.SourceID {
			return out, errors.New("远程软件源标识发生变化")
		}
		if sourceIndex >= 0 && r.Action == "import" {
			return out, errors.New("软件源已存在，请更新列表或先删除旧软件源")
		}
		if sourceIndex < 0 {
			if len(c.Sources) >= 32 {
				return out, errors.New("软件源数量已达上限")
			}
			c.Sources = append(c.Sources, source)
		} else {
			c.Sources[sourceIndex] = source
		}
		out.SourceID = source.ID
		out.Message = "软件源已保存"
		err = save(data, c)
	case "delete":
		if sourceIndex < 0 {
			return out, errors.New("软件源不存在")
		}
		if slices.ContainsFunc(c.Installed, func(i Installation) bool { return i.SourceID == r.SourceID }) {
			return out, errors.New("请先卸载该软件源下已安装的软件")
		}
		c.Sources = append(c.Sources[:sourceIndex], c.Sources[sourceIndex+1:]...)
		out.Message = "软件源已删除"
		err = save(data, c)
	case "install", "update", "uninstall", "start", "stop", "restart", "logs":
		out, err = application(ctx, data, core, c, r, progress)
	default:
		err = errors.New("软件操作不受支持")
	}
	return out, err
}

func application(ctx context.Context, data, core string, c Catalog, r Request, progress Progress) (Result, error) {
	out := Result{SourceID: r.SourceID, AppID: r.AppID}
	index := slices.IndexFunc(c.Installed, func(item Installation) bool { return item.SourceID == r.SourceID && item.Application.ID == r.AppID })
	var app *Application
	if index >= 0 {
		copy := c.Installed[index].Application
		app = &copy
	}
	if r.Action == "install" || r.Action == "update" {
		if r.Action == "install" && index >= 0 {
			return out, errors.New("软件已经安装")
		}
		if r.Action == "update" && index < 0 {
			return out, errors.New("软件尚未安装")
		}
		app = nil
		for _, source := range c.Sources {
			if source.ID == r.SourceID {
				for _, candidate := range source.Applications {
					if candidate.ID == r.AppID {
						copy := candidate
						app = &copy
						break
					}
				}
			}
		}
	}
	if app == nil {
		return out, errors.New("软件不存在或尚未安装")
	}
	if _, ok := app.Actions[r.Action]; !ok {
		return out, errors.New("软件未提供此操作")
	}
	var selected *componentversions.Version
	var err error
	var previous *Installation
	if index >= 0 {
		copy := c.Installed[index]
		previous = &copy
	}
	if r.Action == "install" || r.Action == "update" {
		selected, err = resolveVersion(ctx, data, r.SourceID, *app, previous, r.Version)
		if err != nil {
			return out, err
		}
		if selected != nil {
			v := componentversions.ApplyAvailability(*selected, core)
			selected = &v
			if v.Unavailable != "" {
				return out, errors.New(v.Unavailable)
			}
		}
	}
	next := c
	next.Installed = slices.Clone(c.Installed)
	if r.Action == "install" || r.Action == "update" {
		item := Installation{SourceID: r.SourceID, Application: *app, UpdatedAt: time.Now().Unix(), Version: selected}
		if previous != nil {
			item.Previous = previous.Version
		}
		if index < 0 {
			next.Installed = append(next.Installed, item)
		} else {
			next.Installed[index] = item
		}
		raw, err := json.Marshal(next)
		if err != nil {
			return out, err
		}
		if len(raw) > maxCatalog {
			return out, errors.New("软件配置存储空间已满，请移除不再使用的软件源")
		}
	}
	labels := map[string]string{"install": "安装", "update": "更新", "uninstall": "卸载", "start": "启动", "stop": "停止", "restart": "重启", "logs": "读取服务日志"}
	progress("正在" + labels[r.Action] + "软件")
	oldVersion, target := "", ""
	var oldMetadata *componentversions.Version
	if previous != nil && previous.Version != nil {
		oldVersion = previous.Version.Version
	}
	if previous != nil {
		oldMetadata = previous.Version
	}
	if selected != nil {
		target = selected.Version
	}
	if oldVersion != "" && target != "" {
		if direction, compareErr := releases.CompareVersions(target, oldVersion); compareErr == nil && direction < 0 {
			progress("正在降级，现有配置或数据可能与目标版本不兼容")
		}
	}
	if selected != nil {
		if _, ok := app.Actions["check-version"]; ok {
			if out.Log, err = versionCommand(ctx, data, r.SourceID, *app, "check-version", selected, oldMetadata, progress); err != nil {
				return out, err
			}
		}
		if previous != nil {
			if _, ok := app.Actions["backup"]; ok {
				if out.Log, err = versionCommand(ctx, data, r.SourceID, *app, "backup", selected, oldMetadata, progress); err != nil {
					return out, err
				}
			}
		}
	}
	text, err := versionCommand(ctx, data, r.SourceID, *app, r.Action, selected, oldMetadata, progress)
	out.Log += "\n" + text
	if err == nil && selected != nil {
		err = waitVersion(ctx, data, r.SourceID, *app, selected.Version)
	}
	catalogWriteAttempted := false
	restore := func(cause error) (Result, error) {
		if selected != nil && previous != nil && previous.Version != nil {
			progress("正在尝试恢复原版本")
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
			defer cancel()
			action := "update"
			if _, ok := previous.Application.Actions["restore"]; ok {
				action = "restore"
			}
			log, restoreErr := versionCommand(recovery, data, r.SourceID, previous.Application, action, previous.Version, selected, progress)
			out.Log += "\n" + log
			if restoreErr == nil {
				restoreErr = waitVersion(recovery, data, r.SourceID, previous.Application, previous.Version.Version)
			}
			if restoreErr != nil {
				return out, fmt.Errorf("%w；恢复原版本失败：%v", cause, restoreErr)
			}
			if catalogWriteAttempted {
				if restoreErr = save(data, c); restoreErr != nil {
					return out, fmt.Errorf("%w；原服务已恢复，但恢复安装记录失败：%v", cause, restoreErr)
				}
			}
			return out, fmt.Errorf("%w；已恢复原版本", cause)
		}
		return out, cause
	}
	if err != nil {
		return restore(err)
	}
	if r.Action == "uninstall" {
		next.Installed = append(next.Installed[:index], next.Installed[index+1:]...)
	}
	if r.Action == "install" || r.Action == "update" || r.Action == "uninstall" {
		catalogWriteAttempted = true
		if err = save(data, next); err != nil {
			return restore(fmt.Errorf("写入软件安装记录失败：%w", err))
		}
	}
	out.Message = labels[r.Action] + "已完成"
	out.Version = selected
	return out, nil
}

func waitVersion(ctx context.Context, data, source string, app Application, target string) error {
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		raw, err := operationCommand(call, data, source, app, "status", nil)
		cancel()
		var state runtimeObservation
		if err == nil {
			state, err = decodeObservation(raw)
		}
		if err != nil {
			return fmt.Errorf("无法验证软件状态：%w", err)
		}
		if state.Version != target {
			return errors.New("软件状态没有报告所选版本，安装结果未确认")
		}
		if state.State == "running" || state.State == "stopped" {
			return nil
		}
		if state.State != "starting" {
			return errors.New("软件未正常启动：" + state.State + " " + state.Message)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("软件启动检查超时")
		case <-time.After(time.Second):
		}
	}
}
