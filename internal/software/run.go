package software

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"nginxpanel/internal/secure"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"
)

type Progress func(string)

func Run(ctx context.Context, data string, r Request, progress Progress) (Result, error) {
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
	case "install", "update", "uninstall":
		out, err = application(ctx, data, c, r, progress)
	default:
		err = errors.New("软件操作不受支持")
	}
	return out, err
}

type limitedLog struct {
	bytes.Buffer
	progress Progress
	last     time.Time
}

func (b *limitedLog) Write(p []byte) (int, error) {
	n := len(p)
	_, _ = b.Buffer.Write(p)
	if b.progress != nil && time.Since(b.last) >= time.Second {
		b.last = time.Now()
		lines := strings.FieldsFunc(strings.ToValidUTF8(string(p), ""), func(r rune) bool { return r == '\n' || r == '\r' })
		if len(lines) > 0 {
			last := lines[len(lines)-1]
			if len(last) > 500 {
				last = last[:500]
			}
			b.progress(last)
		}
	}
	if b.Len() > 16000 {
		tail := append([]byte(nil), b.Bytes()[b.Len()-16000:]...)
		b.Reset()
		_, _ = b.Buffer.Write(tail)
	}
	return n, nil
}
func docker(ctx context.Context, progress Progress, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "/usr/bin/docker", args...)
	log := limitedLog{progress: progress}
	command.Stdout = &log
	command.Stderr = &log
	err := command.Run()
	text := strings.TrimSpace(log.String())
	if err != nil {
		if text == "" {
			return text, fmt.Errorf("无法执行 Docker 操作：%w", err)
		}
		return text, fmt.Errorf("Docker 操作失败：%s", text)
	}
	return text, nil
}
func application(ctx context.Context, data string, c Catalog, r Request, progress Progress) (Result, error) {
	out := Result{SourceID: r.SourceID, AppID: r.AppID}
	index := slices.IndexFunc(c.Installed, func(i Installation) bool { return i.SourceID == r.SourceID && i.Application.ID == r.AppID })
	name := "nginxpanel-app-" + r.SourceID + "-" + r.AppID
	exists, err := containerExists(ctx, name)
	if err != nil {
		return out, err
	}
	if exists {
		if err = ownedContainer(ctx, name, r.SourceID, r.AppID); err != nil {
			return out, err
		}
	}
	if r.Action == "uninstall" {
		if index < 0 {
			return out, errors.New("软件尚未安装")
		}
		if exists {
			if _, err = docker(ctx, progress, "rm", "-f", name); err != nil {
				return out, err
			}
		}
		c.Installed = append(c.Installed[:index], c.Installed[index+1:]...)
		out.Message = "软件已卸载，数据卷已保留"
		return out, save(data, c)
	}
	var app *Application
	for _, s := range c.Sources {
		if s.ID == r.SourceID {
			for _, a := range s.Applications {
				if a.ID == r.AppID {
					copy := a
					app = &copy
					break
				}
			}
		}
	}
	if app == nil {
		return out, errors.New("软件源中未找到此软件")
	}
	if r.Action == "install" && index >= 0 {
		return out, errors.New("软件已经安装，请使用更新操作")
	}
	if r.Action == "update" && index < 0 {
		return out, errors.New("软件尚未安装")
	}
	raw, _ := json.Marshal(app)
	configHash := secure.Hash(raw)
	if index < 0 && exists {
		fingerprint, err := docker(ctx, nil, "inspect", "--format", `{{index .Config.Labels "org.nginxpanel.config"}}`, name)
		if err != nil {
			return out, err
		}
		if fingerprint != configHash {
			return out, errors.New("发现本软件的未完成安装，配置与当前软件源不同，请恢复原软件源后重试")
		}
		state, err := docker(ctx, nil, "inspect", "--format", "{{.State.Running}}", name)
		if err != nil {
			return out, err
		}
		if state != "true" {
			if _, err = docker(ctx, progress, "start", name); err != nil {
				return out, err
			}
		}
		imageID, err := docker(ctx, nil, "inspect", "--format", "{{.Image}}", name)
		if err != nil {
			return out, err
		}
		c.Installed = append(c.Installed, Installation{SourceID: r.SourceID, Application: *app, Container: name, ImageID: imageID, UpdatedAt: time.Now().Unix()})
		out.Message = "软件安装已恢复"
		return out, save(data, c)
	}
	// Check catalog capacity before changing any running container.
	pending := Installation{SourceID: r.SourceID, Application: *app, Container: name, ImageID: "sha256:" + strings.Repeat("0", 64), UpdatedAt: time.Now().Unix()}
	next := c
	next.Installed = slices.Clone(c.Installed)
	if index < 0 {
		next.Installed = append(next.Installed, pending)
	} else {
		next.Installed[index] = pending
	}
	snapshot, _ := json.Marshal(next)
	if len(snapshot) > maxCatalog {
		return out, errors.New("软件配置存储空间已满，请移除不再使用的软件源")
	}
	progress("正在拉取软件镜像")
	pull, err := docker(ctx, progress, "pull", app.Image)
	out.Log = pull
	if err != nil {
		return out, err
	}
	backup := name + "-previous"
	backedUp := false
	if index >= 0 && !exists {
		found, err := containerExists(ctx, backup)
		if err != nil {
			return out, err
		}
		if found {
			if err = ownedContainer(ctx, backup, r.SourceID, r.AppID); err != nil {
				return out, err
			}
			backedUp = true
		}
	}
	if index >= 0 && exists {
		leftover, err := containerExists(ctx, backup)
		if err != nil {
			return out, err
		}
		if leftover {
			if err = ownedContainer(ctx, backup, r.SourceID, r.AppID); err != nil {
				return out, err
			}
			running, err := docker(ctx, nil, "inspect", "--format", "{{.State.Running}}", backup)
			if err != nil {
				return out, err
			}
			if running == "true" {
				return out, errors.New("上次更新保留的容器仍在运行，请查看软件日志")
			}
			if _, err = docker(ctx, nil, "rm", backup); err != nil {
				return out, err
			}
		}
		if _, err = docker(ctx, nil, "stop", "--time", "20", name); err != nil {
			return out, err
		}
		if _, err = docker(ctx, nil, "rename", name, backup); err != nil {
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if _, startErr := docker(recovery, nil, "start", name); startErr != nil {
				return out, fmt.Errorf("%w；恢复启动失败：%v", err, startErr)
			}
			return out, err
		}
		backedUp = true
	}
	args := []string{"run", "--detach", "--name", name, "--restart", "unless-stopped", "--label", "org.nginxpanel.source=" + r.SourceID, "--label", "org.nginxpanel.application=" + r.AppID, "--label", "org.nginxpanel.config=" + configHash}
	for _, p := range app.Ports {
		args = append(args, "--publish", fmt.Sprintf("%d:%d/%s", p.Host, p.Container, p.Protocol))
	}
	for _, v := range app.Volumes {
		args = append(args, "--mount", "type=volume,src="+name+"-"+v.Name+",dst="+v.Target)
	}
	env := make([]string, 0, len(app.Environment))
	for key := range app.Environment {
		env = append(env, key)
	}
	sort.Strings(env)
	for _, key := range env {
		args = append(args, "--env", key+"="+app.Environment[key])
	}
	args = append(args, app.Image)
	restore := func(cause error) error {
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		found, err := containerExists(recovery, name)
		if err != nil {
			return fmt.Errorf("%w；无法核对容器状态：%v", cause, err)
		}
		if found {
			if err = ownedContainer(recovery, name, r.SourceID, r.AppID); err != nil {
				return fmt.Errorf("%w；%v", cause, err)
			}
			if _, err = docker(recovery, nil, "rm", "-f", name); err != nil {
				return fmt.Errorf("%w；清理失败容器失败：%v", cause, err)
			}
		}
		if backedUp {
			if _, err = docker(recovery, nil, "rename", backup, name); err != nil {
				return fmt.Errorf("%w；原容器保留为 %s，恢复名称失败：%v", cause, backup, err)
			}
			if _, err = docker(recovery, nil, "start", name); err != nil {
				return fmt.Errorf("%w；原容器恢复启动失败：%v", cause, err)
			}
		}
		return cause
	}
	progress("正在启动软件")
	_, err = docker(ctx, nil, args...)
	if err == nil {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
		}
		if err == nil {
			state, readErr := docker(ctx, nil, "inspect", "--format", "{{.State.Running}}", name)
			if readErr != nil {
				err = readErr
			} else if state != "true" {
				logs, logErr := docker(ctx, nil, "logs", "--tail", "100", name)
				if logErr != nil {
					return out, restore(fmt.Errorf("软件启动后退出，读取日志失败：%w", logErr))
				}
				out.Log = truncateLog(out.Log + "\n" + logs)
				err = errors.New("软件启动后退出，请查看安装日志")
			}
		}
	}
	if err != nil {
		return out, restore(err)
	}
	imageID, err := docker(ctx, nil, "inspect", "--format", "{{.Image}}", name)
	if err != nil {
		return out, restore(err)
	}
	pending.ImageID = imageID
	pending.UpdatedAt = time.Now().Unix()
	if index < 0 {
		c.Installed = append(c.Installed, pending)
	} else {
		c.Installed[index] = pending
	}
	if err = save(data, c); err != nil {
		return out, restore(err)
	}
	if backedUp {
		if _, err = docker(ctx, nil, "rm", backup); err != nil {
			return out, fmt.Errorf("软件已更新，清理旧容器失败：%w", err)
		}
	}
	out.Message = "软件已启动"
	return out, nil
}
func truncateLog(s string) string {
	if len(s) > 16000 {
		return strings.ToValidUTF8(s[len(s)-16000:], "")
	}
	return s
}
func containerExists(ctx context.Context, name string) (bool, error) {
	raw, err := docker(ctx, nil, "container", "ls", "--all", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	return raw != "", err
}
func ownedContainer(ctx context.Context, name, source, app string) error {
	raw, err := docker(ctx, nil, "inspect", "--format", "{{json .Config.Labels}}", name)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if json.Unmarshal([]byte(raw), &labels) != nil || labels["org.nginxpanel.source"] != source || labels["org.nginxpanel.application"] != app {
		return errors.New("同名容器不属于此软件源，未修改")
	}
	return nil
}

func Docker(ctx context.Context, progress Progress, args ...string) (string, error) {
	return docker(ctx, progress, args...)
}
