package frpscontainer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"path/filepath"
	"time"
)

func Run(ctx context.Context, data string, request frps.Request, progress func(string)) (out software.Result, err error) {
	if err = request.Validate(); err != nil {
		return out, err
	}
	if progress == nil {
		progress = func(string) {}
	}
	original, err := read(data)
	if err != nil {
		return out, err
	}
	next := original
	current, err := inspect(ctx, data, Name)
	if err != nil {
		return out, err
	}
	if request.Action != "install" && !original.Installed && current == nil {
		return out, errors.New("请先安装 FRP 服务端")
	}
	command := func(arguments ...string) error {
		var text string
		text, err := software.Docker(ctx, progress, arguments...)
		out.Log = addLog(out.Log, text)
		return err
	}
	if request.Config != nil {
		if request.Action == "configure" && request.Config.Image != original.Config.Image {
			return out, errors.New("请通过版本管理切换软件版本")
		}
		next.Config = *request.Config
		if next.Config.Token == "" {
			next.Config.Token = original.Config.Token
		}
	}
	if !software.ValidImage(next.Config.Image) {
		return out, errors.New("FRP 下载来源无效")
	}
	switch request.Action {
	case "logs":
		if current == nil {
			return out, errors.New("FRP 服务不存在")
		}
		err = command("logs", "--tail", "100", Name)
		if err == nil {
			out.Message = "服务日志已读取"
		}
		return out, err
	case "uninstall":
		if current != nil {
			progress("正在停止并卸载 FRP 服务端")
			if err = command("rm", "--force", Name); err != nil {
				return out, err
			}
		}
		if backup, e := inspect(ctx, data, Name+"-previous"); e != nil {
			return out, e
		} else if backup != nil {
			if err = command("rm", "--force", Name+"-previous"); err != nil {
				return out, err
			}
		}
		next.Installed = false
		if err = save(data, next); err != nil {
			return out, err
		}
		out.Message = "FRP 已卸载，配置已保留"
		return out, nil
	case "start", "stop", "restart":
		if current == nil {
			return out, errors.New("FRP 服务不存在，请更新软件以恢复安装")
		}
		progress(map[string]string{"start": "正在启动 FRP 服务端", "stop": "正在停止 FRP 服务端", "restart": "正在重启 FRP 服务端"}[request.Action])
		if err = command(request.Action, Name); err != nil {
			return out, err
		}
		if request.Action != "stop" {
			if err = waitReady(ctx, data, next); err != nil {
				logs, _ := software.Docker(ctx, nil, "logs", "--tail", "80", Name)
				out.Log = addLog(out.Log, logs)
				return out, err
			}
		}
		out.Message = map[string]string{"start": "FRP 已启动", "stop": "FRP 已停止", "restart": "FRP 已重启"}[request.Action]
		return out, nil
	case "install", "configure", "update":
		if request.Action == "install" && (original.Installed || current != nil) {
			return out, errors.New("FRP 已安装，请使用服务设置或更新操作")
		}
	default:
		return out, errors.New("不支持此 FRP 操作")
	}
	if next.Config.Token == "" {
		return out, errors.New("请填写供客户端连接使用的访问密钥")
	}
	if err = next.Config.Validate(); err != nil {
		return out, err
	}
	for _, p := range []string{directory(data), filepath.Join(directory(data), "runtime")} {
		if err = secure.RootDirectory(p, 0700); err != nil {
			return out, err
		}
	}
	if next.DashboardPassword == "" {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return out, e
		}
		next.DashboardPort = listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		next.DashboardPassword = secure.Token()
	}
	if next.DashboardPort == next.Config.BindPort || next.DashboardPort == next.Config.HTTPPort || next.DashboardPort == next.Config.HTTPSPort {
		return out, errors.New("此端口已被服务使用，请选择其他端口")
	}
	if backup, e := inspect(ctx, data, Name+"-previous"); e != nil {
		return out, e
	} else if backup != nil {
		return out, errors.New("上次 FRP 操作尚未清理完成，请先卸载后重新安装，已有配置会保留")
	}
	if request.Action != "configure" || next.Config.Image != original.Config.Image {
		progress("正在下载 FRP 服务端")
		if err = command("pull", next.Config.Image); err != nil {
			return out, err
		}
	}
	progress("正在检查 FRP 配置")
	candidatePath, cleanup, err := candidate(data, next)
	if err != nil {
		return out, err
	}
	defer cleanup()
	if err = command("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", "type=bind,src="+candidatePath+",dst=/etc/frp/frps.json,readonly", next.Config.Image, "verify", "-c", "/etc/frp/frps.json"); err != nil {
		return out, err
	}
	wasRunning := current != nil && (current.State == "running" || current.State == "restarting")
	start := request.Action == "install" || current == nil || wasRunning
	changed, stopped, committed := false, false, false
	defer func() {
		if committed || (!changed && !stopped) {
			return
		}
		recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var failures []error
		recoverCommand := func(args ...string) {
			text, e := software.Docker(recovery, nil, args...)
			out.Log = addLog(out.Log, text)
			if e != nil {
				failures = append(failures, e)
			}
		}
		if changed {
			if candidate, e := inspect(recovery, data, Name); e != nil {
				failures = append(failures, e)
			} else if candidate != nil {
				recoverCommand("rm", "--force", Name)
			}
			if current != nil {
				if e := writeRuntime(data, original); e != nil {
					failures = append(failures, e)
				}
				recoverCommand("rename", Name+"-previous", Name)
			}
			retained := original
			if retained.Config.Token == "" {
				retained = next
				retained.Installed = false
			}
			if e := save(data, retained); e != nil {
				failures = append(failures, e)
			}
		}
		if current != nil && wasRunning {
			recoverCommand("start", Name)
			if e := waitReady(recovery, data, original); e != nil {
				failures = append(failures, e)
			}
		}
		if len(failures) > 0 {
			err = errors.Join(err, fmt.Errorf("恢复原服务未完成：%w", errors.Join(failures...)))
		}
	}()
	if current != nil {
		progress("正在应用 FRP 设置")
		if wasRunning {
			stopped = true
			if err = command("stop", "--time", "10", Name); err != nil {
				return out, err
			}
		}
		if err = command("rename", Name, Name+"-previous"); err != nil {
			return out, err
		}
	}
	changed = true
	if err = availablePorts(next.Config, next.DashboardPort); err != nil {
		return out, err
	}
	if err = writeRuntime(data, next); err != nil {
		return out, err
	}
	restart := "no"
	if next.Config.AutoStart {
		restart = "unless-stopped"
	}
	progress("正在准备 FRP 服务")
	if err = command("create", "--name", Name, "--label", ownerLabel+"=frps", "--label", dataLabel+"="+secure.Hash([]byte(data)), "--network", "host", "--restart", restart, "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges", "--log-opt", "max-size=10m", "--log-opt", "max-file=3", "--mount", "type=bind,src="+filepath.Join(directory(data), "runtime")+",dst=/etc/frp,readonly", next.Config.Image, "-c", "/etc/frp/frps.json"); err != nil {
		return out, err
	}
	if start {
		progress("正在启动 FRP 服务端")
		if err = command("start", Name); err != nil {
			return out, err
		}
		if err = waitReady(ctx, data, next); err != nil {
			logs, _ := software.Docker(ctx, nil, "logs", "--tail", "80", Name)
			out.Log = addLog(out.Log, logs)
			return out, err
		}
	}
	next.Installed = true
	if err = save(data, next); err != nil {
		return out, err
	}
	committed = true
	if current != nil {
		if err = command("rm", Name+"-previous"); err != nil {
			return out, fmt.Errorf("FRP 已应用设置，但旧服务清理失败：%w", err)
		}
	}
	out.Message = map[string]string{"install": "FRP 服务端已安装", "update": "FRP 服务端已更新", "configure": "FRP 设置已保存"}[request.Action]
	return out, nil
}
