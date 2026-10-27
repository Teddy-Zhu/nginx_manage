package fail2bancontainer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/software"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Run(ctx context.Context, data string, r fail2ban.ContainerRequest, progress func(string)) (out software.Result, err error) {
	out = software.Result{}
	if err := r.Validate(); err != nil {
		return out, err
	}
	if progress == nil {
		progress = func(string) {}
	}
	c, installed, err := Configuration(data)
	original := c
	if err != nil {
		return out, err
	}
	if r.Action != "install" && !installed {
		return out, errors.New("请先安装登录防护")
	}
	if !software.ValidImage(c.Image) {
		return out, errors.New("下载来源无效")
	}
	present, err := exists(ctx)
	if err != nil {
		return out, err
	}
	if present {
		if err = owned(ctx); err != nil {
			return out, err
		}
	}
	switch r.Action {
	case "logs":
		if !present {
			return out, errors.New("软件容器不存在，请更新软件以恢复安装")
		}
		out.Log, err = command(ctx, "logs", "--tail", "100", Name)
		out.Message = "服务日志已读取"
		return out, err
	case "install", "update":
		if r.Action == "install" {
			if installed && c.Revision != r.Config.Revision {
				return out, errors.New("配置已更新，请刷新后重试")
			}
			c = *r.Config
			if !software.ValidImage(c.Image) {
				return out, errors.New("下载来源无效")
			}
		}
		if err = setup(data); err != nil {
			return out, err
		}
		progress("正在下载 Fail2ban")
		out.Log, err = software.Docker(ctx, progress, "pull", c.Image)
		if err != nil {
			return out, err
		}
		progress("正在检查安装条件")
		if _, err = command(ctx, "run", "--rm", "--entrypoint", "/bin/sh", c.Image, "-ec", `for utility in fail2ban-client python3 ipset iptables-legacy ip6tables-legacy flock; do command -v "$utility" >/dev/null || exit 1; done`); err != nil {
			return out, fmt.Errorf("下载来源缺少所需防护工具，请使用兼容的 Fail2ban 镜像：%w", err)
		}
		progress("正在准备防护环境")
		if err = prepareKernel(ctx); err != nil {
			return out, err
		}
		if _, err = command(ctx, "run", "--rm", "--network", "host", "--cap-add", "NET_ADMIN", "--entrypoint", "/bin/sh", c.Image, "-ec", "iptables-legacy -w -S INPUT >/dev/null; ip6tables-legacy -w -S INPUT >/dev/null; ipset list -name >/dev/null"); err != nil {
			return out, fmt.Errorf("系统暂不支持所需防护规则：%w", err)
		}
		backup := Name + "-previous"
		backedUp := false
		wasRunning := false
		var leftover bool
		leftover, err = containerNamed(ctx, backup)
		if err != nil {
			return out, err
		}
		if leftover {
			if err = ownedNamed(ctx, backup); err != nil {
				return out, err
			}
			if !present {
				if _, err = command(ctx, "rename", backup, Name); err != nil {
					return out, err
				}
				present = true
			} else {
				if _, err = command(ctx, "rm", backup); err != nil {
					return out, err
				}
			}
		}
		if present {
			wasRunning, err = running(ctx)
			if err != nil {
				return out, err
			}
			if _, err = command(ctx, "stop", "--time", "20", Name); err != nil {
				return out, err
			}
			if _, err = command(ctx, "rename", Name, backup); err != nil {
				if wasRunning {
					if _, restoreErr := command(ctx, "start", Name); restoreErr != nil {
						return out, fmt.Errorf("%w；恢复启动失败：%v", err, restoreErr)
					}
				}
				return out, err
			}
			backedUp = true
		}
		defer func() {
			if err == nil || !backedUp {
				return
			}
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
			defer cancel()
			restore := func() error {
				found, e := exists(recovery)
				if e != nil {
					return e
				}
				if found {
					if e = owned(recovery); e != nil {
						return e
					}
					if _, e = command(recovery, "rm", "-f", Name); e != nil {
						return e
					}
				}
				if e = render(data, original); e != nil {
					return e
				}
				if e = saveState(data, original, installed); e != nil {
					return e
				}
				if _, e = command(recovery, "rename", backup, Name); e != nil {
					return e
				}
				if wasRunning {
					_, e = command(recovery, "start", Name)
				}
				return e
			}
			if restoreErr := restore(); restoreErr != nil {
				err = fmt.Errorf("%w；恢复原服务失败：%v", err, restoreErr)
			}
		}()
		if err = render(data, c); err != nil {
			return out, err
		}
		restart := "no"
		if c.AutoStart {
			restart = "always"
		}
		args := []string{"run", "-d", "--name", Name, "--restart", restart, "--network", "host", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--label", "org.nginxpanel.builtin=fail2ban", "--mount", "type=bind,src=" + filepath.Join(directory(data), "data") + ",dst=/data", "--mount", "type=bind,src=" + filepath.Join(data, "agent", "security") + ",dst=/panel-security,readonly", "--mount", "type=bind,src=" + filepath.Join(data, "logs") + ",dst=/panel-logs,readonly", "--env", "F2B_LOG_TARGET=STDOUT", "--env", "TZ=Asia/Shanghai"}
		for _, path := range []string{"/var/log/journal", "/run/log/journal", "/etc/machine-id"} {
			if _, err := os.Stat(path); err == nil {
				args = append(args, "--mount", "type=bind,src="+path+",dst="+path+",readonly")
			} else if !os.IsNotExist(err) {
				return out, err
			}
		}
		if _, err := os.Stat("/var/log"); err == nil {
			args = append(args, "--mount", "type=bind,src=/var/log,dst=/host-logs,readonly")
		} else if !os.IsNotExist(err) {
			return out, err
		}
		args = append(args, c.Image)
		progress("正在启动登录防护")
		if _, err = command(ctx, args...); err != nil {
			return out, err
		}
		c.Revision++
		if err = save(data, c); err != nil {
			return out, err
		}
		if err = wait(ctx); err != nil {
			logs, logErr := command(ctx, "logs", "--tail", "100", Name)
			if logErr != nil {
				return out, fmt.Errorf("%w；读取服务日志失败：%v", err, logErr)
			}
			out.Log = logs
			return out, err
		}
		if err = persistKernel(); err != nil {
			return out, err
		}
		if backedUp {
			backedUp = false
			if _, err = command(ctx, "rm", backup); err != nil {
				return out, fmt.Errorf("软件已更新，清理旧容器失败：%w", err)
			}
		}
		out.Message = "登录防护已安装并启动"
	case "configure":
		next := *r.Config
		if next.Revision != c.Revision {
			return out, errors.New("配置已更新，请刷新后重试")
		}
		if next.Image != c.Image {
			return out, errors.New("更换下载来源后，请重新安装软件")
		}
		alive := false
		if present {
			alive, err = running(ctx)
			if err != nil {
				return out, err
			}
		}
		if err = render(data, next); err != nil {
			return out, err
		}
		committed := false
		defer func() {
			if committed || err == nil {
				return
			}
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			restoreErr := render(data, c)
			if restoreErr == nil && alive {
				_, restoreErr = client(recovery, "reload")
			}
			if restoreErr == nil && present {
				restart := "no"
				if c.AutoStart {
					restart = "always"
				}
				_, restoreErr = command(recovery, "update", "--restart", restart, Name)
			}
			if restoreErr != nil {
				err = fmt.Errorf("%w；恢复原配置失败：%v", err, restoreErr)
			}
		}()
		if alive {
			out.Log, err = client(ctx, "-t")
			if err != nil {
				return out, err
			}
			if _, err = client(ctx, "reload"); err != nil {
				return out, err
			}
		}
		restart := "no"
		if next.AutoStart {
			restart = "always"
		}
		if present {
			if _, err = command(ctx, "update", "--restart", restart, Name); err != nil {
				return out, err
			}
		}
		next.Revision++
		if err = save(data, next); err != nil {
			return out, err
		}
		committed = true
		out.Message = "防护规则已保存"
	case "start", "restart":
		if !present {
			return out, errors.New("软件容器不存在，请重新安装")
		}
		if err = prepareKernel(ctx); err != nil {
			return out, err
		}
		if _, err = command(ctx, r.Action, Name); err != nil {
			return out, err
		}
		if err = wait(ctx); err != nil {
			return out, err
		}
		out.Message = "登录防护已启动"
	case "stop":
		if present {
			alive, err := running(ctx)
			if err != nil {
				return out, err
			}
			if alive {
				if _, err = command(ctx, "stop", "--time", "20", Name); err != nil {
					return out, err
				}
			}
		}
		out.Message = "登录防护已停止"
	case "uninstall":
		if present {
			if _, err = command(ctx, "stop", "--time", "20", Name); err != nil {
				return out, err
			}
			if _, err = command(ctx, "rm", Name); err != nil {
				return out, err
			}
		}
		backup := Name + "-previous"
		if found, e := containerNamed(ctx, backup); e != nil {
			return out, e
		} else if found {
			if err = ownedNamed(ctx, backup); err != nil {
				return out, err
			}
			if _, err = command(ctx, "stop", "--time", "20", backup); err != nil {
				return out, err
			}
			if _, err = command(ctx, "rm", backup); err != nil {
				return out, err
			}
		}
		if err = removeKernelConfig(); err != nil {
			return out, err
		}
		if err = saveState(data, c, false); err != nil {
			return out, err
		}
		out.Message = "软件已卸载，配置和防护数据已保留"
	case "ban", "unban":
		address, _ := netip.ParseAddr(r.Address)
		r.Address = address.Unmap().String()
		if r.Action == "ban" {
			ip, _ := netip.ParseAddr(r.Address)
			for _, entry := range append([]string{"127.0.0.0/8", "::1"}, c.Whitelist...) {
				prefix, err := netip.ParsePrefix(entry)
				if err == nil && prefix.Contains(ip) {
					return out, errors.New("该地址位于信任名单，不能封禁")
				}
				trusted, err := netip.ParseAddr(entry)
				if err == nil && trusted.Unmap() == ip.Unmap() {
					return out, errors.New("该地址位于信任名单，不能封禁")
				}
			}
		}
		var found *fail2ban.ContainerRule
		for _, rule := range c.Rules {
			if rule.ID == r.JailID && rule.Enabled {
				copy := rule
				found = &copy
				break
			}
		}
		if found == nil {
			return out, errors.New("请选择已启用的防护规则")
		}
		action := "banip"
		if r.Action == "unban" {
			action = "unbanip"
		}
		out.Log, err = client(ctx, "set", jailName(r.JailID), action, r.Address)
		if err != nil {
			return out, err
		}
		if err = waitBan(ctx, *found, r.Address, r.Action == "ban"); err != nil {
			return out, err
		}
		out.Message = "封禁名单已更新"
	}
	return out, nil
}
func wait(ctx context.Context) error {
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		response, err := client(ctx, "ping")
		if err == nil && strings.Contains(response, "pong") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("登录防护未能启动，请查看安装日志")
		case <-ticker.C:
		}
	}
}
