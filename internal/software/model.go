// Package software defines the panel's component operations.
package software

import (
	"errors"
	"regexp"
	"strings"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/containers"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/frps"
	"nginxpanel/internal/releases"
)

type Progress func(string)

type Request struct {
	Container  *containers.Control        `json:"container,omitempty"`
	Frps       *frps.Request              `json:"frps,omitempty"`
	Fail2ban   *fail2ban.ContainerRequest `json:"fail2ban,omitempty"`
	Action     string                     `json:"action"`
	AppID      string                     `json:"app_id,omitempty"`
	PlanID     string                     `json:"plan_id,omitempty"`
	Prerelease bool                       `json:"prerelease,omitempty"`
	Version    string                     `json:"version,omitempty"`
	AutoStart  *bool                      `json:"auto_start,omitempty"`
}

type Result struct {
	AppID   string                     `json:"app_id,omitempty"`
	Message string                     `json:"message"`
	Log     string                     `json:"log"`
	Version *componentversions.Version `json:"version,omitempty"`
}

var image = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}$`)

func ValidImage(value string) bool { return image.MatchString(value) }

func (r Request) RequiresSecurity() bool {
	return r.Action == "fail2ban" || r.AppID == "fail2ban"
}

func (r Request) Validate() error {
	if r.Action != "update-panel" && (r.PlanID != "" || r.Prerelease) ||
		r.Action != "install" && r.AutoStart != nil ||
		r.Action != "install" && r.Action != "update" && r.Action != "install-nginx" && r.Version != "" ||
		r.Action != "container" && r.Container != nil ||
		r.Action != "fail2ban" && r.Fail2ban != nil ||
		r.Action != "frps" && r.Action != "install" && r.Frps != nil {
		return errors.New("软件操作参数无效")
	}
	switch r.Action {
	case "install", "update", "start", "stop", "restart", "uninstall", "logs":
		return r.validateComponent()
	}
	if r.AppID != "" {
		return errors.New("软件操作参数无效")
	}
	switch r.Action {
	case "install-nginx":
		// Completed install receipts from before version selection omit the ID.
		if r.Version == "" || r.Version == componentversions.BundledNginxID {
			return nil
		}
		if version, ok := strings.CutPrefix(r.Version, "nginx-v"); ok && releases.VersionChannel(version) != "" {
			return nil
		}
		return errors.New("请选择 Nginx 安装版本")
	case "update-panel":
		if len(r.PlanID) == 64 && strings.Trim(r.PlanID, "0123456789abcdef") == "" {
			return nil
		}
	case "container":
		if r.Container != nil {
			return r.Container.Validate()
		}
	case "frps":
		if r.Frps != nil && r.Frps.Action == "configure" {
			return r.Frps.Validate()
		}
	case "fail2ban":
		if r.Fail2ban != nil {
			switch r.Fail2ban.Action {
			case "configure", "ban", "unban":
				return r.Fail2ban.Validate()
			}
		}
	}
	return errors.New("软件操作无效")
}

func (r Request) validateComponent() error {
	if r.AppID != "frps" && r.AppID != "fail2ban" {
		return errors.New("内置组件不存在")
	}
	if (r.Action == "install" || r.Action == "update") &&
		(r.Version == "" || len(r.Version) > 128 || strings.ContainsAny(r.Version, " \t\r\n/\\\x00")) {
		return errors.New("请选择可用的组件版本")
	}
	if r.Action != "install" {
		return nil
	}
	if r.AppID == "frps" {
		if r.Frps == nil || r.Frps.Action != "install" || r.AutoStart != nil {
			return errors.New("请先填写 FRP 连接设置")
		}
		return r.Frps.Validate()
	}
	if r.Frps != nil {
		return errors.New("登录防护安装参数无效")
	}
	return nil
}
