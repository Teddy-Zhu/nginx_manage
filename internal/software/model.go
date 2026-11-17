// Package software manages software catalogs and invokes provider-defined operations.
package software

import (
	"encoding/json"
	"errors"
	"net/url"
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/containers"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/frps"
	"regexp"
	"strings"
)

type Action struct {
	Command     []string `json:"command"`
	Description string   `json:"description,omitempty"`
}
type Application struct {
	ID          string                      `json:"id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	Actions     map[string]Action           `json:"actions"`
	VersionsURL string                      `json:"versions_url,omitempty"`
	Versions    []componentversions.Version `json:"versions,omitempty"`
}
type Source struct {
	Schema       int           `json:"schema"`
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	URL          string        `json:"url,omitempty"`
	Applications []Application `json:"applications"`
}
type Installation struct {
	SourceID    string                     `json:"source_id"`
	Application Application                `json:"application"`
	UpdatedAt   int64                      `json:"updated_at"`
	State       string                     `json:"state,omitempty"`
	Error       string                     `json:"error,omitempty"`
	Entry       string                     `json:"entry,omitempty"`
	Version     *componentversions.Version `json:"version,omitempty"`
	Previous    *componentversions.Version `json:"previous,omitempty"`
}
type Catalog struct {
	Sources   []Source       `json:"sources"`
	Installed []Installation `json:"installed"`
	Error     string         `json:"error,omitempty"`
}
type Request struct {
	Container  *containers.Control        `json:"container,omitempty"`
	Frps       *frps.Request              `json:"frps,omitempty"`
	Fail2ban   *fail2ban.ContainerRequest `json:"fail2ban,omitempty"`
	Action     string                     `json:"action"`
	Source     *Source                    `json:"source,omitempty"`
	URL        string                     `json:"url,omitempty"`
	SourceID   string                     `json:"source_id,omitempty"`
	AppID      string                     `json:"app_id,omitempty"`
	PlanID     string                     `json:"plan_id,omitempty"`
	Prerelease bool                       `json:"prerelease,omitempty"`
	Version    string                     `json:"version,omitempty"`
}
type Result struct {
	SourceID string                     `json:"source_id,omitempty"`
	AppID    string                     `json:"app_id,omitempty"`
	Message  string                     `json:"message"`
	Log      string                     `json:"log"`
	Version  *componentversions.Version `json:"version,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
var image = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}$`)

func (s Source) Validate() error {
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 24<<10 {
		return errors.New("软件源配置不能超过 24 KB")
	}
	if s.Schema != 1 || !identifier.MatchString(s.ID) || s.ID == "builtin" || strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 || len(s.Applications) == 0 || len(s.Applications) > 64 {
		return errors.New("软件源格式无效：需要名称、标识和软件列表")
	}
	if s.URL != "" {
		if _, err := sourceURL(s.URL); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, app := range s.Applications {
		if !identifier.MatchString(app.ID) || seen[app.ID] || strings.TrimSpace(app.Name) == "" || len(app.Name) > 128 || len(app.Description) > 1024 || len(app.Actions) < 3 || len(app.Actions) > 11 {
			return errors.New("软件名称或操作定义无效")
		}
		seen[app.ID] = true
		if app.VersionsURL != "" && len(app.Versions) > 0 {
			return errors.New("软件版本列表与版本目录地址只能选择一种")
		}
		if app.VersionsURL != "" {
			if _, err := sourceURL(app.VersionsURL); err != nil {
				return err
			}
		}
		if err := validateVersions(app.Versions); err != nil {
			return err
		}
		for _, required := range []string{"install", "uninstall", "status"} {
			if _, ok := app.Actions[required]; !ok {
				return errors.New("软件必须定义安装、卸载和状态检查操作")
			}
		}
		for name, action := range app.Actions {
			switch name {
			case "install", "uninstall", "status", "start", "stop", "restart", "update", "logs", "check-version", "backup", "restore":
			default:
				return errors.New("不支持的软件操作：" + name)
			}
			if len(action.Command) == 0 || len(action.Command) > 32 || strings.TrimSpace(action.Command[0]) == "" || len(action.Description) > 512 {
				return errors.New("软件操作命令无效")
			}
			for _, arg := range action.Command {
				if len(arg) > 8192 || strings.ContainsRune(arg, 0) {
					return errors.New("软件操作参数无效")
				}
			}
		}
	}

	return nil
}
func (r Request) Validate() error {
	if r.Version == "" && (r.SourceID == "builtin" && (r.Action == "install" || r.Action == "update") || r.Frps != nil && (r.Frps.Action == "install" || r.Frps.Action == "update") || r.Fail2ban != nil && (r.Fail2ban.Action == "install" || r.Fail2ban.Action == "update")) {
		return errors.New("请选择需要安装的软件版本")
	}
	if len(r.Version) > 128 || strings.ContainsAny(r.Version, " \t\r\n/\\\x00") || r.Version != "" && r.Action != "install" && r.Action != "update" && r.Action != "frps" && r.Action != "fail2ban" {
		return errors.New("目标软件版本无效")
	}
	if r.Version != "" && (r.Action == "frps" && (r.Frps == nil || r.Frps.Action != "install" && r.Frps.Action != "update") || r.Action == "fail2ban" && (r.Fail2ban == nil || r.Fail2ban.Action != "install" && r.Fail2ban.Action != "update")) {
		return errors.New("此操作不能选择版本")
	}
	if r.Action == "container" {
		if r.Container == nil || r.Frps != nil || r.Fail2ban != nil || r.Source != nil || r.URL != "" || r.SourceID != "" || r.AppID != "" || r.PlanID != "" || r.Prerelease {
			return errors.New("容器操作参数无效")
		}
		return r.Container.Validate()
	}
	if r.Container != nil {
		return errors.New("此操作不能携带容器操作参数")
	}
	if r.Action == "frps" {
		if r.Frps == nil || r.Fail2ban != nil || r.Source != nil || r.URL != "" || r.SourceID != "" || r.AppID != "" || r.PlanID != "" || r.Prerelease {
			return errors.New("FRP 操作参数无效")
		}
		return r.Frps.Validate()
	}
	if r.Frps != nil {
		return errors.New("此操作不能携带 FRP 配置")
	}
	if r.Action == "fail2ban" {
		if r.Fail2ban == nil || r.Source != nil || r.URL != "" || r.SourceID != "" || r.AppID != "" || r.PlanID != "" || r.Prerelease {
			return errors.New("登录防护操作参数无效")
		}
		return r.Fail2ban.Validate()
	}
	if r.Fail2ban != nil {
		return errors.New("此操作不能携带登录防护配置")
	}
	switch r.Action {
	case "import":
		if r.SourceID != "" || r.AppID != "" || r.PlanID != "" || r.Prerelease || (r.Source == nil) == (r.URL == "") {
			return errors.New("请选择配置文件或软件源地址")
		}
		if r.Source != nil {
			return r.Source.Validate()
		}
		_, err := sourceURL(r.URL)
		return err
	case "refresh", "delete":
		if identifier.MatchString(r.SourceID) && r.Source == nil && r.URL == "" && r.AppID == "" && r.PlanID == "" && !r.Prerelease {
			return nil
		}
	case "install", "update", "uninstall", "start", "stop", "restart", "logs":
		if identifier.MatchString(r.SourceID) && identifier.MatchString(r.AppID) && r.Source == nil && r.URL == "" && r.PlanID == "" && !r.Prerelease {
			return nil
		}
	case "update-panel":
		if r.Source == nil && r.URL == "" && r.SourceID == "" && r.AppID == "" && len(r.PlanID) == 64 && strings.Trim(r.PlanID, "0123456789abcdef") == "" {
			return nil
		}
	}
	return errors.New("软件操作无效")
}
func sourceURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Hostname() == "" || u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("软件源需为不含密码的 HTTP 或 HTTPS 配置地址")
	}
	if u.Host == "github.com" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) >= 5 && parts[2] == "blob" {
			u.Host = "raw.githubusercontent.com"
			u.Path = "/" + strings.Join(append(parts[:2], parts[3:]...), "/")
		}
	}
	return u, nil
}

func ValidImage(value string) bool { return image.MatchString(value) }
