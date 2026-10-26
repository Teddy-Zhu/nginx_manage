// Package software manages user-selected Docker applications and their catalogs.
package software

import (
	"encoding/json"
	"errors"
	"net/url"
	"nginxpanel/internal/fail2ban"
	"regexp"
	"strings"
)

type Port struct {
	Host      int    `json:"host"`
	Container int    `json:"container"`
	Protocol  string `json:"protocol"`
}
type Volume struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}
type Application struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Image       string            `json:"image"`
	Ports       []Port            `json:"ports,omitempty"`
	Volumes     []Volume          `json:"volumes,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}
type Source struct {
	Schema       int           `json:"schema"`
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	URL          string        `json:"url,omitempty"`
	Applications []Application `json:"applications"`
}
type Installation struct {
	SourceID    string      `json:"source_id"`
	Application Application `json:"application"`
	Container   string      `json:"container"`
	ImageID     string      `json:"image_id"`
	UpdatedAt   int64       `json:"updated_at"`
}
type Catalog struct {
	Sources   []Source       `json:"sources"`
	Installed []Installation `json:"installed"`
	Error     string         `json:"error,omitempty"`
}
type Request struct {
	Fail2ban   *fail2ban.ContainerRequest `json:"fail2ban,omitempty"`
	Action     string                     `json:"action"`
	Source     *Source                    `json:"source,omitempty"`
	URL        string                     `json:"url,omitempty"`
	SourceID   string                     `json:"source_id,omitempty"`
	AppID      string                     `json:"app_id,omitempty"`
	PlanID     string                     `json:"plan_id,omitempty"`
	Prerelease bool                       `json:"prerelease,omitempty"`
}
type Result struct {
	SourceID string `json:"source_id,omitempty"`
	AppID    string `json:"app_id,omitempty"`
	Message  string `json:"message"`
	Log      string `json:"log"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
var image = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

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
		if !identifier.MatchString(app.ID) || seen[app.ID] || strings.TrimSpace(app.Name) == "" || len(app.Name) > 128 || len(app.Description) > 1024 || !image.MatchString(app.Image) || len(app.Ports) > 32 || len(app.Volumes) > 16 || len(app.Environment) > 64 {
			return errors.New("软件名称、镜像或配置无效")
		}
		seen[app.ID] = true
		ports := map[string]bool{}
		for _, p := range app.Ports {
			if p.Host < 1 || p.Host > 65535 || p.Container < 1 || p.Container > 65535 || p.Protocol != "tcp" && p.Protocol != "udp" {
				return errors.New("端口映射无效")
			}
			key := string(rune(p.Host)) + p.Protocol
			if ports[key] {
				return errors.New("同一软件的主机端口重复")
			}
			ports[key] = true
		}
		vols := map[string]bool{}
		targets := map[string]bool{}
		for _, v := range app.Volumes {
			if !identifier.MatchString(v.Name) || vols[v.Name] || targets[v.Target] || !strings.HasPrefix(v.Target, "/") || v.Target == "/" || strings.Contains(v.Target, "..") || strings.ContainsAny(v.Target, ",\x00\r\n") || len(v.Target) > 256 {
				return errors.New("软件数据目录无效")
			}
			vols[v.Name] = true
			targets[v.Target] = true
		}
		for name, value := range app.Environment {
			if !envName.MatchString(name) || len(value) > 4096 || strings.ContainsRune(value, 0) {
				return errors.New("软件环境变量无效")
			}
		}
	}
	return nil
}
func (r Request) Validate() error {
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
	case "install", "update", "uninstall":
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
