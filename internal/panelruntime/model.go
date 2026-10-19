// Package panelruntime publishes and verifies root-approved, persistent panel
// releases. It never downloads artifacts or selects an executable from a request.
package panelruntime

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const Schema = 1
const DeploymentLimit = 8 << 10
const BinaryLimit = 192 << 20
const WebFileLimit = 8 << 20
const WebLimit = 64 << 20
const FileCountLimit = 4096

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var relative = regexp.MustCompile(`^[a-zA-Z0-9_.][a-zA-Z0-9_./-]*$`)
var imageValue = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,240}@sha256:[0-9a-f]{64}$`)

type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Release struct {
	Schema          int             `json:"schema"`
	ID              string          `json:"id"`
	Version         string          `json:"version"`
	DatabaseSchema  int64           `json:"database_schema"`
	AgentProtocol   int             `json:"agent_protocol"`
	LauncherVersion int             `json:"launcher_version"`
	Architecture    string          `json:"architecture"`
	BinarySHA256    string          `json:"binary_sha256"`
	Web             map[string]File `json:"web"`
}
type Deployment struct {
	Schema         int                    `json:"schema"`
	Mode           string                 `json:"mode"`
	DataDir        string                 `json:"data_dir"`
	Listen         string                 `json:"listen"`
	UID            int                    `json:"uid"`
	GID            int                    `json:"gid"`
	IPCGID         int                    `json:"ipc_gid"`
	LauncherSHA256 string                 `json:"launcher_sha256"`
	InitialRelease string                 `json:"initial_release"`
	Image          string                 `json:"image"`
	ImageID        string                 `json:"image_id"`
	SignedImage    releases.ImageApproval `json:"signed_image"`
}
type BindInput struct {
	DataDir, Binary, WebDir, LauncherBinary, Listen, Image string
	UID, GID, IPCGID                                       int
	Signature                                              releases.ImageInput
}
type Snapshot struct {
	Deployment Deployment `json:"deployment"`
	Release    Release    `json:"release"`
	Directory  string     `json:"directory"`
}

func Root(data string) (string, error) {
	if !filepath.IsAbs(data) || filepath.Clean(data) != data || (!strings.HasPrefix(data, "/srv/") && !strings.HasPrefix(data, "/var/lib/")) || strings.Trim(data, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "", errors.New("面板运行数据目录须为 /srv 或 /var/lib 下的规范路径")
	}
	return filepath.Join(data, "runtime"), nil
}
func validRelative(name string) bool {
	return len(name) <= 512 && relative.MatchString(name) && filepath.Clean(name) == name && !strings.HasPrefix(name, "../") && name != "." && name != ".." && strings.Count(name, "/") <= 12
}
func releaseID(r Release) string {
	r.ID = ""
	raw, _ := json.Marshal(r)
	return secure.Hash(raw)
}
func (d Deployment) validate(data string) error {
	host, port, err := net.SplitHostPort(d.Listen)
	n, parse := strconv.Atoi(port)
	if err != nil || parse != nil || (host != "127.0.0.1" && host != "::1") || n < 1024 || n > 65535 || d.Schema != Schema || d.DataDir != data || d.UID <= 0 || d.GID <= 0 || d.IPCGID <= 0 || !digest.MatchString(d.InitialRelease) {
		return errors.New("面板运行绑定无效")
	}
	if raw, err := json.Marshal(d); err != nil || len(raw) > DeploymentLimit {
		return errors.New("面板运行绑定超过记录上限")
	}
	switch d.Mode {
	case "native":
		if d.LauncherSHA256 != "" || d.Image != "" || d.ImageID != "" || d.SignedImage != (releases.ImageApproval{}) {
			return errors.New("原生面板绑定不能包含容器来源")
		}
		return nil
	case "docker":
		if !digest.MatchString(d.LauncherSHA256) || !imageValue.MatchString(d.Image) {
			return errors.New("容器面板的固定镜像或 launcher 无效")
		}
		return d.SignedImage.Validate("panel-launcher", d.Image, d.ImageID, d.LauncherSHA256)
	default:
		return errors.New("面板运行绑定模式无效")
	}
}
func (r Release) validate() error {
	// This immutable inventory can describe a future release. Activation checks
	// the installed Agent and launcher separately from signature staging.
	if r.Schema != Schema || !digest.MatchString(r.ID) || r.ID != releaseID(r) || r.Version == "" || len(r.Version) > 128 || r.DatabaseSchema <= 0 || r.AgentProtocol <= 0 || r.LauncherVersion <= 0 || !digest.MatchString(r.BinarySHA256) || len(r.Web) < 1 || len(r.Web) > FileCountLimit {
		return errors.New("面板发布清单身份或协议不匹配")
	}
	if _, ok := r.Web["index.html"]; !ok {
		return errors.New("面板发布缺少前端入口")
	}
	var size int64
	for name, f := range r.Web {
		if !validRelative(name) || !digest.MatchString(f.SHA256) || f.Size < 0 || f.Size > WebFileLimit {
			return errors.New("面板前端清单无效")
		}
		size += f.Size
	}
	if size > WebLimit {
		return errors.New("面板前端产物超过容量限制")
	}
	return nil
}
