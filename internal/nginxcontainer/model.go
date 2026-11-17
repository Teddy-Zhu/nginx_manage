// Package nginxcontainer admits one locally approved, fixed-image Nginx
// container. Only the host Agent talks to Docker; web requests cannot choose
// an image, container, executable, mount or exec argument.
package nginxcontainer

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/releases"
)

const Schema = 1
const Name = "nginxpanel-nginx"
const Binary = "/usr/sbin/nginx"
const Bootstrap = "/usr/local/bin/nginxpanel-nginx-launcher"
const binaryLimit = 192 << 20

var hashValue = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageValue = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9._:/-]{0,240}@sha256:[0-9a-f]{64})$`)

// Compare daemon RepoDigests by immutable repository/digest identity, retaining
// registry ports when normalizing an optional tag in daemon metadata.
func repositoryDigest(value string) string {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	name := parts[0]
	if tag := strings.LastIndex(name, ":"); tag > strings.LastIndex(name, "/") {
		name = name[:tag]
	}
	// Docker may omit its default registry in RepoDigests even when the signed
	// reference explicitly uses docker.io. Keep other registries distinct.
	name = strings.TrimPrefix(strings.TrimPrefix(name, "docker.io/"), "index.docker.io/")
	if !strings.Contains(name, "/") {
		name = "library/" + name
	}
	return name + "@" + parts[1]
}

type Capabilities struct {
	Schema           int      `json:"schema"`
	Version          string   `json:"nginx_version"`
	Policy           string   `json:"module_policy"`
	Features         []string `json:"static_features"`
	Installation     bool     `json:"runtime_module_installation"`
	Compilation      bool     `json:"runtime_module_compilation"`
	Dynamic          []string `json:"dynamic_modules"`
	BuildInformation string   `json:"build_information"`
	BinaryDigest     string   `json:"binary_digest"`
}
type Binding struct {
	Schema          int                    `json:"schema"`
	DataDir         string                 `json:"data_dir"`
	Image           string                 `json:"image"`
	ImageID         string                 `json:"image_id"`
	Architecture    string                 `json:"architecture"`
	UID             int                    `json:"uid"`
	GID             int                    `json:"gid"`
	BinarySHA256    string                 `json:"binary_sha256"`
	BootstrapSHA256 string                 `json:"bootstrap_sha256"`
	Build           string                 `json:"build"`
	Capabilities    Capabilities           `json:"capabilities"`
	Environment     []string               `json:"environment"`
	BoundAt         int64                  `json:"bound_at"`
	SignedImage     releases.ImageApproval `json:"signed_image"`
}
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

func Path(data string) (string, error) {
	if !filepath.IsAbs(data) || filepath.Clean(data) != data || (!strings.HasPrefix(data, "/srv/") && !strings.HasPrefix(data, "/var/lib/")) || strings.Trim(data, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "", errors.New("Nginx 容器数据目录须为 /srv 或 /var/lib 下的规范路径")
	}
	return filepath.Join(data, "bin", "components", "nginx-container.json"), nil
}
func (b Binding) Mounts() []Mount {
	var out []Mount
	for _, item := range []struct {
		path     string
		readOnly bool
	}{{"bin/components", true}, {"nginx", true}, {"certificates", true}, {"run", true}, {"nginx/tmp", false}, {"run/nginx", false}, {"logs", false}} {
		p := filepath.Join(b.DataDir, item.path)
		out = append(out, Mount{p, p, item.readOnly})
	}
	return out
}
func (b Binding) validate(data string) error {
	c := b.Capabilities
	if b.Schema != Schema || b.DataDir != data || !imageValue.MatchString(b.Image) || !strings.HasPrefix(b.ImageID, "sha256:") || !hashValue.MatchString(strings.TrimPrefix(b.ImageID, "sha256:")) || b.Architecture != runtime.GOARCH || b.UID <= 0 || b.GID <= 0 || !hashValue.MatchString(b.BinarySHA256) || !hashValue.MatchString(b.BootstrapSHA256) || b.BoundAt <= 0 || len(b.Build) == 0 || len(b.Build) > 64<<10 || len(b.Environment) > 64 {
		return errors.New("Nginx 容器绑定身份无效")
	}
	if err := b.SignedImage.Validate("nginx", b.Image, b.ImageID, b.BootstrapSHA256); err != nil {
		return err
	}
	if b.BoundAt != b.SignedImage.ApprovedAt {
		return errors.New("Nginx 镜像安装时间与签名批准记录不一致")
	}
	if c.Schema != 1 || c.Version == "" || len(c.Version) > 64 || c.Policy != "image-only" || c.Installation || c.Compilation || len(c.Dynamic) != 0 || len(c.Features) == 0 || len(c.Features) > 64 || c.BuildInformation != "/usr/share/nginxpanel/nginx-build.txt" || c.BinaryDigest != "/usr/share/nginxpanel/nginx.sha256" {
		return errors.New("Nginx 镜像必须在构建时预置模块，禁止运行时增装或编译")
	}
	seen := map[string]bool{}
	for _, name := range c.Features {
		if name == "" || len(name) > 64 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz_0123456789") != "" || seen[name] {
			return errors.New("Nginx 镜像能力清单无效")
		}
		seen[name] = true
	}
	total := 0
	for _, value := range b.Environment {
		total += len(value)
		if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") || !strings.Contains(value, "=") {
			return errors.New("Nginx 镜像环境无效")
		}
	}
	if total > 16<<10 {
		return errors.New("Nginx 镜像环境超过预算")
	}
	if len(canonical(b)) > 128<<10 {
		return errors.New("Nginx 容器登记超过大小预算")
	}
	return nil
}
func (b Binding) Installation() *nginxruntime.Installation {
	return &nginxruntime.Installation{Owner: "docker", Version: b.Capabilities.Version, SHA256: b.BinarySHA256, SourceURL: b.Image, BoundAt: b.BoundAt}
}
func canonical(v any) []byte { raw, _ := json.Marshal(v); return raw }
