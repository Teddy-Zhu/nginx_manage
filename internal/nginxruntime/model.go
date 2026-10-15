// Package nginxruntime binds a locally approved Nginx executable to a native
// installation, including an explicitly uninstalled slot. Bindings are
// immutable; installing into a slot or replacing a runtime uses maintenance.
package nginxruntime

import (
	"errors"
	"path/filepath"
	"strings"

	"nginxpanel/internal/releases"
)

const Schema = 1

var ErrNotInstalled = errors.New("本机已明确登记为未安装 Nginx")

type Input struct {
	DataDir, Binary, PlanID, AssetID, TrustPath string
	Prerelease                                  bool
	Uninstalled                                 bool
}
type Signed struct {
	PlanID         string            `json:"plan_id"`
	AssetID        string            `json:"asset_id"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	TrustSHA256    string            `json:"trust_sha256"`
	TrustPath      string            `json:"trust_path"`
	Prerelease     bool              `json:"prerelease"`
	Host           releases.Host     `json:"host"`
	Receiver       releases.Receiver `json:"receiver"`
}
type Binding struct {
	OperationID string  `json:"operation_id,omitempty"`
	Schema      int     `json:"schema"`
	DataDir     string  `json:"data_dir"`
	Owner       string  `json:"owner"`
	Binary      string  `json:"binary"`
	SHA256      string  `json:"sha256"`
	Version     string  `json:"version"`
	BoundAt     int64   `json:"bound_at"`
	Signed      *Signed `json:"signed,omitempty"`
}
type Installation struct {
	Owner     string `json:"owner"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	PlanID    string `json:"plan_id"`
	AssetID   string `json:"asset_id"`
	SourceURL string `json:"source_url"`
	License   string `json:"license"`
	BoundAt   int64  `json:"bound_at"`
}

func bindingPath(data string) (string, error) {
	if !filepath.IsAbs(data) || filepath.Clean(data) != data || (!strings.HasPrefix(data, "/srv/") && !strings.HasPrefix(data, "/var/lib/")) || strings.Trim(data, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "", errors.New("原生绑定的数据目录须为 /srv 或 /var/lib 下的规范路径")
	}
	return filepath.Join(data, "bin", "components", "nginx.json"), nil
}
