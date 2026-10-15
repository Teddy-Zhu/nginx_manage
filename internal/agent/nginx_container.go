package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/secure"
)

func sameContainerBinding(a, b nginxcontainer.Binding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func containerFeatures(b nginxcontainer.Binding) (NginxFeatures, error) {
	out := parseNginxFeatures(b.Build)
	if !out.Available || out.Version != b.Capabilities.Version {
		return out, errors.New("镜像声明与 Nginx 编译版本不匹配")
	}
	for _, name := range b.Capabilities.Features {
		if feature, ok := out.Features[name]; !ok || !feature.Available {
			return out, errors.New("镜像声明的静态 Nginx 能力不能由编译信息确认: " + name)
		}
	}
	return out, nil
}
func (n *Nginx) runtimeIdentity() string {
	if n.Container != nil {
		return n.Container.Binding.ImageID
	}
	return "native"
}
func (n *Nginx) runPath(name string) string {
	if n.Container != nil {
		return filepath.Join(n.DataDir, "run", "nginx", name)
	}
	return filepath.Join(n.DataDir, "run", name)
}

// Certificates remain root-owned and immutable to Nginx. Only the dedicated
// Nginx group receives traversal/read access; the Web user is never in it.
func (n *Nginx) certificateDirectory(dir string) error {
	if n.Container == nil {
		return secure.RootDirectory(dir, 0700)
	}
	root := filepath.Join(n.DataDir, "certificates")
	if dir != root && !strings.HasPrefix(dir, root+"/") {
		return errors.New("证书目录不属于受管空间")
	}
	var chain []string
	for at := dir; ; at = filepath.Dir(at) {
		chain = append(chain, at)
		if at == root {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if err := secure.RootDirectory(chain[i], 0750); err != nil {
			return err
		}
		if err := os.Chown(chain[i], 0, n.gid); err != nil {
			return err
		}
		if err := os.Chmod(chain[i], 0750); err != nil {
			return err
		}
	}
	return nil
}
