package releases

import (
	"errors"
	"path/filepath"
	"runtime"
	"time"
)

// ContainerPackage is the content inventory shipped inside a complete installer.
// Root approves this local input just as it approves the installer program itself.
// Registry releases continue to use publisher signatures and OCI attestations.
type ContainerPackage struct {
	Schema       int               `json:"schema"`
	Version      string            `json:"version"`
	Architecture string            `json:"architecture"`
	BinarySHA256 string            `json:"binary_sha256"`
	Images       map[string]string `json:"images"`
	Web          []File            `json:"web"`
}

func (a ImageApproval) validateLocal(component, reference, imageID, launcher string) error {
	p, f := a.Image.Platform, a.Image.Evidence
	if a.Schema != Schema || !validVersion(a.Version) || a.Repository != "" || a.Commit != "" || a.KeyID != "" || !validHash(a.ManifestSHA256) || a.TrustSHA256 != a.ManifestSHA256 || !filepath.IsAbs(a.TrustPath) || filepath.Clean(a.TrustPath) != a.TrustPath || len(a.TrustPath) > 512 || a.ApprovedAt <= 0 || a.ApprovedAt > time.Now().Unix()+300 || (component != "panel-launcher" && component != "nginx") || a.Image.ID != component || a.Image.Reference != reference || !imageDigest(reference) || reference != imageID || reference != p.ConfigDigest || p.Digest != "" || p.OS != "linux" || p.Architecture != runtime.GOARCH || !validHash(launcher) || p.LauncherSHA256 != launcher || f.Path != "containers.json" || f.SHA256 != a.ManifestSHA256 || f.Size <= 0 || f.Size > 2<<20 || f.Mode != 0644 || a.Prerelease {
		return errors.New("本地安装包与容器内容绑定不一致")
	}
	return nil
}

func admitLocalImage(in ImageInput, component, reference string, prior *ImageApproval) (ImageApproval, Asset, error) {
	var out ImageApproval
	if in.ManifestPath != "" || in.SignaturePath != "" || in.ExpectedManifestSHA256 != "" || in.AllowPrerelease {
		return out, Asset{}, errors.New("本地安装包不能混用远程发行批准参数")
	}
	raw, err := readRoot(in.LocalManifestPath, 2<<20)
	if err != nil {
		return out, Asset{}, err
	}
	var pkg ContainerPackage
	if err = decodeJSON(raw, &pkg, true); err != nil {
		return out, Asset{}, err
	}
	if pkg.Schema != 1 || !validVersion(pkg.Version) || pkg.Architecture != runtime.GOARCH || !validHash(pkg.BinarySHA256) || len(pkg.Images) != 2 || !imageDigest(pkg.Images["panel-launcher"]) || !imageDigest(pkg.Images["nginx"]) || pkg.Images[component] != reference || len(pkg.Web) == 0 || len(pkg.Web) > 4096 {
		return out, Asset{}, errors.New("容器安装包版本、架构或内容清单无效")
	}
	seen := map[string]bool{}
	for _, f := range pkg.Web {
		if !safePath(f.Path) || len(f.Path) <= len("web/") || f.Path[:4] != "web/" || !validHash(f.SHA256) || f.Size < 0 || f.Size > 32<<20 || f.Mode != 0644 || seen[f.Path] {
			return out, Asset{}, errors.New("安装包前端文件清单无效")
		}
		seen[f.Path] = true
	}
	if !seen["web/index.html"] {
		return out, Asset{}, errors.New("安装包缺少前端入口")
	}
	digest := hash(raw)
	out = ImageApproval{LocalBuild: true, Schema: Schema, Version: pkg.Version, ManifestSHA256: digest, TrustSHA256: digest, TrustPath: in.LocalManifestPath, ApprovedAt: time.Now().Unix(),
		Image: ImageChoice{ID: component, Reference: reference, Platform: ImagePlatform{OS: "linux", Architecture: pkg.Architecture, ConfigDigest: reference, LauncherSHA256: pkg.BinarySHA256}, Evidence: File{Path: "containers.json", SHA256: digest, Size: int64(len(raw)), Mode: 0644}}}
	if prior != nil {
		if err = prior.validateLocal(component, reference, reference, pkg.BinarySHA256); err != nil {
			return ImageApproval{}, Asset{}, err
		}
		out.ApprovedAt = prior.ApprovedAt
		if out != *prior {
			return ImageApproval{}, Asset{}, errors.New("续装不能更改已批准的本地容器安装包")
		}
	}
	if err = out.Validate(component, reference, reference, pkg.BinarySHA256); err != nil {
		return ImageApproval{}, Asset{}, err
	}
	return out, Asset{Version: pkg.Version, Files: pkg.Web}, nil
}
