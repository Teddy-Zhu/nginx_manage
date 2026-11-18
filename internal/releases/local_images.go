package releases

import (
	"errors"
	"path/filepath"
	"runtime"
	"time"
)

// ContainerPackage inventories the prebuilt Nginx image shipped in an installer.
// Registry releases continue to use publisher signatures and OCI attestations.
type ContainerPackage struct {
	Schema           int               `json:"schema"`
	Version          string            `json:"version"`
	NginxVersion     string            `json:"nginx_version,omitempty"`
	Architecture     string            `json:"architecture"`
	BinarySHA256     string            `json:"binary_sha256"`
	LauncherProtocol int               `json:"launcher_protocol"`
	Images           map[string]string `json:"images"`
}

func (a ImageApproval) validateLocal(component, reference, imageID, launcher string) error {
	p, f := a.Image.Platform, a.Image.Evidence
	if a.Schema != Schema || !validVersion(a.Version) || a.Repository != "" || a.Commit != "" || a.KeyID != "" || !validHash(a.ManifestSHA256) || a.TrustSHA256 != a.ManifestSHA256 || !filepath.IsAbs(a.TrustPath) || filepath.Clean(a.TrustPath) != a.TrustPath || len(a.TrustPath) > 512 || a.ApprovedAt <= 0 || a.ApprovedAt > time.Now().Unix()+300 || component != "nginx" || a.Image.ID != component || a.Image.Reference != reference || !imageDigest(reference) || reference != imageID || reference != p.ConfigDigest || p.Digest != "" || p.OS != "linux" || p.Architecture != runtime.GOARCH || p.LauncherProtocol != LauncherVersion || !validHash(launcher) || p.LauncherSHA256 != launcher || f.Path != "containers.json" || f.SHA256 != a.ManifestSHA256 || f.Size <= 0 || f.Size > 2<<20 || f.Mode != 0644 || a.Prerelease {
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
	if pkg.Schema != 1 || !validVersion(pkg.Version) || pkg.Architecture != runtime.GOARCH || !validHash(pkg.BinarySHA256) || pkg.LauncherProtocol != LauncherVersion || len(pkg.Images) != 1 || !imageDigest(pkg.Images["nginx"]) || component != "nginx" || pkg.Images[component] != reference {
		return out, Asset{}, errors.New("容器安装包版本、架构或内容清单无效")
	}
	digest := hash(raw)
	out = ImageApproval{LocalBuild: true, Schema: Schema, Version: pkg.Version, ManifestSHA256: digest, TrustSHA256: digest, TrustPath: in.LocalManifestPath, ApprovedAt: time.Now().Unix(),
		Image: ImageChoice{ID: component, Reference: reference, Platform: ImagePlatform{OS: "linux", Architecture: pkg.Architecture, ConfigDigest: reference, LauncherProtocol: pkg.LauncherProtocol, LauncherSHA256: pkg.BinarySHA256}, Evidence: File{Path: "containers.json", SHA256: digest, Size: int64(len(raw)), Mode: 0644}}}
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
	return out, Asset{}, nil
}
