package releases

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nginxpanel/internal/protocol"
)

type ImageInput struct {
	TrustPath, ManifestPath, SignaturePath string
	ExpectedManifestSHA256                 string
	AllowPrerelease                        bool
}

// ImageApproval belongs to an immutable, root-owned deployment binding. The
// timestamp and historical trust hash must never be supplied by a Web request.
// Running an approved image does not require retaining the offline input files.
type ImageApproval struct {
	Schema         int         `json:"schema"`
	Repository     string      `json:"repository"`
	Version        string      `json:"version"`
	Commit         string      `json:"commit"`
	KeyID          string      `json:"key_id"`
	ManifestSHA256 string      `json:"manifest_sha256"`
	TrustSHA256    string      `json:"trust_sha256"`
	TrustPath      string      `json:"trust_path"`
	Prerelease     bool        `json:"prerelease"`
	ApprovedAt     int64       `json:"approved_at"`
	Image          ImageChoice `json:"image"`
}

func (a ImageApproval) Validate(component, reference, config, launcher string) error {
	p, f := a.Image.Platform, a.Image.Evidence
	prefix := imageRepository(a.Repository, component) + "@"
	if a.Schema != Schema || !repository.MatchString(a.Repository) || !validVersion(a.Version) || !validCommit(a.Commit) || !identifier.MatchString(a.KeyID) || !validHash(a.ManifestSHA256) || !validHash(a.TrustSHA256) || len(a.TrustPath) > 512 || !filepath.IsAbs(a.TrustPath) || filepath.Clean(a.TrustPath) != a.TrustPath || a.ApprovedAt <= 0 || a.ApprovedAt > time.Now().Unix()+300 || (component != "panel-launcher" && component != "nginx") || a.Image.ID != component || a.Image.Reference != reference || !strings.HasPrefix(reference, prefix) || !imageDigest(strings.TrimPrefix(reference, prefix)) || p.OS != "linux" || p.Architecture != runtime.GOARCH || !imageDigest(p.Digest) || !imageDigest(p.ConfigDigest) || p.ConfigDigest != config || !validHash(p.LauncherSHA256) || p.LauncherSHA256 != launcher || f.Path != component+".oci.json" || !validHash(f.SHA256) || f.Size <= 0 || f.Size > MaxImageEvidenceBytes || f.Mode != 0644 {
		return errors.New("镜像签名批准记录与本机运行绑定不一致")
	}
	return nil
}

// AdmitImage authenticates a new admission at the current time. A retry may use
// only the original approval read from a root-owned immutable binding: it still
// checks current local keys, so removing a signing key blocks that retry.
func AdmitImage(in ImageInput, component, reference string, prior *ImageApproval) (ImageApproval, Asset, error) {
	var out ImageApproval
	if in.TrustPath == "" || in.ManifestPath == "" || in.SignaturePath == "" {
		return out, Asset{}, errors.New("镜像准入须提供本机信任、发行清单与签名信封")
	}
	at := time.Now().Unix()
	if prior != nil {
		if err := prior.Validate(component, reference, prior.Image.Platform.ConfigDigest, prior.Image.Platform.LauncherSHA256); err != nil {
			return out, Asset{}, err
		}
		if prior.TrustPath != in.TrustPath || prior.Prerelease != in.AllowPrerelease {
			return out, Asset{}, errors.New("续装不能改变镜像信任位置或预发布授权")
		}
		at = prior.ApprovedAt
	}
	// These images carry static Linux programs; host distribution libraries are
	// not an admission dependency. The catalog must contain that static package.
	input := Input{TrustPath: in.TrustPath, ManifestPath: in.ManifestPath, SignaturePath: in.SignaturePath, AllowPrerelease: in.AllowPrerelease,
		Host:     Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: "any", Version: "any"},
		Receiver: Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: LauncherVersion},
		Assets:   []string{"panel-linux-" + runtime.GOARCH}, AllowedComponents: []string{"panel"}}
	v, err := verifyAt(input, at)
	if err != nil {
		return out, Asset{}, err
	}
	p := v.Plan()
	if in.ExpectedManifestSHA256 != "" && (!validHash(in.ExpectedManifestSHA256) || p.ManifestSHA256 != in.ExpectedManifestSHA256) {
		return out, Asset{}, ErrReleaseChanged
	}
	for _, image := range p.Manifest.Images {
		if image.ID != component || image.Repository+"@"+image.Digest != reference {
			continue
		}
		for _, platform := range image.Platforms {
			if platform.OS != runtime.GOOS || platform.Architecture != runtime.GOARCH {
				continue
			}
			out = ImageApproval{Schema: Schema, Repository: p.Manifest.Repository, Version: p.Manifest.Version, Commit: image.Commit, KeyID: p.KeyID,
				ManifestSHA256: p.ManifestSHA256, TrustSHA256: p.TrustSHA256, TrustPath: in.TrustPath, Prerelease: in.AllowPrerelease, ApprovedAt: at,
				Image: ImageChoice{ID: component, Reference: reference, Platform: platform, Evidence: image.Evidence}}
		}
	}
	if out.Schema == 0 {
		return out, Asset{}, errors.New("签名发行未批准此镜像摘要或当前架构")
	}
	if err := out.Validate(component, reference, out.Image.Platform.ConfigDigest, out.Image.Platform.LauncherSHA256); err != nil {
		return ImageApproval{}, Asset{}, err
	}
	if prior != nil {
		// Keep original admission evidence while authenticating with current keys.
		out.TrustSHA256 = prior.TrustSHA256
		if out != *prior {
			return ImageApproval{}, Asset{}, errors.New("镜像发行身份与原批准记录不一致")
		}
	}
	for _, asset := range p.Assets {
		if asset.ID == "panel-linux-"+runtime.GOARCH && asset.ABI == "static" && asset.Distribution == "any" && asset.DistributionVersion == "any" && p.Manifest.FrontendVersion == asset.Version {
			return out, asset, nil
		}
	}
	return ImageApproval{}, Asset{}, errors.New("镜像缺少同版静态面板和前端发行资产")
}
