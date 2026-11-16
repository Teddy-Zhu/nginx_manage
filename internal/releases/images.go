package releases

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxImageEvidenceBytes = 32 << 20

func ImageToken(id string) (string, bool) {
	if id == "nginx" {
		return "image-nginx", true
	}
	return "", false
}

func ImageIDFromToken(token string) (string, bool) {
	if token == "image-nginx" {
		return "nginx", true
	}
	return "", false
}

func imageAllowedComponent(id string) string {
	return id
}

func PlanImage(plan Plan, token string) (ImageChoice, bool) {
	id, ok := ImageIDFromToken(token)
	if !ok || !slices.Contains(plan.Selected, token) {
		return ImageChoice{}, false
	}
	for _, image := range plan.Manifest.Images {
		if image.ID != id {
			continue
		}
		for _, platform := range image.Platforms {
			if platform.OS == plan.Host.OS && platform.Architecture == plan.Host.Architecture {
				return ImageChoice{ID: id, Reference: image.Repository + "@" + image.Digest, Platform: platform, Evidence: image.Evidence}, true
			}
		}
	}
	return ImageChoice{}, false
}

type ImagePlatform struct {
	OS               string `json:"os"`
	Architecture     string `json:"architecture"`
	Digest           string `json:"digest"`
	ConfigDigest     string `json:"config_digest"`
	LauncherSHA256   string `json:"launcher_sha256,omitempty"`
	LauncherProtocol int    `json:"launcher_protocol"`
}

// The index digest authenticates the platform manifests and their attached
// attestations. Evidence contains only metadata, never executable image layers.
type ContainerImage struct {
	ID         string          `json:"id"`
	Repository string          `json:"repository"`
	Version    string          `json:"version"`
	Commit     string          `json:"commit"`
	Digest     string          `json:"digest"`
	Platforms  []ImagePlatform `json:"platforms"`
	Evidence   File            `json:"evidence"`
}

type imagePublication struct {
	Schema     int              `json:"schema"`
	Repository string           `json:"repository"`
	Version    string           `json:"version"`
	Commit     string           `json:"commit"`
	Images     []ContainerImage `json:"images"`
}

type imageBlob struct {
	Digest string `json:"digest"`
	Data   []byte `json:"data"`
}
type imageEvidence struct {
	Schema int         `json:"schema"`
	Index  []byte      `json:"index"`
	Blobs  []imageBlob `json:"blobs"`
}
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
	Platform    struct {
		OS, Architecture, Variant string
	} `json:"platform"`
}
type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	ArtifactType  string          `json:"artifactType"`
	Manifests     []ociDescriptor `json:"manifests"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
	Subject       *ociDescriptor  `json:"subject"`
}

func imageRepository(repo, id string) string {
	return "ghcr.io/" + strings.ToLower(repo) + "/nginx"
}
func imageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validHash(strings.TrimPrefix(value, "sha256:"))
}
func validateImages(m Manifest) error {
	if len(m.Images) > 1 {
		return errors.New("发行仅允许包含 Nginx 容器镜像")
	}
	seen := map[string]bool{}
	commit := ""
	for _, image := range m.Images {
		if image.ID != "nginx" || seen[image.ID] || image.Repository != imageRepository(m.Repository, image.ID) || image.Version != m.Version || !validCommit(image.Commit) || commit != "" && commit != image.Commit || !imageDigest(image.Digest) || len(image.Platforms) != 2 {
			return errors.New("镜像身份、版本、提交、摘要或平台无效")
		}
		seen[image.ID], commit = true, image.Commit
		architectures := map[string]bool{}
		for _, p := range image.Platforms {
			if p.OS != "linux" || !slices.Contains([]string{"amd64", "arm64"}, p.Architecture) || architectures[p.Architecture] || !imageDigest(p.Digest) || !imageDigest(p.ConfigDigest) || p.LauncherProtocol != LauncherVersion || p.LauncherSHA256 != "" {
				return errors.New("镜像须分别固定 Linux amd64/arm64 的 manifest 和 config 摘要")
			}
			architectures[p.Architecture] = true
		}
		f := image.Evidence
		if f.Path != image.ID+".oci.json" || !validHash(f.SHA256) || f.Size <= 0 || f.Size > MaxImageEvidenceBytes || f.Mode != 0644 {
			return errors.New("镜像 OCI 证据文件无效")
		}
	}
	return nil
}

func cloneImages(images []ContainerImage) []ContainerImage {
	out := slices.Clone(images)
	for i := range out {
		out[i].Platforms = slices.Clone(out[i].Platforms)
	}
	return out
}

func publicationImages(in PublishInput, spec PublicationSpec, manifest Manifest) ([]ContainerImage, map[string][]byte, error) {
	if in.ImagesPath == "" {
		return nil, nil, errors.New("正式发行必须包含 Nginx 容器镜像")
	}
	raw, err := readPublicationFile(in.ImagesPath, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	var publication imagePublication
	if err := strictJSON(raw, &publication); err != nil {
		return nil, nil, err
	}
	if publication.Schema != Schema || publication.Repository != in.Repository || publication.Version != in.Version || publication.Commit != in.Commit || len(publication.Images) != 1 || publication.Images[0].ID != "nginx" {
		return nil, nil, errors.New("镜像发布输入与批准的源码身份不一致")
	}
	m := manifest
	m.Images = publication.Images
	if err := validateImages(m); err != nil {
		return nil, nil, err
	}
	evidence := map[string][]byte{}
	for _, image := range m.Images {
		if image.Commit != spec.Commit {
			return nil, nil, errors.New("镜像提交与归档提交不一致")
		}
		data, err := readPublicationFile(filepath.Join(filepath.Dir(in.ImagesPath), image.Evidence.Path), MaxImageEvidenceBytes)
		if err != nil {
			return nil, nil, err
		}
		if int64(len(data)) != image.Evidence.Size || hash(data) != image.Evidence.SHA256 {
			return nil, nil, errors.New("镜像证据长度或散列不匹配")
		}
		if err := inspectImageEvidence(data, image, m.Repository); err != nil {
			return nil, nil, fmt.Errorf("镜像 %s：%w", image.ID, err)
		}
		evidence[image.Evidence.Path] = data
	}
	return m.Images, evidence, nil
}

func inspectImageEvidence(raw []byte, image ContainerImage, repository string) error {
	var evidence imageEvidence
	if err := strictJSON(raw, &evidence); err != nil {
		return err
	}
	if evidence.Schema != Schema || len(evidence.Index) == 0 || len(evidence.Index) > 64<<10 || "sha256:"+hash(evidence.Index) != image.Digest || len(evidence.Blobs) == 0 || len(evidence.Blobs) > 24 {
		return errors.New("OCI 索引或元数据数量无效")
	}
	blobs, used := map[string][]byte{}, map[string]bool{}
	for _, b := range evidence.Blobs {
		if !imageDigest(b.Digest) || len(b.Data) == 0 || len(b.Data) > 16<<20 || "sha256:"+hash(b.Data) != b.Digest || blobs[b.Digest] != nil {
			return errors.New("OCI 元数据摘要、长度或唯一性无效")
		}
		blobs[b.Digest] = b.Data
	}
	read := func(d ociDescriptor, out any, strict bool) error {
		data := blobs[d.Digest]
		if !imageDigest(d.Digest) || d.Size <= 0 || d.Size > 16<<20 || int64(len(data)) != d.Size {
			return errors.New("OCI 描述符未匹配完整元数据")
		}
		used[d.Digest] = true
		if strict {
			return decodeJSON(data, out, false)
		}
		// SPDX file inventories may exceed the release manifest's token count.
		if !utf8.Valid(data) {
			return errors.New("OCI 证据 JSON 编码无效")
		}
		return json.Unmarshal(data, out)
	}
	var index ociManifest
	if err := decodeJSON(evidence.Index, &index, false); err != nil {
		return err
	}
	if index.SchemaVersion != 2 || index.MediaType != "application/vnd.oci.image.index.v1+json" || len(index.Manifests) != 4 {
		return errors.New("OCI 索引须包含两个运行平台及各自的证据 manifest")
	}
	platforms, attestations := map[string]ociDescriptor{}, map[string]ociDescriptor{}
	for _, d := range index.Manifests {
		if d.MediaType != "application/vnd.oci.image.manifest.v1+json" {
			return errors.New("OCI 索引包含不支持的 manifest 类型")
		}
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			target := d.Annotations["vnd.docker.reference.digest"]
			if d.Platform.OS != "unknown" || d.Platform.Architecture != "unknown" || !imageDigest(target) || attestations[target].Digest != "" {
				return errors.New("OCI 证据的平台关联无效")
			}
			attestations[target] = d
		} else {
			if d.Platform.OS != "linux" || !slices.Contains([]string{"amd64", "arm64"}, d.Platform.Architecture) || d.Platform.Variant != "" && (d.Platform.Architecture != "arm64" || d.Platform.Variant != "v8") || platforms[d.Platform.Architecture].Digest != "" {
				return errors.New("OCI 运行平台重复或无效")
			}
			platforms[d.Platform.Architecture] = d
		}
	}
	for _, p := range image.Platforms {
		d := platforms[p.Architecture]
		var manifest ociManifest
		if d.Digest != p.Digest || read(d, &manifest, true) != nil || manifest.SchemaVersion != 2 || manifest.MediaType != d.MediaType || manifest.Config.MediaType != "application/vnd.oci.image.config.v1+json" || manifest.Config.Digest != p.ConfigDigest || len(manifest.Layers) == 0 || len(manifest.Layers) > 64 || manifest.ArtifactType != "" || manifest.Subject != nil {
			return errors.New("OCI 平台 manifest 与签名描述不匹配")
		}
		for _, layer := range manifest.Layers {
			if !imageDigest(layer.Digest) || layer.Size <= 0 || layer.Size > 2<<30 || !slices.Contains([]string{"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"}, layer.MediaType) {
				return errors.New("OCI 运行层描述符无效")
			}
		}
		var config struct {
			OS, Architecture string
			Config           struct{ Labels map[string]string }
		}
		if err := read(manifest.Config, &config, true); err != nil {
			return err
		}
		labels := config.Config.Labels
		if config.OS != p.OS || config.Architecture != p.Architecture || labels["org.opencontainers.image.source"] != "https://github.com/"+repository || labels["org.opencontainers.image.revision"] != image.Commit || labels["org.opencontainers.image.version"] != image.Version {
			return errors.New("OCI 配置的源码、版本或架构不一致")
		}
		launcherProtocol, err := strconv.Atoi(labels["org.nginxpanel.launcher.protocol"])
		if err != nil || launcherProtocol != p.LauncherProtocol || launcherProtocol != LauncherVersion {
			return errors.New("OCI launcher 协议与受支持版本不一致")
		}
		if labels["org.nginxpanel.launcher.sha256"] != "" {
			return errors.New("OCI Nginx 镜像不得绑定独立发布的面板二进制")
		}
		var attestation ociManifest
		a := attestations[p.Digest]
		if read(a, &attestation, true) != nil || attestation.SchemaVersion != 2 || attestation.MediaType != a.MediaType || attestation.ArtifactType != "application/vnd.docker.attestation.manifest.v1+json" || attestation.Subject == nil || attestation.Subject.Digest != p.Digest || attestation.Subject.Size != d.Size || attestation.Subject.MediaType != d.MediaType || len(attestation.Layers) != 2 {
			return errors.New("OCI 平台缺少明确绑定的 SBOM 和来源证据")
		}
		// BuildKit's OCI artifact config is an empty JSON object.
		var empty map[string]json.RawMessage
		if attestation.Config.MediaType != "application/vnd.oci.empty.v1+json" || read(attestation.Config, &empty, true) != nil || empty == nil || len(empty) != 0 {
			return errors.New("OCI 证据 config 无效")
		}
		predicates := map[string]bool{}
		for _, layer := range attestation.Layers {
			var statement struct {
				Type          string `json:"_type"`
				PredicateType string `json:"predicateType"`
				Subject       []struct {
					Digest map[string]string `json:"digest"`
				} `json:"subject"`
				Predicate json.RawMessage `json:"predicate"`
			}
			if layer.MediaType != "application/vnd.in-toto+json" || read(layer, &statement, false) != nil || !slices.Contains([]string{"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}, statement.Type) || len(statement.Subject) != 1 || statement.Subject[0].Digest["sha256"] != strings.TrimPrefix(p.Digest, "sha256:") || layer.Annotations["in-toto.io/predicate-type"] != statement.PredicateType || predicates[statement.PredicateType] {
				return errors.New("OCI in-toto 证据与运行镜像不匹配")
			}
			predicates[statement.PredicateType] = true
			switch statement.PredicateType {
			case "https://spdx.dev/Document":
				var spdx struct {
					Version  string            `json:"spdxVersion"`
					ID       string            `json:"SPDXID"`
					Packages []json.RawMessage `json:"packages"`
				}
				if json.Unmarshal(statement.Predicate, &spdx) != nil || spdx.Version != "SPDX-2.3" || spdx.ID != "SPDXRef-DOCUMENT" || len(spdx.Packages) == 0 || len(spdx.Packages) > 20000 {
					return errors.New("镜像缺少非空 SPDX 2.3 清单")
				}
			case "https://slsa.dev/provenance/v0.2":
				var provenance struct {
					BuildType   string `json:"buildType"`
					BuildConfig struct {
						LLBDefinition []json.RawMessage `json:"llbDefinition"`
					} `json:"buildConfig"`
				}
				if decodeJSON(statement.Predicate, &provenance, false) != nil || provenance.BuildType != "https://mobyproject.org/buildkit@v1" || len(provenance.BuildConfig.LLBDefinition) == 0 {
					return errors.New("镜像缺少 BuildKit mode=max 构建来源")
				}
			default:
				return errors.New("镜像证据类型不在批准范围")
			}
		}
		if !predicates["https://spdx.dev/Document"] || !predicates["https://slsa.dev/provenance/v0.2"] {
			return errors.New("镜像证据不完整")
		}
	}
	if len(used) != len(blobs) {
		return errors.New("OCI 证据包含未被镜像索引引用的数据")
	}
	return nil
}

type ImageChoice struct {
	ID        string        `json:"id"`
	Reference string        `json:"reference"`
	Platform  ImagePlatform `json:"platform"`
	Evidence  File          `json:"evidence"`
}
type ImageVerification struct {
	State          string        `json:"state"`
	Repository     string        `json:"repository"`
	Version        string        `json:"version"`
	ManifestSHA256 string        `json:"manifest_sha256"`
	TrustSHA256    string        `json:"trust_sha256"`
	KeyID          string        `json:"key_id"`
	Images         []ImageChoice `json:"images"`
}

// VerifyImages authenticates the catalog with the existing local trust root.
// It neither contacts a registry nor pulls, approves, binds or starts an image.
func VerifyImages(in Input) (ImageVerification, error) {
	in.Assets, in.Components, in.AllowedComponents = nil, nil, nil
	in.ImageCatalog = true
	verified, err := Verify(in)
	if err != nil {
		return ImageVerification{}, err
	}
	p := verified.Plan()
	out := ImageVerification{State: "images_verified", Repository: p.Manifest.Repository, Version: p.Manifest.Version, ManifestSHA256: p.ManifestSHA256, TrustSHA256: p.TrustSHA256, KeyID: p.KeyID}
	for _, token := range p.Selected {
		choice, ok := PlanImage(p, token)
		if ok {
			out.Images = append(out.Images, choice)
		}
	}
	return out, nil
}
