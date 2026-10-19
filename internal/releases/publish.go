package releases

import (
	"context"
	"crypto/ed25519"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/protocol"
	"nginxpanel/migrations"
)

type PackageSource struct {
	Directory       string   `json:"directory"`
	Asset           Asset    `json:"asset"`
	ExecutableFiles []string `json:"executable_files"`
}
type PublicationSpec struct {
	Commit   string          `json:"commit"`
	Manifest Manifest        `json:"manifest"`
	Packages []PackageSource `json:"packages"`
}
type PublishInput struct {
	InputRoot, SpecPath, Output, KeyPath, KeyID, PublicKey string
	Repository, Version, Commit                            string
	ImagesPath                                             string
}
type PublicationResult struct {
	State          string `json:"state"`
	Directory      string `json:"directory"`
	Repository     string `json:"repository"`
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Key            Key    `json:"key"`
}
type BuildProvenance struct {
	Schema        int                    `json:"schema"`
	Repository    string                 `json:"repository"`
	Version       string                 `json:"version"`
	Commit        string                 `json:"commit"`
	Asset         string                 `json:"asset"`
	Scope         string                 `json:"scope"`
	GoVersion     string                 `json:"go_version,omitempty"`
	NodeVersion   string                 `json:"node_version,omitempty"`
	PNPMVersion   string                 `json:"pnpm_version,omitempty"`
	GoSumSHA256   string                 `json:"go_sum_sha256,omitempty"`
	WebLockSHA256 string                 `json:"web_lock_sha256,omitempty"`
	BinarySHA256  string                 `json:"binary_sha256,omitempty"`
	WorkflowRun   string                 `json:"workflow_run"`
	NativeNginx   *NativeNginxProvenance `json:"native_nginx,omitempty"`
	Fail2ban      *Fail2banProvenance    `json:"fail2ban,omitempty"`
}

func validCommit(commit string) bool {
	raw, err := hex.DecodeString(commit)
	return err == nil && (len(raw) == 20 || len(raw) == 32) && commit == strings.ToLower(commit)
}

// NewPublication describes matching panel/web and prebuilt native Nginx assets.
func NewPublication(repo, version, commit, notes string) (PublicationSpec, error) {
	if !repository.MatchString(repo) || !validVersion(version) || !validCommit(commit) {
		return PublicationSpec{}, errors.New("发布身份或版本无效")
	}
	if !ValidNotes(notes) || strings.TrimSpace(notes) == "" {
		return PublicationSpec{}, errors.New("发布须包含符合长度和编码限制的非空发行说明")
	}
	databaseSchema, err := migrations.LatestVersion()
	if err != nil {
		return PublicationSpec{}, err
	}
	now := time.Now().Unix()
	channel := "stable"
	if strings.Contains(strings.Split(version, "+")[0], "-") {
		channel = "prerelease"
	}
	spec := PublicationSpec{Commit: commit, Manifest: Manifest{Schema: Schema, Repository: repo, Version: version, Channel: channel, CreatedAt: now, ExpiresAt: now + 365*86400, APIMajor: 1, DatabaseSchema: databaseSchema, MinimumAgentProtocol: protocol.Agent, MinimumLauncher: LauncherVersion, FrontendVersion: version, Notes: notes}}
	for _, arch := range []string{"amd64", "arm64", "any"} {
		id, component, archive := "panel-linux-"+arch, "panel", "nginxpanel_"+version+"_linux_"+arch+".tar.gz"
		executable := []string{"nginxpanel"}
		if arch == "any" {
			id, component, archive, executable = "web", "web", "nginxpanel_"+version+"_web.tar.gz", []string{}
		}
		spec.Packages = append(spec.Packages, PackageSource{Directory: id, ExecutableFiles: executable, Asset: Asset{ID: id, Component: component, Version: version, OS: "linux", Architecture: arch, Distribution: "any", DistributionVersion: "any", ABI: "static", Archive: archive, License: "MIT", LicenseFiles: []string{"LICENSE", "THIRD_PARTY_NOTICES.txt"}, SourceURL: "https://github.com/" + repo + "/tree/" + commit, Maintenance: "maintained"}})
	}
	for _, arch := range []string{"amd64", "arm64"} {
		component, err := nginxPublicationPackage(arch, version)
		if err != nil {
			return PublicationSpec{}, err
		}
		spec.Packages = append(spec.Packages, component)
	}
	fail2ban, err := fail2banPublicationPackage(version)
	if err != nil {
		return PublicationSpec{}, err
	}
	spec.Packages = append(spec.Packages, fail2ban)
	return spec, nil
}

func publicationEvidence(directory string, asset Asset, spec PublicationSpec) (map[string][]byte, error) {
	sbomName, provenanceName := asset.ID+".spdx.json", asset.ID+".provenance.json"
	sbom, err := readPublicationFile(filepath.Join(directory, sbomName), 16<<20)
	if err != nil {
		return nil, err
	}
	var inventory struct {
		Version  string            `json:"spdxVersion"`
		ID       string            `json:"SPDXID"`
		Packages []json.RawMessage `json:"packages"`
	}
	// The SBOM is authenticated data, never an executable instruction. Its much
	// larger package inventory is bounded by bytes instead of manifest token caps.
	if err := json.Unmarshal(sbom, &inventory); err != nil || !utf8.Valid(sbom) || inventory.Version != "SPDX-2.3" || inventory.ID != "SPDXRef-DOCUMENT" || len(inventory.Packages) == 0 || len(inventory.Packages) > 20000 {
		return nil, errors.New("发布资产须包含非空 SPDX 2.3 JSON 依赖清单")
	}
	raw, err := readPublicationFile(filepath.Join(directory, provenanceName), 64<<10)
	if err != nil {
		return nil, err
	}
	var p BuildProvenance
	if err := strictJSON(raw, &p); err != nil {
		return nil, err
	}
	if p.Schema != Schema || p.Repository != spec.Manifest.Repository || p.Version != spec.Manifest.Version || p.Commit != spec.Commit || p.Asset != asset.ID || !text(p.WorkflowRun, 256) {
		return nil, errors.New("发布构建来源与仓库、版本、提交或依赖输入不一致")
	}
	if asset.Component == "nginx" {
		if err := nginxPublicationEvidence(directory, asset, spec, p, sbom); err != nil {
			return nil, err
		}
		return map[string][]byte{sbomName: sbom, provenanceName: raw}, nil
	}
	if asset.Component == "fail2ban" {
		if err := fail2banPublicationEvidence(directory, asset, spec, p, sbom); err != nil {
			return nil, err
		}
		return map[string][]byte{sbomName: sbom, provenanceName: raw}, nil
	}
	if p.NativeNginx != nil || p.Fail2ban != nil || p.Scope != "source-and-build-dependencies" || !text(p.GoVersion, 64) || !text(p.NodeVersion, 64) || !text(p.PNPMVersion, 64) || !validHash(p.GoSumSHA256) || !validHash(p.WebLockSHA256) {
		return nil, errors.New("发布构建来源缺少对应工具链及依赖输入")
	}
	if asset.Component == "panel" {
		var binaryHash string
		for _, f := range asset.Files {
			if f.Path == "nginxpanel" {
				binaryHash = f.SHA256
			}
		}
		if !validHash(p.BinarySHA256) || p.BinarySHA256 != binaryHash {
			return nil, errors.New("构建来源未绑定实际面板二进制")
		}
		info, err := buildinfo.ReadFile(filepath.Join(directory, "nginxpanel"))
		if err != nil {
			return nil, err
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		flags := strings.Fields(settings["-ldflags"])
		versioned := false
		for i, flag := range flags {
			if flag == "-X" && i+1 < len(flags) && flags[i+1] == "main.version="+asset.Version {
				versioned = true
			}
		}
		if info.Path != "nginxpanel/cmd/nginxpanel" || info.Main.Path != "nginxpanel" || info.Main.Replace != nil || info.GoVersion != p.GoVersion || settings["GOOS"] != "linux" || settings["GOARCH"] != asset.Architecture || settings["CGO_ENABLED"] != "0" || settings["vcs.revision"] != spec.Commit || settings["vcs.modified"] != "false" || !versioned {
			return nil, errors.New("面板 Go 构建信息与发布架构、版本或干净提交不一致")
		}
		for _, dep := range info.Deps {
			if dep.Replace != nil {
				return nil, errors.New("正式面板资产不接受模块替换构建")
			}
		}
	} else if p.BinarySHA256 != "" {
		return nil, errors.New("非面板构建来源不得声明面板二进制散列")
	}
	return map[string][]byte{sbomName: sbom, provenanceName: raw}, nil
}

// Publish packages approved inputs and signs their exact manifest. It performs
// no network request, source build, input execution or receiving-host mutation.
func Publish(ctx context.Context, in PublishInput) (PublicationResult, error) {
	if !repository.MatchString(in.Repository) || !validVersion(in.Version) || !validCommit(in.Commit) || !identifier.MatchString(in.KeyID) {
		return PublicationResult{}, errors.New("须明确发布仓库、版本、提交和签名 Key ID")
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(in.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(pub) != in.PublicKey {
		return PublicationResult{}, errors.New("须提供经独立确认的规范 Ed25519 发布公钥")
	}
	if err := publicationParents(filepath.Join(in.InputRoot, ".inspect")); err != nil {
		return PublicationResult{}, err
	}
	if err := publicationParents(in.Output); err != nil {
		return PublicationResult{}, err
	}
	if rel, err := filepath.Rel(in.InputRoot, in.Output); err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return PublicationResult{}, errors.New("发布输出须位于输入树之外")
	}
	if !filepath.IsAbs(in.KeyPath) || filepath.Clean(in.KeyPath) != in.KeyPath {
		return PublicationResult{}, errors.New("发布私钥须为规范绝对路径")
	}
	inputTrees := []string{in.InputRoot, in.Output}
	if in.ImagesPath != "" {
		inputTrees = append(inputTrees, filepath.Dir(in.ImagesPath))
	}
	for _, root := range inputTrees {
		if rel, err := filepath.Rel(root, in.KeyPath); err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return PublicationResult{}, errors.New("发布私钥须位于输入与输出树之外")
		}
	}
	if _, err := os.Lstat(in.Output); err == nil {
		return PublicationResult{}, errors.New("发布输出已存在，不覆盖既有发行记录")
	} else if !os.IsNotExist(err) {
		return PublicationResult{}, err
	}
	raw, err := readPublicationFile(in.SpecPath, MaxPlanBytes)
	if err != nil {
		return PublicationResult{}, err
	}
	var spec PublicationSpec
	if err := strictJSON(raw, &spec); err != nil {
		return PublicationResult{}, err
	}
	m, now := spec.Manifest, time.Now().Unix()
	databaseSchema, err := migrations.LatestVersion()
	if err != nil {
		return PublicationResult{}, err
	}
	if spec.Commit != in.Commit || m.Schema != Schema || m.Repository != in.Repository || m.Version != in.Version || !validVersion(m.FrontendVersion) || !ValidNotes(m.Notes) || strings.TrimSpace(m.Notes) == "" || m.APIMajor != 1 || m.DatabaseSchema != databaseSchema || m.MinimumAgentProtocol != protocol.Agent || m.MinimumLauncher != LauncherVersion || m.CreatedAt <= 0 || m.CreatedAt > now+300 || m.ExpiresAt <= now || m.ExpiresAt <= m.CreatedAt || m.ExpiresAt-m.CreatedAt > 2*366*86400 || m.AutomaticRollback || len(m.Assets) != 0 || len(m.Images) != 0 || len(spec.Packages) == 0 || len(spec.Packages) > 16 {
		return PublicationResult{}, errors.New("发布清单身份、有效期、协议或回滚条件不满足")
	}
	if m.Channel != "stable" && m.Channel != "prerelease" || m.Channel == "stable" && strings.Contains(strings.Split(m.Version, "+")[0], "-") {
		return PublicationResult{}, errors.New("发布渠道与版本不一致")
	}
	stage, err := os.MkdirTemp(filepath.Dir(in.Output), ".publish-*")
	if err != nil {
		return PublicationResult{}, err
	}
	defer func() {
		if err := os.RemoveAll(stage); err != nil {
			slog.Error("清理本次发布暂存失败", "path", stage, "error", err)
		}
	}()
	if err := os.Chmod(stage, 0700); err != nil {
		return PublicationResult{}, err
	}
	evidence := map[string][]byte{}
	names := map[string]bool{"release-manifest.json": true, "release-manifest.sig": true, "checksums.txt": true}
	budget := int64(MaxManifestBytes + (64 << 10))
	fileCount := 0
	for _, source := range spec.Packages {
		if err := ctx.Err(); err != nil {
			return PublicationResult{}, err
		}
		a := source.Asset
		if !identifier.MatchString(a.ID) || !safePath(source.Directory) || !safePath(a.Archive) || strings.Contains(a.Archive, "/") || !strings.HasSuffix(a.Archive, ".tar.gz") || names[a.Archive] || len(a.Files) != 0 || a.Size != 0 || a.UnpackedBytes != 0 || a.SHA256 != "" || len(source.ExecutableFiles) > 64 {
			return PublicationResult{}, errors.New("发布源目录、归档名称或计算字段无效")
		}
		names[a.Archive] = true
		directory := filepath.Join(in.InputRoot, source.Directory)
		a.Files, a.UnpackedBytes, err = publicationFiles(ctx, directory, source.ExecutableFiles)
		if err != nil {
			return PublicationResult{}, err
		}
		fileCount += len(a.Files)
		if fileCount > MaxFiles {
			return PublicationResult{}, errors.New("发行文件清单合计超过 4096 项")
		}
		if err := inspectEntry(directory, a); err != nil {
			return PublicationResult{}, err
		}
		records, err := publicationEvidence(directory, a, spec)
		if err != nil {
			return PublicationResult{}, err
		}
		for name, data := range records {
			if names[name] {
				return PublicationResult{}, errors.New("发布证据文件名称重复")
			}
			bound := false
			for _, file := range a.Files {
				if file.Path == name && file.Size == int64(len(data)) && file.SHA256 == hash(data) && file.Mode == 0644 {
					bound = true
				}
			}
			if !bound {
				return PublicationResult{}, errors.New("发布证据在扫描后发生变化或未绑定到归档清单")
			}
			names[name], evidence[name] = true, data
			budget += int64(len(data))
		}
		a.Size, a.SHA256, err = packPublication(ctx, filepath.Join(stage, a.Archive), directory, a)
		if err != nil {
			return PublicationResult{}, err
		}
		if err := validateAsset(a); err != nil {
			return PublicationResult{}, err
		}
		budget += a.Size + a.UnpackedBytes
		if budget > MaxStoreBytes {
			return PublicationResult{}, errors.New("整次发布的输入与输出超过 2 GiB")
		}
		m.Assets = append(m.Assets, a)
	}
	var imageEvidence map[string][]byte
	m.Images, imageEvidence, err = publicationImages(in, spec, m)
	if err != nil {
		return PublicationResult{}, err
	}
	for name, data := range imageEvidence {
		if names[name] {
			return PublicationResult{}, errors.New("镜像证据与既有发行文件重名")
		}
		names[name], evidence[name] = true, data
		budget += int64(len(data))
	}
	if budget > MaxStoreBytes {
		return PublicationResult{}, errors.New("整次发布的输入与输出超过 2 GiB")
	}
	if _, err := manifestCatalog(m); err != nil {
		return PublicationResult{}, err
	}
	slices.SortFunc(m.Assets, func(a, b Asset) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(m.Images, func(a, b ContainerImage) int { return strings.Compare(a.ID, b.ID) })
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return PublicationResult{}, err
	}
	manifest = append(manifest, '\n')
	if len(manifest) > MaxManifestBytes {
		return PublicationResult{}, errors.New("发布清单超过 2 MiB")
	}
	private, err := signingKey(in.KeyPath)
	if err != nil {
		return PublicationResult{}, err
	}
	defer clear(private)
	if base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) != in.PublicKey {
		return PublicationResult{}, errors.New("发布私钥与独立配置的公钥不匹配")
	}
	signature := ed25519.Sign(private, append([]byte(SignatureDomain), manifest...))
	if !ed25519.Verify(pub, append([]byte(SignatureDomain), manifest...), signature) {
		return PublicationResult{}, errors.New("生成的发布签名未通过公钥验证")
	}
	sig, err := json.Marshal(Signature{Schema: Schema, KeyID: in.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		return PublicationResult{}, err
	}
	evidence["release-manifest.json"], evidence["release-manifest.sig"] = manifest, append(sig, '\n')
	for name, data := range evidence {
		if err := writePublicationFile(filepath.Join(stage, name), data); err != nil {
			return PublicationResult{}, err
		}
	}
	checksums := map[string]string{}
	for _, a := range m.Assets {
		checksums[a.Archive] = a.SHA256
	}
	for name, data := range evidence {
		checksums[name] = hash(data)
	}
	ordered := make([]string, 0, len(checksums))
	for name := range checksums {
		ordered = append(ordered, name)
	}
	slices.Sort(ordered)
	var lines strings.Builder
	for _, name := range ordered {
		fmt.Fprintf(&lines, "%s  %s\n", checksums[name], name)
	}
	if err := writePublicationFile(filepath.Join(stage, "checksums.txt"), []byte(lines.String())); err != nil {
		return PublicationResult{}, err
	}
	if err := syncTree(stage); err != nil {
		return PublicationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PublicationResult{}, err
	}
	if time.Now().Unix() >= m.ExpiresAt {
		return PublicationResult{}, errors.New("发布清单已过期")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, in.Output, unix.RENAME_NOREPLACE); err != nil {
		return PublicationResult{}, err
	}
	if err := syncDir(filepath.Dir(in.Output)); err != nil {
		return PublicationResult{}, fmt.Errorf("发行产物已生成，但父目录同步未确认：%w", err)
	}
	return PublicationResult{State: "signed", Directory: in.Output, Repository: m.Repository, Version: m.Version, ManifestSHA256: hash(manifest), Key: Key{ID: in.KeyID, PublicKey: in.PublicKey}}, nil
}
