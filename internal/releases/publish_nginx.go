package releases

import (
	"bytes"
	"debug/elf"
	_ "embed"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// The builder and signer consume the same reviewed source and module recipe.
//
//go:embed nginx-source-lock.json
var nginxSourceLock []byte

type nginxSource struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	URL          string   `json:"url"`
	SHA256       string   `json:"sha256"`
	Size         int64    `json:"size"`
	Root         string   `json:"root"`
	License      string   `json:"license"`
	LicenseFiles []string `json:"license_files"`
}
type nginxRecipe struct {
	Schema                int           `json:"schema"`
	Version               string        `json:"version"`
	Sources               []nginxSource `json:"sources"`
	ConfigureArgs         []string      `json:"configure_args"`
	Features              []string      `json:"features"`
	RequiredModuleSymbols []string      `json:"required_module_symbols"`
}
type NginxRuntimeArchive struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	LicenseFile string `json:"license_file"`
}
type NativeNginxProvenance struct {
	LockSHA256      string                `json:"lock_sha256"`
	ConfigureArgs   []string              `json:"configure_args"`
	Compiler        string                `json:"compiler"`
	CompilerVersion string                `json:"compiler_version"`
	BuildInfoSHA256 string                `json:"build_info_sha256"`
	ToolchainSHA256 string                `json:"toolchain_sha256"`
	RuntimeArchives []NginxRuntimeArchive `json:"runtime_archives"`
	RunnerImage     string                `json:"runner_image"`
}

func nginxBuildRecipe() (nginxRecipe, error) {
	var recipe nginxRecipe
	if err := strictJSON(nginxSourceLock, &recipe); err != nil {
		return recipe, err
	}
	if recipe.Schema != 1 || !validVersion(recipe.Version) || len(recipe.Sources) != 4 || len(recipe.ConfigureArgs) == 0 || len(recipe.Features) == 0 || len(recipe.RequiredModuleSymbols) == 0 {
		return recipe, errors.New("内嵌 Nginx 源码锁定清单无效")
	}
	for i, source := range recipe.Sources {
		if source.ID != []string{"nginx", "openssl", "pcre2", "zlib"}[i] || !validHash(source.SHA256) || source.Size <= 0 || source.Size > 64<<20 || !safePath(source.Root) || strings.Contains(source.Root, "/") || len(source.LicenseFiles) == 0 {
			return recipe, errors.New("内嵌 Nginx 源码身份或许可无效")
		}
		for _, name := range source.LicenseFiles {
			if !safePath(name) {
				return recipe, errors.New("内嵌 Nginx 许可路径无效")
			}
		}
	}
	return recipe, nil
}

func nginxPublicationPackage(architecture, releaseVersion string) (PackageSource, error) {
	recipe, err := nginxBuildRecipe()
	if err != nil {
		return PackageSource{}, err
	}
	if architecture != "amd64" && architecture != "arm64" {
		return PackageSource{}, errors.New("原生 Nginx 构建架构无效")
	}
	licenses := []string{}
	for _, source := range recipe.Sources {
		for _, name := range source.LicenseFiles {
			licenses = append(licenses, "licenses/"+source.ID+"/"+name)
		}
	}
	for _, name := range []string{"libc.a", "libgcc.a", "libgcc_eh.a"} {
		licenses = append(licenses, "licenses/toolchain/"+name+".txt")
	}
	licenses = append(licenses, "licenses/toolchain/GPL-3.txt")
	id := "nginx-linux-" + architecture
	return PackageSource{Directory: id, ExecutableFiles: []string{"bin/nginx"}, Asset: Asset{
		ID: id, Component: "nginx", Version: recipe.Version, OS: "linux", Architecture: architecture,
		Distribution: "any", DistributionVersion: "any", ABI: "static",
		Archive:      "nginx_" + recipe.Version + "_nginxpanel_" + releaseVersion + "_linux_" + architecture + ".tar.gz",
		License:      "BSD-2-Clause AND Apache-2.0 AND (BSD-3-Clause WITH PCRE2-exception) AND Zlib AND LicenseRef-Runtime-libc-a AND LicenseRef-Runtime-libgcc-a AND LicenseRef-Runtime-libgcc-eh-a",
		LicenseFiles: licenses, SourceURL: recipe.Sources[0].URL, Maintenance: "maintained", Features: slices.Clone(recipe.Features),
	}}, nil
}

func nginxPublicationEvidence(directory string, asset Asset, spec PublicationSpec, p BuildProvenance, sbom []byte) error {
	recipe, err := nginxBuildRecipe()
	if err != nil {
		return err
	}
	expected, err := nginxPublicationPackage(asset.Architecture, spec.Manifest.Version)
	if err != nil {
		return err
	}
	metadata := asset
	metadata.SHA256, metadata.Size, metadata.UnpackedBytes, metadata.Files = "", 0, 0, nil
	if !reflect.DeepEqual(metadata, expected.Asset) {
		return errors.New("Nginx 资产与内嵌源码、许可或静态模块配方不一致")
	}
	n := p.NativeNginx
	if n == nil || p.Fail2ban != nil || p.Scope != "native-nginx-source-and-static-runtime" || p.GoVersion != "" || p.NodeVersion != "" || p.PNPMVersion != "" || p.GoSumSHA256 != "" || p.WebLockSHA256 != "" || n.LockSHA256 != hash(nginxSourceLock) || !slices.Equal(n.ConfigureArgs, recipe.ConfigureArgs) || n.Compiler != "musl-gcc" || !text(n.CompilerVersion, 4096) || !text(n.RunnerImage, 256) || len(n.RuntimeArchives) != 3 {
		return errors.New("Nginx 构建来源未绑定原生工具链和固定源码配方")
	}
	fileHashes := map[string]string{}
	for _, file := range asset.Files {
		fileHashes[file.Path] = file.SHA256
	}
	for name, hash := range map[string]string{"bin/nginx": p.BinarySHA256, "build/nginx-source-lock.json": n.LockSHA256, "build/nginx-V.txt": n.BuildInfoSHA256, "build/toolchain-packages.txt": n.ToolchainSHA256} {
		if !validHash(hash) || fileHashes[name] != hash {
			return errors.New("Nginx 构建来源与实际程序或证据文件不一致")
		}
	}
	lock, err := readPublicationFile(filepath.Join(directory, "build/nginx-source-lock.json"), 64<<10)
	if err != nil || !bytes.Equal(lock, nginxSourceLock) {
		return errors.New("Nginx 包内源码锁定清单与发布工具不一致")
	}
	buildInfo, err := readPublicationFile(filepath.Join(directory, "build/nginx-V.txt"), 64<<10)
	if err != nil || !strings.Contains(string(buildInfo), "nginx version: nginx/"+recipe.Version+"\n") || !strings.Contains(string(buildInfo), "built with OpenSSL "+recipe.Sources[1].Version+" ") {
		return errors.New("Nginx 构建记录缺少固定 Nginx/OpenSSL 版本")
	}
	// Inspect the approved ELF without executing uploaded binaries in the signer.
	// Keeping symbols also allows a module declaration to be checked independently
	// of the builder's textual nginx -V record. Static closure is checked upstream.
	binary, err := elf.Open(filepath.Join(directory, "bin/nginx"))
	if err != nil {
		return err
	}
	defer binary.Close()
	symbols, err := binary.Symbols()
	if err != nil {
		return err
	}
	modules := map[string]bool{}
	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF && elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT && symbol.Size > 0 {
			modules[symbol.Name] = true
		}
	}
	for _, name := range recipe.RequiredModuleSymbols {
		if !modules[name] {
			return errors.New("Nginx ELF 缺少配方要求的静态模块符号: " + name)
		}
	}
	var inventory struct {
		Packages []struct {
			ID        string `json:"SPDXID"`
			Version   string `json:"versionInfo"`
			Download  string `json:"downloadLocation"`
			License   string `json:"licenseDeclared"`
			Checksums []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
		Licenses []struct {
			ID   string `json:"licenseId"`
			Text string `json:"extractedText"`
		} `json:"hasExtractedLicensingInfos"`
	}
	if err := json.Unmarshal(sbom, &inventory); err != nil {
		return err
	}
	type input struct{ version, url, hash, license string }
	inputs := map[string]input{"SPDXRef-nginx-binary": {recipe.Version, "NOASSERTION", p.BinarySHA256, asset.License}}
	for _, source := range recipe.Sources {
		inputs["SPDXRef-"+source.ID+"-source"] = input{source.Version, source.URL, source.SHA256, source.License}
	}
	runtimeLicenses := map[string]string{}
	gpl, err := readPublicationFile(filepath.Join(directory, "licenses/toolchain/GPL-3.txt"), 256<<10)
	if err != nil || len(gpl) == 0 {
		return errors.New("Nginx 运行库许可缺少 GPL-3 原文")
	}
	for i, archive := range n.RuntimeArchives {
		name := []string{"libc.a", "libgcc.a", "libgcc_eh.a"}[i]
		license := "licenses/toolchain/" + name + ".txt"
		if archive.Name != name || !filepath.IsAbs(archive.Path) || filepath.Clean(archive.Path) != archive.Path || !text(archive.Path, 512) || !text(archive.Package, 256) || !text(archive.Version, 256) || !validHash(archive.SHA256) || archive.LicenseFile != license || !validHash(fileHashes[license]) {
			return errors.New("Nginx 静态运行库来源或许可记录不完整")
		}
		licenseText, err := readPublicationFile(filepath.Join(directory, license), 2<<20)
		if err != nil || len(licenseText) == 0 {
			return errors.New("Nginx 静态运行库许可缺少原文")
		}
		if name != "libc.a" {
			if !bytes.Contains(bytes.ToUpper(licenseText), []byte("GCC RUNTIME LIBRARY EXCEPTION")) {
				return errors.New("Nginx GCC 运行库许可缺少运行库例外")
			}
			licenseText = append(append(licenseText, '\n'), gpl...)
		}
		suffix := strings.NewReplacer(".", "-", "_", "-").Replace(name)
		licenseID := "LicenseRef-Runtime-" + suffix
		inputs["SPDXRef-runtime-"+suffix] = input{archive.Version, "NOASSERTION", archive.SHA256, licenseID}
		runtimeLicenses[licenseID] = string(licenseText)
	}
	if len(inventory.Packages) != len(inputs) {
		return errors.New("Nginx SPDX 未完整登记源码和静态运行库")
	}
	for _, entry := range inventory.Packages {
		expected, ok := inputs[entry.ID]
		if !ok || entry.Version != expected.version || entry.Download != expected.url || entry.License != expected.license || len(entry.Checksums) != 1 || entry.Checksums[0].Algorithm != "SHA256" || entry.Checksums[0].Value != expected.hash {
			return errors.New("Nginx SPDX 与锁定源码、程序或静态运行库散列不一致")
		}
		delete(inputs, entry.ID)
	}
	if len(inventory.Licenses) != len(runtimeLicenses) {
		return errors.New("Nginx SPDX 运行库许可引用不完整")
	}
	for _, license := range inventory.Licenses {
		expected, ok := runtimeLicenses[license.ID]
		if !ok || license.Text != expected {
			return errors.New("Nginx SPDX 运行库许可与原文不一致")
		}
		delete(runtimeLicenses, license.ID)
	}
	return nil
}
