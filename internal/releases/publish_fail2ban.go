package releases

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
)

//go:embed fail2ban-source-lock.json
var fail2banSourceLock []byte

type fail2banRecipe struct {
	Schema        int               `json:"schema"`
	Version       string            `json:"version"`
	URL           string            `json:"url"`
	SHA256        string            `json:"sha256"`
	Size          int64             `json:"size"`
	Root          string            `json:"root"`
	Python        PythonRuntime     `json:"python"`
	License       string            `json:"license"`
	LicenseFiles  []string          `json:"license_files"`
	RequiredFiles map[string]string `json:"required_files"`
}
type Fail2banProvenance struct {
	LockSHA256            string `json:"lock_sha256"`
	InventorySHA256       string `json:"inventory_sha256"`
	VersionsSHA256        string `json:"versions_sha256"`
	AssemblyPythonVersion string `json:"assembly_python_version"`
}

func fail2banBuildRecipe() (fail2banRecipe, error) {
	var recipe fail2banRecipe
	if err := strictJSON(fail2banSourceLock, &recipe); err != nil {
		return recipe, err
	}
	if recipe.Schema != 1 || !validVersion(recipe.Version) || !validHash(recipe.SHA256) || !recipe.Python.Valid() || recipe.Size <= 0 || recipe.Size > 8<<20 || len(recipe.RequiredFiles) == 0 || len(recipe.LicenseFiles) == 0 {
		return recipe, errors.New("内嵌 Fail2ban 源码锁定清单无效")
	}
	for name, sha := range recipe.RequiredFiles {
		if !safePath(name) || !validHash(sha) {
			return recipe, errors.New("内嵌 Fail2ban 固定文件无效")
		}
	}
	return recipe, nil
}
func fail2banPublicationPackage(releaseVersion string) (PackageSource, error) {
	r, err := fail2banBuildRecipe()
	if err != nil {
		return PackageSource{}, err
	}
	return PackageSource{Directory: "fail2ban", ExecutableFiles: []string{"bin/fail2ban-server", "bin/fail2ban-client", "bin/fail2ban-regex"}, Asset: Asset{
		ID: "fail2ban", Component: "fail2ban", Version: r.Version, OS: "linux", Architecture: "any", Distribution: "any", DistributionVersion: "any", ABI: "system-python", Python: &r.Python,
		Archive: "fail2ban_" + r.Version + "_nginxpanel_" + releaseVersion + "_linux_any.tar.gz", License: r.License, LicenseFiles: r.LicenseFiles, SourceURL: r.URL, Maintenance: "maintained",
	}}, nil
}

func fail2banPublicationEvidence(directory string, asset Asset, spec PublicationSpec, p BuildProvenance, sbom []byte) error {
	r, err := fail2banBuildRecipe()
	if err != nil {
		return err
	}
	expected, err := fail2banPublicationPackage(spec.Manifest.Version)
	if err != nil {
		return err
	}
	metadata := asset
	metadata.SHA256, metadata.Size, metadata.UnpackedBytes, metadata.Files = "", 0, 0, nil
	n := p.Fail2ban
	if !reflect.DeepEqual(metadata, expected.Asset) || n == nil || p.NativeNginx != nil || p.GoVersion != "" || p.NodeVersion != "" || p.PNPMVersion != "" || p.GoSumSHA256 != "" || p.WebLockSHA256 != "" || p.BinarySHA256 != "" || p.Scope != "fail2ban-official-code" || n.LockSHA256 != hash(fail2banSourceLock) || !r.Python.AcceptsVersion(n.AssemblyPythonVersion) {
		return errors.New("Fail2ban 资产或构建来源与固定源码配方不一致")
	}
	files := map[string]File{}
	for _, file := range asset.Files {
		files[file.Path] = file
	}
	for name, sha := range map[string]string{"build/fail2ban-source-lock.json": n.LockSHA256, "build/source-files.json": n.InventorySHA256, "build/entry-versions.json": n.VersionsSHA256} {
		if !validHash(sha) || files[name].SHA256 != sha {
			return errors.New("Fail2ban 来源未绑定实际代码清单与构建记录")
		}
	}
	lock, err := readPublicationFile(filepath.Join(directory, "build/fail2ban-source-lock.json"), 64<<10)
	if err != nil || !bytes.Equal(lock, fail2banSourceLock) {
		return errors.New("Fail2ban 包内源码锁定清单与发布工具不一致")
	}
	for name, sha := range r.RequiredFiles {
		if files[name].SHA256 != sha {
			return errors.New("Fail2ban 固定入口或官方兼容文件不匹配: " + name)
		}
	}
	raw, err := readPublicationFile(filepath.Join(directory, "build/source-files.json"), 1<<20)
	if err != nil {
		return err
	}
	var sources []File
	if err := strictJSON(raw, &sources); err != nil {
		return err
	}
	if len(sources) == 0 || len(sources) > 1024 || len(asset.Files) != len(sources)+5 {
		return errors.New("Fail2ban 源文件清单不完整或超限")
	}
	previous := ""
	for _, source := range sources {
		if !safePath(source.Path) || source.Path <= previous || !fail2banSourcePath(source.Path) || files[source.Path] != source {
			return errors.New("Fail2ban 原代码文件清单与资产不一致")
		}
		previous = source.Path
	}
	versionsRaw, err := readPublicationFile(filepath.Join(directory, "build/entry-versions.json"), 16<<10)
	if err != nil {
		return err
	}
	var versions map[string]string
	if err := strictJSON(versionsRaw, &versions); err != nil {
		return err
	}
	if len(versions) != 3 {
		return errors.New("Fail2ban 须提供三个官方入口的构建版本记录")
	}
	for _, name := range expected.ExecutableFiles {
		version := "Fail2Ban v" + r.Version
		if name == "bin/fail2ban-regex" {
			version = "fail2ban-regex " + r.Version
		}
		if strings.TrimSpace(versions[name]) != version {
			return errors.New("Fail2ban 官方入口版本记录不匹配")
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
	if len(inventory.Packages) != 1 || len(inventory.Licenses) != 1 {
		return errors.New("Fail2ban SPDX 源码或兼容许可记录不完整")
	}
	entry := inventory.Packages[0]
	if entry.ID != "SPDXRef-fail2ban-source" || entry.Version != r.Version || entry.Download != r.URL || entry.License != r.License || len(entry.Checksums) != 1 || entry.Checksums[0].Algorithm != "SHA256" || entry.Checksums[0].Value != r.SHA256 {
		return errors.New("Fail2ban SPDX 与官方源码锁定不一致")
	}
	var compatibility []byte
	for _, name := range []string{"fail2ban/compat/asyncore.py", "fail2ban/compat/asynchat.py"} {
		raw, err := readPublicationFile(filepath.Join(directory, name), 64<<10)
		if err != nil {
			return err
		}
		compatibility = append(compatibility, raw...)
	}
	if inventory.Licenses[0].ID != "LicenseRef-Async-Compat" || inventory.Licenses[0].Text != string(compatibility) {
		return errors.New("Fail2ban SPDX 兼容许可与实际官方文件不一致")
	}
	return nil
}

func fail2banSourcePath(name string) bool {
	if name == "COPYING" || name == "README.md" || name == "ChangeLog" {
		return true
	}
	if strings.HasPrefix(name, "config/") {
		return strings.HasSuffix(name, ".conf")
	}
	if strings.HasPrefix(name, "fail2ban/") {
		return strings.HasSuffix(name, ".py") && !strings.HasPrefix(name, "fail2ban/tests/") && name != "fail2ban/setup.py"
	}
	return name == "bin/fail2ban-server" || name == "bin/fail2ban-client" || name == "bin/fail2ban-regex"
}
