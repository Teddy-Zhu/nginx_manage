package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/secure"
)

type ModuleDependency struct {
	SHA256       string   `json:"sha256"`
	BinarySHA256 string   `json:"binary_sha256"`
	Bytes        int64    `json:"bytes"`
	Features     []string `json:"features"`
}
type NativeModule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	SHA256    string   `json:"sha256"`
	Available bool     `json:"available"`
	Running   bool     `json:"running"`
	Features  []string `json:"features"`
	Reason    string   `json:"reason"`
}

func moduleHeader(modules map[string]ModuleDependency) bool {
	total := int64(0)
	if len(modules) > limits.NginxModules {
		return false
	}
	for name, module := range modules {
		if !nginxmodules.Reference(name) || !strings.HasSuffix(name, "/"+module.SHA256+".so") || len(module.BinarySHA256) != 64 || module.Bytes <= 0 || module.Bytes > limits.NginxModuleBytes || len(module.Features) > 4 {
			return false
		}
		total += module.Bytes
	}
	return total <= limits.NginxModuleBundleBytes
}
func (n *Nginx) prepareModules(parsed *nginxconfig.Parsed) (map[string]ModuleDependency, error) {
	out := map[string]ModuleDependency{}
	if len(parsed.Tree.ModulePaths) == 0 {
		return out, nil
	}
	if n.Container != nil {
		return nil, errors.New("Nginx 容器只使用镜像预置模块，缺失能力须更换匹配的受信镜像")
	}
	if len(parsed.Tree.ModulePaths) > limits.NginxModules {
		return nil, errors.New("native module count exceeds budget")
	}
	binaryHash, err := nginxmodules.HashTrusted(n.Binary, limits.NginxBinaryBytes)
	if err != nil {
		return nil, err
	}
	approved := map[string]nginxmodules.Approval{}
	for _, item := range n.Modules {
		approved[item.Path()] = item
	}
	total := 0
	for _, name := range parsed.Tree.ModulePaths {
		item, ok := approved[name]
		if !ok {
			return nil, errors.New("native module is not approved")
		}
		data, features, err := n.approvedModule(item, binaryHash)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > limits.NginxModuleBundleBytes {
			return nil, errors.New("native module bundle exceeds budget")
		}
		target := filepath.Join(n.DataDir, filepath.FromSlash(name))
		parent := filepath.Dir(target)
		if err := secure.RootDirectory(parent, 0755); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(target); err == nil {
			hash, readErr := nginxmodules.HashTrusted(target, int64(len(data)))
			if readErr != nil || hash != item.SHA256 {
				return nil, ErrExternalChange
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		} else {
			if err := n.moduleCapacity(int64(len(data))); err != nil {
				return nil, err
			}
			// Publish without replacing another immutable version. The source was
			// copied and verified before any Nginx process can load it.
			temp := filepath.Join(parent, ".tmp-"+secure.ID())
			defer os.Remove(temp)
			if err := durableFile(temp, data, 0644, 0); err != nil {
				return nil, err
			}
			if err := unix.Renameat2(unix.AT_FDCWD, temp, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
				return nil, err
			}
		}
		for _, dir := range []string{parent, filepath.Dir(parent), n.DataDir} {
			if err := syncDir(dir); err != nil {
				return nil, err
			}
		}
		out[name] = ModuleDependency{SHA256: item.SHA256, BinarySHA256: binaryHash, Bytes: int64(len(data)), Features: features}
	}
	return out, nil
}
func (n *Nginx) moduleCapacity(incoming int64) error {
	count := 0
	files := 0
	bytes := incoming
	root := filepath.Join(n.DataDir, "modules")
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > limits.StoredNginxModules*3 {
			return errors.New("native module store entry budget reached")
		}
		if entry.IsDir() && name != root && filepath.Dir(name) != root {
			return errors.New("unexpected module store directory")
		}
		if !entry.IsDir() {
			files++
			info, err := entry.Info()
			if err != nil {
				return err
			}
			bytes += info.Size()
			if files >= limits.StoredNginxModules || bytes > limits.StoredNginxModuleBytes {
				return errors.New("native module store capacity reached")
			}
		}
		return nil
	})
}
func (n *Nginx) approvedModule(item nginxmodules.Approval, binaryHash string) ([]byte, []string, error) {
	if item.BinarySHA256 != binaryHash {
		return nil, nil, errors.New("native module approval targets another binary")
	}
	copy := filepath.Join(n.DataDir, filepath.FromSlash(item.Path()))
	if _, err := os.Lstat(copy); os.IsNotExist(err) {
		return nginxmodules.Material(item, binaryHash)
	} else if err != nil {
		return nil, nil, err
	}
	data, err := nginxmodules.ReadTrusted(copy, limits.NginxModuleBytes)
	if err != nil || secure.Hash(data) != item.SHA256 {
		return nil, nil, ErrExternalChange
	}
	features, err := nginxmodules.Inspect(data)
	return data, features, err
}
func (n *Nginx) verifyModules(modules map[string]ModuleDependency) error {
	if !moduleHeader(modules) {
		return ErrExternalChange
	}
	if len(modules) == 0 {
		return nil
	}
	binaryHash, err := nginxmodules.HashTrusted(n.Binary, limits.NginxBinaryBytes)
	if err != nil {
		return err
	}
	for name, module := range modules {
		hash, err := nginxmodules.HashTrusted(filepath.Join(n.DataDir, filepath.FromSlash(name)), module.Bytes)
		if err != nil || hash != module.SHA256 || binaryHash != module.BinarySHA256 {
			return ErrExternalChange
		}
	}
	return nil
}
func (n *Nginx) scanModules(modules map[string]ModuleDependency) ([]ExternalFile, error) {
	out := []ExternalFile{}
	if !moduleHeader(modules) {
		return nil, ErrExternalChange
	}
	if len(modules) == 0 {
		return out, nil
	}
	binaryHash, _ := nginxmodules.HashTrusted(n.Binary, limits.NginxBinaryBytes)
	names := []string{}
	binaries := map[string]bool{}
	for name, dependency := range modules {
		names = append(names, name)
		binaries[dependency.BinarySHA256] = true
	}
	sort.Strings(names)
	for _, name := range names {
		dependency := modules[name]
		file := ExternalFile{Path: name, ExpectedSHA256: dependency.SHA256, Status: "unsafe", Reason: "模块副本不可安全读取；请在本机检查，或批准并选择新的模块版本"}
		hash, err := nginxmodules.HashTrusted(filepath.Join(n.DataDir, filepath.FromSlash(name)), dependency.Bytes)
		if err == nil {
			file.ObservedSHA256 = hash
			file.Status = "modified"
			file.Reason = "模块副本散列已变化"
			if hash == dependency.SHA256 {
				file.Status = "unchanged"
				file.Reason = ""
			}
		}
		out = append(out, file)
	}
	expected := []string{}
	for hash := range binaries {
		expected = append(expected, hash)
	}
	sort.Strings(expected)
	for _, hash := range expected {
		file := ExternalFile{Path: "nginx-binary", ExpectedSHA256: hash, ObservedSHA256: binaryHash, Status: "modified", Reason: "Nginx 二进制与模块批准时的散列不一致"}
		if binaryHash == "" {
			file.Status = "unsafe"
			file.Reason = "Nginx 二进制不可安全读取"
		} else if binaryHash == hash {
			file.Status = "unchanged"
			file.Reason = ""
		}
		out = append(out, file)
	}
	return out, nil
}
