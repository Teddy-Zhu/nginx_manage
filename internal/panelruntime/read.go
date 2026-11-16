package panelruntime

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"nginxpanel/internal/secure"
)

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("运行清单包含额外数据")
	}
	return nil
}
func ReadDeployment(data string) (Deployment, error) {
	var d Deployment
	root, err := Root(data)
	if err != nil {
		return d, err
	}
	info, err := os.Lstat(filepath.Join(root, "launcher.json"))
	if err != nil {
		return d, err
	}
	if info.Mode().Perm() != 0444 {
		return d, errors.New("面板运行绑定须为只读记录")
	}
	raw, err := secure.ReadRootFile(filepath.Join(root, "launcher.json"), DeploymentLimit)
	if err != nil {
		return d, err
	}
	if err = decode(raw, &d); err != nil {
		return d, err
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(canonical, raw) {
		return d, errors.New("面板运行绑定不是原始规范记录")
	}
	return d, d.validate(data)
}
func executable(name, expected string) error {
	f, info, err := secure.OpenRootFile(name, BinaryLimit)
	if err != nil {
		return err
	}
	defer f.Close()
	if info.Mode().Perm()&0111 == 0 {
		return errors.New("面板程序不可执行")
	}
	e, err := elf.NewFile(f)
	if err != nil {
		return err
	}
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return errors.New("面板运行架构不受支持")
	}
	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != machine || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
		return errors.New("面板程序 ELF 架构无效")
	}
	for _, p := range e.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("面板须使用无动态解释器的静态程序")
		}
	}
	needed, err := e.ImportedLibraries()
	if err != nil || len(needed) != 0 {
		return errors.New("面板不能依赖动态共享库")
	}
	b, err := buildinfo.Read(f)
	if err != nil {
		return err
	}
	static := false
	for _, setting := range b.Settings {
		if setting.Key == "CGO_ENABLED" && setting.Value == "0" {
			static = true
		}
	}
	if !static || !secure.RootFileUnchanged(f, info) {
		return errors.New("面板须来自 CGO_ENABLED=0 的稳定产物")
	}
	actual, err := secure.HashRootFile(name, BinaryLimit)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("面板程序散列已变化")
	}
	return nil
}
func readRelease(dir, id string) (Release, error) {
	var r Release
	for _, entry := range []struct {
		name string
		mode os.FileMode
	}{{dir, 0755}, {filepath.Join(dir, "release.json"), 0444}, {filepath.Join(dir, "nginxpanel"), 0555}} {
		info, err := os.Lstat(entry.name)
		if err != nil {
			return r, err
		}
		if info.Mode().Perm() != entry.mode {
			return r, errors.New("面板发布目录或文件权限已变化")
		}
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, "release.json"), 1<<20)
	if err != nil {
		return r, err
	}
	if err = decode(raw, &r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return r, errors.New("面板发布清单不是原始规范记录")
	}
	if err = r.validate(); err != nil {
		return r, err
	}
	if r.ID != id || r.Architecture != runtime.GOARCH {
		return r, errors.New("面板发布目录身份或架构不匹配")
	}
	if err = executable(filepath.Join(dir, "nginxpanel"), r.BinarySHA256); err != nil {
		return r, err
	}
	return r, nil
}

// ReadVersion verifies an immutable, already published release without changing
// current. The independent updater uses it to preserve the original rollback
// program identity before selecting any new code.
func ReadVersion(data, id string) (Snapshot, error) {
	if !digest.MatchString(id) {
		return Snapshot{}, errors.New("面板发布身份无效")
	}
	d, err := ReadDeployment(data)
	if err != nil {
		return Snapshot{}, err
	}
	root, _ := Root(data)
	dir := filepath.Join(root, "releases", id)
	r, err := readRelease(dir, id)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Deployment: d, Release: r, Directory: dir}, nil
}

func Read(data string) (Snapshot, error) {
	var out Snapshot
	d, err := ReadDeployment(data)
	if err != nil {
		return out, err
	}
	root, _ := Root(data)
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink == 0 {
		return out, errors.New("面板当前版本须为 root 持有的发布指针")
	}
	target, err := os.Readlink(current)
	if err != nil || !strings.HasPrefix(target, "releases/") || !digest.MatchString(strings.TrimPrefix(target, "releases/")) {
		return out, errors.New("面板当前版本指针无效")
	}
	dir := filepath.Join(root, target)
	r, err := readRelease(dir, strings.TrimPrefix(target, "releases/"))
	if err != nil {
		return out, err
	}
	if after, err := os.Readlink(current); err != nil || after != target {
		return out, errors.New("面板版本在核对期间变化")
	}
	return Snapshot{Deployment: d, Release: r, Directory: dir}, nil
}
