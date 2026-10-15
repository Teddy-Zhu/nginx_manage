package nginxruntime

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var versionValue = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var versionLine = regexp.MustCompile(`(?m)^nginx version: nginx/([0-9]+\.[0-9]+\.[0-9]+)(?:[ \t][^\r\n]*)?\r?$`)

func host() releases.Host {
	p := platform.Detect()
	return releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: p.OS, Version: p.Version}
}
func receiver() releases.Receiver {
	return releases.Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: releases.LauncherVersion}
}
func inputFor(s Signed) releases.Input {
	return releases.Input{TrustPath: s.TrustPath, Assets: []string{s.AssetID}, AllowedComponents: []string{"nginx"}, AllowPrerelease: s.Prerelease, Host: s.Host, Receiver: s.Receiver}
}
func fromPlan(p releases.Result, assetID string) (releases.Asset, string, error) {
	if len(p.Plan.Selected) != 1 || p.Plan.Selected[0] != assetID || len(p.Plan.Assets) != 1 || p.Plan.Assets[0].ID != assetID || p.Plan.Assets[0].Component != "nginx" {
		return releases.Asset{}, "", errors.New("原生 Nginx 绑定须只包含一个 Nginx 资产")
	}
	return p.Plan.Assets[0], filepath.Join(p.Directory, assetID, "bin", "nginx"), nil
}
func readBinding(data string) (Binding, error) {
	var b Binding
	name, err := bindingPath(data)
	if err != nil {
		return b, err
	}
	raw, err := nginxmodules.ReadTrusted(name, 16<<10)
	if err != nil {
		return b, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF {
		return b, errors.New("Nginx 绑定记录格式无效")
	}
	info, err := os.Lstat(name)
	if err != nil {
		return b, err
	}
	if info.Mode().Perm() != 0444 || b.Schema != Schema || b.DataDir != data || b.BoundAt <= 0 || b.BoundAt > time.Now().Unix()+300 {
		return b, errors.New("Nginx 绑定身份或权限无效")
	}
	if b.Owner == "uninstalled" {
		if b.Binary != "" || b.SHA256 != "" || b.Version != "" || b.Signed != nil {
			return b, errors.New("未安装登记包含无效运行信息")
		}
	} else if !digest.MatchString(b.SHA256) || len(b.Version) > 64 || !versionValue.MatchString(b.Version) || !filepath.IsAbs(b.Binary) || filepath.Clean(b.Binary) != b.Binary || (b.Owner == "managed") != (b.Signed != nil) || b.Owner != "managed" && b.Owner != "local" {
		return b, errors.New("Nginx 安装绑定内容无效")
	}
	return b, nil
}

// Read verifies the installed receipt using current keys and exact files. Its
// approval time is read only from the immutable local binding, not caller input.
func Read(ctx context.Context, data string) (Binding, Installation, error) {
	b, info, err := Selection(ctx, data)
	if err != nil {
		return b, Installation{}, err
	}
	if info == nil {
		return b, Installation{}, ErrNotInstalled
	}
	return b, *info, nil
}

// Selection accepts only a valid root-owned record. A missing record or missing
// installed asset remains an error; neither is an uninstalled selection.
func Selection(ctx context.Context, data string) (Binding, *Installation, error) {
	b, err := readBinding(data)
	if err != nil {
		return b, nil, err
	}
	if err = ctx.Err(); err != nil {
		return b, nil, err
	}
	if b.Owner == "uninstalled" {
		return b, nil, nil
	}
	info := Installation{Owner: b.Owner, Version: b.Version, SHA256: b.SHA256, BoundAt: b.BoundAt}
	if b.Signed != nil {
		s := *b.Signed
		current := receiver()
		if s.Host != host() || s.Receiver.APIMajor != current.APIMajor || s.Receiver.AgentProtocol > current.AgentProtocol || s.Receiver.Launcher > current.Launcher {
			return b, nil, errors.New("本机平台或接收端不满足已安装组件")
		}
		p, e := releases.Installed(ctx, inputFor(s), s.PlanID, b.BoundAt, s.TrustSHA256)
		if e != nil {
			return b, nil, e
		}
		asset, binary, e := fromPlan(p, s.AssetID)
		if e != nil {
			return b, nil, e
		}
		if binary != b.Binary || p.Plan.ManifestSHA256 != s.ManifestSHA256 || asset.Version != b.Version {
			return b, nil, errors.New("已安装 Nginx 与签名资产不一致")
		}
		info.PlanID, info.AssetID, info.SourceURL, info.License = s.PlanID, s.AssetID, asset.SourceURL, asset.License
	}
	if err = verifyExecutable(b.Binary, b.SHA256); err != nil {
		return b, nil, err
	}
	return b, &info, nil
}
func verifyExecutable(binary, expected string) error {
	raw, err := nginxmodules.ReadTrusted(binary, limits.NginxBinaryBytes)
	if err != nil {
		return err
	}
	if expected != "" && secure.Hash(raw) != expected {
		return errors.New("Nginx 二进制内容已变化，须维护确认")
	}
	image, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return errors.New("Nginx 必须为受信 ELF 可执行文件")
	}
	defer image.Close()
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return errors.New("不支持的 Nginx 架构")
	}
	if image.Class != elf.ELFCLASS64 || image.Data != elf.ELFDATA2LSB || image.Machine != machine || image.Type != elf.ET_DYN && image.Type != elf.ET_EXEC {
		return errors.New("Nginx ELF 架构或类型不匹配")
	}
	info, err := os.Lstat(binary)
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("Nginx 程序不可执行")
	}
	return nil
}

type output struct{ value bytes.Buffer }

func (w *output) String() string { return w.value.String() }

func (w *output) Write(p []byte) (int, error) {
	if w.value.Len()+len(p) > 64<<10 {
		return 0, errors.New("Nginx 编译信息超过 64 KiB")
	}
	return w.value.Write(p)
}
func probe(ctx context.Context, binary string) (string, error) {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, binary, "-V")
	cmd.WaitDelay = time.Second
	cmd.Env = Environment()
	var out output
	cmd.Stdout = &out
	cmd.Stderr = &out
	if cmd.Run() != nil {
		return "", errors.New("无法读取已批准 Nginx 的版本")
	}
	matches := versionLine.FindAllStringSubmatch(out.String(), -1)
	if len(matches) != 1 || len(matches[0][1]) > 64 {
		return "", errors.New("Nginx 版本响应无效")
	}
	return matches[0][1], nil
}
func Environment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}
