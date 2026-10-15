package nginxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func (in Input) Validate() error {
	if os.Geteuid() != 0 {
		return errors.New("Nginx 安装绑定需要本机 root")
	}
	if _, err := bindingPath(in.DataDir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(in.DataDir, "bin", "components", "nginx-container.json")); err == nil {
		return errors.New("Nginx 已登记为固定容器，不能同时接入原生组件")
	} else if !os.IsNotExist(err) {
		return err
	}
	local := in.Binary != ""
	managed := in.PlanID != "" && in.AssetID != ""
	if in.Uninstalled {
		if local || in.PlanID != "" || in.AssetID != "" || in.Prerelease {
			return errors.New("未安装登记不能携带 Nginx 程序、签名资产或预发布选择")
		}
		return nil
	}
	if local == managed || local && (in.PlanID != "" || in.AssetID != "" || in.Prerelease) || !local && !digest.MatchString(in.PlanID) {
		return errors.New("须选择一个本机 Nginx 程序或完整的已准备签名资产")
	}
	if managed && (!filepath.IsAbs(in.TrustPath) || filepath.Clean(in.TrustPath) != in.TrustPath || !strings.HasPrefix(in.TrustPath, "/etc/nginxpanel/")) {
		return errors.New("原生发行信任须位于 /etc/nginxpanel 下的规范路径")
	}
	return nil
}
func matches(b Binding, in Input) bool {
	if in.Uninstalled {
		return b.Owner == "uninstalled"
	}
	if in.Binary != "" {
		binary, err := filepath.EvalSymlinks(in.Binary)
		return err == nil && b.Owner == "local" && b.Binary == binary
	}
	return b.Owner == "managed" && b.Signed != nil && b.Signed.PlanID == in.PlanID && b.Signed.AssetID == in.AssetID && b.Signed.TrustPath == in.TrustPath && b.Signed.Prerelease == in.Prerelease
}

// Inspect admits a new binding or revalidates the identical installed binding.
// It does not write, start services or change an existing selection.
func Inspect(ctx context.Context, in Input) (Binding, error) {
	var b Binding
	if err := in.Validate(); err != nil {
		return b, err
	}
	name, _ := bindingPath(in.DataDir)
	if _, err := os.Lstat(name); err == nil {
		prior, _, e := Selection(ctx, in.DataDir)
		if e != nil {
			return b, e
		}
		if !matches(prior, in) {
			return b, errors.New("已有不同 Nginx 绑定，版本切换须进入维护流程")
		}
		return prior, nil
	} else if !os.IsNotExist(err) {
		return b, err
	}
	return Admit(ctx, in)
}

// Admit verifies a candidate without changing the current selection. Activation
// must separately prove ownership of an explicitly uninstalled selection.
func Admit(ctx context.Context, in Input) (Binding, error) {
	var b Binding
	if err := in.Validate(); err != nil {
		return b, err
	}
	b = Binding{Schema: Schema, DataDir: in.DataDir, BoundAt: time.Now().Unix()}
	if in.Uninstalled {
		b.Owner = "uninstalled"
		return b, ctx.Err()
	}
	var expectedVersion string
	var expires int64
	if in.Binary != "" {
		binary, err := filepath.EvalSymlinks(in.Binary)
		if err != nil {
			return b, err
		}
		if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
			return b, errors.New("Nginx 程序须为规范绝对路径")
		}
		if strings.HasPrefix(binary, "/root/") || strings.HasPrefix(binary, "/home/") || strings.HasPrefix(binary, "/run/user/") {
			return b, errors.New("原生 Nginx 程序不能位于服务隔离的用户目录")
		}
		b.Owner, b.Binary = "local", binary
	} else {
		s := Signed{PlanID: in.PlanID, AssetID: in.AssetID, TrustPath: in.TrustPath, Prerelease: in.Prerelease, Host: host(), Receiver: receiver()}
		p, err := releases.Prepared(ctx, inputFor(s), in.PlanID)
		if err != nil {
			return b, err
		}
		asset, binary, err := fromPlan(p, in.AssetID)
		if err != nil {
			return b, err
		}
		s.ManifestSHA256, s.TrustSHA256 = p.Plan.ManifestSHA256, p.Plan.TrustSHA256
		b.Owner, b.Binary, b.Signed = "managed", binary, &s
		expectedVersion, expires = asset.Version, p.Plan.Manifest.ExpiresAt
	}
	hash, err := nginxmodules.HashTrusted(b.Binary, limits.NginxBinaryBytes)
	if err != nil {
		return b, err
	}
	b.SHA256 = hash
	if err = verifyExecutable(b.Binary, b.SHA256); err != nil {
		return b, err
	}
	b.Version, err = probe(ctx, b.Binary)
	if err != nil {
		return b, err
	}
	if expectedVersion != "" && b.Version != expectedVersion {
		return b, errors.New("Nginx 实际版本与已签名资产不一致")
	}
	if err = verifyExecutable(b.Binary, b.SHA256); err != nil {
		return b, err
	}
	if b.Signed != nil {
		current, e := releases.InspectTrust(b.Signed.TrustPath)
		if e != nil {
			return b, e
		}
		if current.SHA256 != b.Signed.TrustSHA256 || time.Now().Unix() >= expires {
			return b, releases.ErrReleaseChanged
		}
	}
	if err = ctx.Err(); err != nil {
		return b, err
	}
	return b, nil
}

// Bind publishes a new immutable installation reference. Different bindings are
// refused; this entry is not an online upgrade or an implicit takeover.
func Bind(ctx context.Context, in Input) (Binding, error) {
	if err := in.Validate(); err != nil {
		return Binding{}, err
	}
	unlock, err := LockSelection(in.DataDir)
	if err != nil {
		return Binding{}, err
	}
	defer unlock()
	b, err := Inspect(ctx, in)
	if err != nil {
		return b, err
	}
	name, _ := bindingPath(in.DataDir)
	for _, dir := range []string{in.DataDir, filepath.Join(in.DataDir, "bin"), filepath.Dir(name)} {
		if err = secure.RootDirectory(dir, 0755); err != nil {
			return b, err
		}
	}
	if _, err = os.Lstat(name); err == nil {
		prior, _, e := Selection(ctx, in.DataDir)
		if e != nil {
			return b, e
		}
		if !matches(prior, in) {
			return b, errors.New("Nginx 绑定已由其他安装计划发布")
		}
		return prior, nil
	} else if !os.IsNotExist(err) {
		return b, err
	}
	return publishBinding(ctx, b, false)
}

func publishBinding(ctx context.Context, b Binding, replace bool) (Binding, error) {
	name, err := bindingPath(b.DataDir)
	if err != nil {
		return b, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return b, err
	}
	if len(raw) > 16<<10 {
		return b, errors.New("Nginx 安装绑定超过 16 KiB")
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".nginx-bind-*")
	if err != nil {
		return b, err
	}
	defer func() {
		if e := os.Remove(f.Name()); e != nil && !os.IsNotExist(e) {
			slog.Error("Nginx 绑定暂存清理失败", "error", e)
		}
	}()
	_, err = f.Write(raw)
	if err == nil {
		err = f.Chmod(0444)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return b, err
	}
	if closed != nil {
		return b, closed
	}
	if err = ctx.Err(); err != nil {
		return b, err
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if replace {
		flags = 0
	}
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, name, flags); err != nil {
		return b, err
	}
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return b, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return b, err
	}
	return b, nil
}
