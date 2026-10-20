package panelruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type boundedOutput struct{ raw []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.raw)+len(p) > 4096 {
		return 0, errors.New("面板版本输出超过限制")
	}
	b.raw = append(b.raw, p...)
	return len(p), nil
}
func describe(ctx context.Context, binary string) (Release, error) {
	var r Release
	hash, err := secure.HashRootFile(binary, BinaryLimit)
	if err != nil {
		return r, err
	}
	if err = executable(binary, hash); err != nil {
		return r, err
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, binary, "version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out, diagnostic boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err = cmd.Run(); err != nil {
		return r, errors.New("本机批准的面板程序无法确认版本")
	}
	var info struct {
		Version         string `json:"version"`
		DatabaseSchema  int64  `json:"database_schema"`
		AgentProtocol   int    `json:"agent_protocol"`
		LauncherVersion int    `json:"launcher_version"`
		ParserVersion   string `json:"parser_version"`
	}
	if err = decode(out.raw, &info); err != nil {
		return r, err
	}
	if after, err := secure.HashRootFile(binary, BinaryLimit); err != nil || after != hash {
		return r, errors.New("面板程序在版本核对期间变化")
	}
	r = Release{Schema: Schema, Version: info.Version, DatabaseSchema: info.DatabaseSchema, AgentProtocol: info.AgentProtocol, LauncherVersion: info.LauncherVersion, Architecture: runtime.GOARCH, BinarySHA256: hash}
	return r, nil
}
func syncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func runtimeDir(name string) error {
	if err := secure.RootDirectory(name, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	// Installer and Agent umasks can restrict a newly created directory. This
	// subtree contains public artifacts, never business secrets.
	if info.Mode().Perm() == 0700 || info.Mode().Perm() == 0750 {
		return os.Chmod(name, 0755)
	}
	if info.Mode().Perm() != 0755 {
		return errors.New("面板发布目录须为 root 持有的 0755 目录")
	}
	return nil
}
func publishFile(name string, raw []byte) error {
	if old, err := secure.ReadRootFile(name, int64(len(raw))+1); err == nil {
		if !bytes.Equal(old, raw) {
			return errors.New("已有不同的面板运行绑定，禁止覆盖")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(0444); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}
func copyArtifact(source, target, expected string, limit int64, mode os.FileMode) error {
	f, before, err := secure.OpenRootFile(source, limit)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if n != before.Size() || n > limit || hex.EncodeToString(h.Sum(nil)) != expected || !secure.RootFileUnchanged(f, before) {
		return errors.New("面板产物在复制期间变化")
	}
	if err = out.Chmod(mode); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	return out.Close()
}

// Bind is a local-root bootstrap operation. It publishes immutable artifacts and
// never starts a service, replaces a current release or trusts container input.
func Bind(ctx context.Context, in BindInput) (Snapshot, error) {
	var out Snapshot
	if os.Geteuid() != 0 {
		return out, errors.New("面板运行初始化需要本机 root")
	}
	root, err := Root(in.DataDir)
	if err != nil {
		return out, err
	}
	binary, err := filepath.EvalSymlinks(in.Binary)
	if err != nil {
		return out, err
	}
	web, err := filepath.EvalSymlinks(in.WebDir)
	if err != nil {
		return out, err
	}
	source, err := VerifySource(ctx, in)
	if err != nil {
		return out, err
	}
	r, approval := source.Release, source.SignedImage
	if err = (StagedRelease{Release: r}).RequireCurrent(); err != nil {
		return out, err
	}
	launcherHash := r.BinarySHA256
	d := Deployment{Schema: Schema, Mode: "docker", DataDir: in.DataDir, Listen: in.Listen, UID: in.UID, GID: in.GID, IPCGID: in.IPCGID, LauncherSHA256: launcherHash, LauncherRelease: r.ID, InitialRelease: r.ID, Image: in.Image, ImageID: source.ImageID, SignedImage: approval}
	if err = d.validate(in.DataDir); err != nil {
		return out, err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return out, err
	}
	defer unlock()
	if prior, err := ReadDeployment(in.DataDir); err == nil {
		// Another identical bootstrap may have published while source inspection
		// was running. Reuse only its admission time and original trust identity.
		candidate := d.SignedImage
		candidate.ApprovedAt, candidate.TrustSHA256 = prior.SignedImage.ApprovedAt, prior.SignedImage.TrustSHA256
		if candidate != prior.SignedImage {
			return out, errors.New("已有不同的镜像签名批准记录")
		}
		d.SignedImage = prior.SignedImage
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	return bindRelease(ctx, root, binary, web, r, d)
}

// bindRelease requires publicationLock and never resets an existing current
// pointer. Repeating bootstrap after an update cannot select the initial code.
func bindRelease(ctx context.Context, root, binary, web string, r Release, d Deployment) (Snapshot, error) {
	var out Snapshot
	ready := filepath.Join(root, "binding.ready")
	bound := false
	if prior, err := secure.ReadRootFile(ready, 64); err == nil {
		if string(prior) != d.InitialRelease {
			return out, errors.New("已有不同的面板初始化完成记录")
		}
		bound = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	rawDeployment, err := json.Marshal(d)
	if err != nil {
		return out, err
	}
	if prior, err := secure.ReadRootFile(filepath.Join(root, "launcher.json"), DeploymentLimit); err == nil {
		if !bytes.Equal(prior, rawDeployment) {
			return out, errors.New("已有不同的面板运行计划")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if err = publishRelease(ctx, root, binary, web, r); err != nil {
		return out, err
	}
	if err = publishFile(filepath.Join(root, "launcher.json"), rawDeployment); err != nil {
		return out, err
	}
	current := filepath.Join(root, "current")
	if _, err = os.Lstat(current); errors.Is(err, os.ErrNotExist) {
		if bound {
			return out, errors.New("已完成初始化但版本指针缺失，不能重置为初始程序")
		}
		if err = os.Symlink("releases/"+r.ID, current); err != nil {
			return out, err
		}
		if err = syncDir(root); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	}
	if err = syncDir(root); err != nil {
		return out, err
	}
	out, err = Read(d.DataDir)
	if err != nil {
		return out, err
	}
	if err = publishFile(ready, []byte(d.InitialRelease)); err != nil {
		return out, err
	}
	return out, nil
}
