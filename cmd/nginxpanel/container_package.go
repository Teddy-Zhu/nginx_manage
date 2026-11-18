package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"nginxpanel/internal/releases"
)

func runContainerPackageInfo(args []string) error {
	f := flag.NewFlagSet("container-package-info", flag.ContinueOnError)
	path := f.String("manifest", "", "installer content inventory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *path == "" {
		return errors.New("须指定容器安装清单")
	}
	info, err := os.Lstat(*path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return errors.New("容器安装清单无效")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var pkg releases.ContainerPackage
	if err = json.Unmarshal(raw, &pkg); err != nil {
		return err
	}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if pkg.Schema != 1 || pkg.Architecture != runtime.GOARCH || len(pkg.Images) != 1 || !digest.MatchString(pkg.Images["nginx"]) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pkg.BinarySHA256) || pkg.LauncherProtocol != releases.LauncherVersion {
		return errors.New("安装包镜像架构或内容标识无效")
	}
	// Resolve archive tags after loading: classic and containerd image stores
	// use different IDs for the same saved image. Runtime binding uses the
	// receiving daemon's immutable ID, never these mutable bootstrap tags.
	_, err = fmt.Fprintf(os.Stdout, "nginxpanel-build-nginx:%s-%s\n", pkg.Architecture, pkg.BinarySHA256)
	return err
}

// Runs in the build container; no host compiler or registry is required to
// produce a complete installer with content-addressed Docker image archives.
func runContainerPackage(args []string) error {
	f := flag.NewFlagSet("container-package", flag.ContinueOnError)
	root := f.String("package-dir", "", "assembled installer directory")
	nginx := f.String("nginx-image", "", "local Nginx image ID")
	if err := f.Parse(args); err != nil {
		return err
	}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if *root == "" || f.NArg() != 0 || !digest.MatchString(*nginx) {
		return errors.New("容器打包须指定安装目录和 Nginx 镜像内容 ID")
	}
	file := func(name string, limit int64) (releases.File, error) {
		var out releases.File
		info, err := os.Lstat(filepath.Join(*root, name))
		if err != nil {
			return out, err
		}
		if !info.Mode().IsRegular() || info.Size() > limit {
			return out, errors.New("安装包只能包含长度受限的普通文件")
		}
		source, err := os.Open(filepath.Join(*root, name))
		if err != nil {
			return out, err
		}
		defer source.Close()
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(source, limit+1))
		if err != nil || n != info.Size() {
			return out, errors.New("安装包文件读取失败或内容已变化")
		}
		return releases.File{Path: filepath.ToSlash(name), SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, Mode: 0644}, nil
	}
	binary, err := file("nginxpanel", 192<<20)
	if err != nil {
		return err
	}
	var capabilities struct {
		Version string `json:"nginx_version"`
	}
	raw, err := os.ReadFile("/usr/share/nginxpanel/capabilities.json")
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &capabilities) != nil || !releases.ValidChannel(capabilities.Version, "stable") {
		return errors.New("镜像能力清单缺少 Nginx 引擎版本")
	}
	pkg := releases.ContainerPackage{Schema: 1, Version: version, NginxVersion: capabilities.Version, Architecture: runtime.GOARCH, BinarySHA256: binary.SHA256, LauncherProtocol: releases.LauncherVersion, Images: map[string]string{"nginx": *nginx}}
	out, err := os.OpenFile(filepath.Join(*root, "containers.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	err = json.NewEncoder(out).Encode(pkg)
	return errors.Join(err, out.Close())
}
