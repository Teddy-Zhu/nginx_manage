package panelruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func signedWeb(files map[string]File, asset releases.Asset) error {
	count := 0
	for _, file := range asset.Files {
		if !strings.HasPrefix(file.Path, "web/") {
			continue
		}
		count++
		actual, ok := files[strings.TrimPrefix(file.Path, "web/")]
		if !ok || file.Mode != 0644 || actual.SHA256 != file.SHA256 || actual.Size != file.Size {
			return errors.New("前端文件不属于签名面板发行")
		}
	}
	if count == 0 || count != len(files) {
		return errors.New("前端文件清单与签名面板发行不一致")
	}
	return nil
}

type SourceVerification struct {
	State       string                 `json:"state"`
	Release     Release                `json:"release"`
	SignedImage releases.ImageApproval `json:"signed_image"`
}

// VerifySource authenticates the initial image/program/frontend combination.
// It publishes no host state and never starts a service or container. Docker
// metadata containers are created stopped and removed before returning success.
func VerifySource(ctx context.Context, in BindInput) (SourceVerification, error) {
	var out SourceVerification
	if os.Geteuid() != 0 {
		return out, errors.New("面板来源核对需要本机 root")
	}
	if _, err := Root(in.DataDir); err != nil {
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
	launcher, err := filepath.EvalSymlinks(in.LauncherBinary)
	if err != nil {
		return out, err
	}
	var previous *releases.ImageApproval
	if prior, err := ReadDeployment(in.DataDir); err == nil {
		if prior.Mode != "docker" {
			return out, errors.New("已有原生面板绑定，不能直接改为容器部署")
		}
		previous = &prior.SignedImage
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	approval, asset, err := releases.AdmitImage(in.Signature, "panel-launcher", in.Image, previous)
	if err != nil {
		return out, err
	}
	binaryHash, err := secure.HashRootFile(binary, BinaryLimit)
	if err != nil {
		return out, err
	}
	launcherHash, err := secure.HashRootFile(launcher, BinaryLimit)
	if err != nil {
		return out, err
	}
	if binaryHash != approval.Image.Platform.LauncherSHA256 || launcherHash != binaryHash {
		return out, errors.New("面板程序及 launcher 必须属于签名镜像对应的同一发行")
	}
	if err = executable(launcher, launcherHash); err != nil {
		return out, err
	}
	r, err := describe(ctx, binary)
	if err != nil {
		return out, err
	}
	if r.BinarySHA256 != binaryHash || r.Version != approval.Version {
		return out, errors.New("面板程序版本或内容与签名批准不一致")
	}
	r.Web, err = inventory(web, false)
	if err != nil {
		return out, err
	}
	if err = signedWeb(r.Web, asset); err != nil {
		return out, err
	}
	r.ID = releaseID(r)
	if err = r.validate(); err != nil {
		return out, err
	}
	if err = nginxcontainer.InspectPanelImage(ctx, in.Image, approval.Image.Platform.ConfigDigest, launcherHash); err != nil {
		return out, err
	}
	return SourceVerification{State: "image_source_verified", Release: r, SignedImage: approval}, nil
}
