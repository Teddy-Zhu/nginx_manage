package nginxcontainer

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func admitSource(in BindInput, launcherHash string, existing *Binding) (releases.ImageApproval, error) {
	var previous *releases.ImageApproval
	if existing != nil {
		previous = &existing.SignedImage
	}
	approval, _, err := releases.AdmitImage(in.Signature, "nginx", in.Image, previous)
	if err != nil {
		return approval, err
	}
	if launcherHash != approval.Image.Platform.LauncherSHA256 {
		return approval, errors.New("Nginx 启动器不属于签名镜像对应的发行程序")
	}
	return approval, nil
}

type SourceVerification struct {
	State       string                 `json:"state"`
	SignedImage releases.ImageApproval `json:"signed_image"`
}

// VerifySource checks the initial image identity before the host installer
// writes its intent or creates accounts. It never binds or starts an image.
func VerifySource(ctx context.Context, in BindInput) (SourceVerification, error) {
	var out SourceVerification
	if os.Geteuid() != 0 {
		return out, errors.New("Nginx 镜像来源核对需要本机 root")
	}
	if _, err := Path(in.DataDir); err != nil {
		return out, err
	}
	launcher, err := filepath.EvalSymlinks(in.LauncherBinary)
	if err != nil {
		return out, err
	}
	hash, err := secure.HashRootFile(launcher, binaryLimit)
	if err != nil {
		return out, err
	}
	var existing *Binding
	if prior, err := Read(in.DataDir); err == nil {
		existing = &prior
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	approval, err := admitSource(in, hash, existing)
	if err != nil {
		return out, err
	}
	d, err := newDocker()
	if err != nil {
		return out, err
	}
	defer d.Close()
	image, err := localImage(ctx, d, in.Image, approval.Image.Platform.ConfigDigest)
	if err != nil {
		return out, err
	}
	if err = imageBinary(ctx, d, image.ID, Bootstrap, hash); err != nil {
		return out, err
	}
	return SourceVerification{State: "image_source_verified", SignedImage: approval}, nil
}
