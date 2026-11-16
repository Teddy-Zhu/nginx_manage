package nginxcontainer

import (
	"context"
	"errors"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/releases"
)

func inspectNginxBootstrap(ctx context.Context, d *dockerClient, image imageInfo, a releases.ImageApproval) (string, error) {
	protocol := a.Image.Platform.LauncherProtocol
	if a.LocalBuild {
		protocol = releases.LauncherVersion
	}
	if err := verifyImageLauncherProtocol(image, protocol); err != nil {
		return "", err
	}
	actual, err := imageBinaryHash(ctx, d, image.ID, Bootstrap, nil)
	if err != nil {
		return "", err
	}
	files, err := imageMetadata(ctx, d, image.ID)
	if err != nil {
		return "", err
	}
	declared, err := checksum(files["launcher.sha256"], Bootstrap)
	if err != nil || declared != actual {
		return "", errors.New("Nginx 镜像bootstrap与其完整性清单不一致")
	}
	if a.LocalBuild && actual != a.Image.Platform.LauncherSHA256 {
		return "", errors.New("本地Nginx镜像bootstrap与安装包散列不一致")
	}
	return actual, nil
}

// InspectSignedImage only reads an image and a stopped metadata container. It
// verifies the signed platform configuration and launcher bytes without running
// any image program or changing an existing runtime binding.
func InspectSignedImage(ctx context.Context, a releases.ImageApproval) error {
	if err := a.Validate(a.Image.ID, a.Image.Reference, a.Image.Platform.ConfigDigest, a.Image.Platform.LauncherSHA256); err != nil {
		return err
	}
	d, err := newDocker()
	if err != nil {
		return err
	}
	defer d.Close()
	image, err := localImage(ctx, d, a.Image.Reference, a.Image.Platform.ConfigDigest)
	if err != nil {
		return err
	}
	if a.Image.ID == "nginx" {
		_, err = inspectNginxBootstrap(ctx, d, image, a)
		return err
	}
	return imageBinary(ctx, d, image.ID, "/usr/local/bin/nginxpanel-launcher", a.Image.Platform.LauncherSHA256)
}

// Only an authoritative image absence permits a download. Unavailable Docker,
// image drift and metadata errors cannot be converted to a new pull attempt.
func PullSignedImage(ctx context.Context, a releases.ImageApproval) (bool, error) {
	if err := a.Validate(a.Image.ID, a.Image.Reference, a.Image.Platform.ConfigDigest, a.Image.Platform.LauncherSHA256); err != nil {
		return false, err
	}
	err := InspectSignedImage(ctx, a)
	if err == nil {
		return true, nil
	}
	var status *dockerapi.StatusError
	if !errors.As(err, &status) || status.StatusCode != 404 {
		return false, err
	}
	// An archive endpoint can also return 404; distinguish a missing image from
	// a present image whose signed launcher path cannot be read.
	d, e := newDocker()
	if e != nil {
		return false, e
	}
	_, e = localImage(ctx, d, a.Image.Reference, a.Image.Platform.ConfigDigest)
	d.Close()
	if !errors.As(e, &status) || status.StatusCode != 404 {
		return false, err
	}
	if err = dockerapi.Pull(ctx, a.Image.Reference, a.Image.Platform.Architecture); err != nil {
		return false, err
	}
	return false, InspectSignedImage(ctx, a)
}
