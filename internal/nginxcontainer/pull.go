package nginxcontainer

import (
	"context"
	"errors"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/releases"
)

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
	path := Bootstrap
	if a.Image.ID == "panel-launcher" {
		path = "/usr/local/bin/nginxpanel-launcher"
	}
	return imageBinary(ctx, d, image.ID, path, a.Image.Platform.LauncherSHA256)
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
