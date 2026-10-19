package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"runtime"
	"time"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
)

// Initial deployment can download a signed image before a panel exists. This
// command never activates it or supplies registry credentials from user input.
func runReleaseImagePull(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("镜像拉取仅允许目标宿主机 root")
	}
	f := flag.NewFlagSet("release-image-pull", flag.ContinueOnError)
	component := f.String("component", "", "panel-launcher or nginx")
	trust := f.String("release-trust", "/etc/nginxpanel/release-trust.json", "root-approved release trust")
	manifest := f.String("release-manifest", "", "signed manifest path")
	signature := f.String("release-signature", "", "signature envelope path")
	expected := f.String("release-manifest-sha256", "", "independently approved manifest SHA-256")
	prerelease := f.Bool("release-prerelease", false, "explicitly allow prerelease")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || (*component != "panel-launcher" && *component != "nginx") || *trust != "/etc/nginxpanel/release-trust.json" || len(*expected) != 64 {
		return errors.New("须选择固定镜像组件、本机固定信任和预期清单 SHA-256")
	}
	host := platform.Detect()
	input := releases.Input{TrustPath: *trust, ManifestPath: *manifest, SignaturePath: *signature, AllowPrerelease: *prerelease, Host: releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: host.OS, Version: host.Version}, Receiver: releases.Receiver{APIMajor: 1, AgentProtocol: protocol.Agent, Launcher: releases.LauncherVersion}}
	input.PanelStaging = *component == "panel-launcher"
	verified, err := releases.VerifyImages(input)
	if err != nil {
		return err
	}
	reference := ""
	for _, image := range verified.Images {
		if image.ID == *component {
			reference = image.Reference
		}
	}
	if reference == "" {
		return errors.New("签名清单不含本机平台镜像")
	}
	imageInput := releases.ImageInput{TrustPath: *trust, ManifestPath: *manifest, SignaturePath: *signature, ExpectedManifestSHA256: *expected, AllowPrerelease: *prerelease, PanelStaging: *component == "panel-launcher"}
	approval, _, err := releases.AdmitImage(imageInput, *component, reference, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	reused, err := nginxcontainer.PullSignedImage(ctx, approval)
	if err != nil {
		return err
	}
	if _, _, err = releases.AdmitImage(imageInput, *component, reference, &approval); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		State    string                 `json:"state"`
		Approval releases.ImageApproval `json:"approval"`
		Reused   bool                   `json:"reused"`
	}{"image_ready", approval, reused})
}
