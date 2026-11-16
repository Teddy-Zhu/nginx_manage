package agent

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/releases"
)

type nginxImageSource struct {
	Plan      releases.Plan
	Choice    releases.ImageChoice
	Signature releases.ImageInput
}

func preparedNginxImageSource(ctx context.Context, stage panelruntime.StageInput) (nginxImageSource, error) {
	var out nginxImageSource
	if stage.DataDir == "" || stage.PlanID == "" || stage.TrustPath != "/etc/nginxpanel/release-trust.json" {
		return out, errors.New("Nginx镜像计划位置或本机信任无效")
	}
	info := platform.Detect()
	token, ok := releases.ImageToken("nginx")
	if !ok {
		return out, errors.New("签名发行未提供 Nginx 镜像选择器")
	}
	source, err := releases.Prepared(ctx, releases.Input{
		TrustPath: stage.TrustPath, Assets: []string{token}, AllowedComponents: []string{"nginx"},
		AllowPrerelease: stage.AllowPrerelease,
		Host:            releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: info.OS, Version: info.Version},
		Receiver:        releases.Receiver{APIMajor: 1, AgentProtocol: Protocol, Launcher: releases.LauncherVersion},
	}, stage.PlanID)
	if err != nil {
		return out, err
	}
	p := source.Plan
	if len(p.Assets) != 0 || len(p.Selected) != 1 || p.Selected[0] != token || p.ID != stage.PlanID {
		return out, errors.New("Nginx更新须引用独立签名镜像计划")
	}
	choice, ok := releases.PlanImage(p, token)
	if !ok || choice.ID != "nginx" {
		return out, errors.New("签名发行未提供当前架构的Nginx镜像")
	}
	out = nginxImageSource{
		Plan:   p,
		Choice: choice,
		Signature: releases.ImageInput{
			TrustPath:              stage.TrustPath,
			ManifestPath:           filepath.Join(source.Directory, "release-manifest.json"),
			SignaturePath:          filepath.Join(source.Directory, "release-manifest.sig"),
			ExpectedManifestSHA256: p.ManifestSHA256,
			AllowPrerelease:        stage.AllowPrerelease,
		},
	}
	return out, nil
}

func nginxImageApprovalHash(plan releases.Plan, choice releases.ImageChoice) string {
	return selectionValueHash(struct {
		PlanID, ManifestSHA256, TrustSHA256 string
		Image                               releases.ImageChoice
	}{plan.ID, plan.ManifestSHA256, plan.TrustSHA256, choice})
}

func admitNginxImageSource(ctx context.Context, stage panelruntime.StageInput, signature releases.ImageInput, image string, prior *releases.ImageApproval) (releases.ImageApproval, string, error) {
	var zero releases.ImageApproval
	source, err := preparedNginxImageSource(ctx, stage)
	if err != nil {
		return zero, "", err
	}
	if signature != source.Signature || image != source.Choice.Reference {
		return zero, "", releases.ErrReleaseChanged
	}
	approval, _, err := releases.AdmitImage(signature, "nginx", image, prior)
	if err != nil {
		return zero, "", err
	}
	if approval.TrustSHA256 != source.Plan.TrustSHA256 || approval.Image != source.Choice {
		return zero, "", releases.ErrReleaseChanged
	}
	return approval, nginxImageApprovalHash(source.Plan, source.Choice), nil
}
