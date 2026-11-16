package components

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
)

type Image struct {
	ID             string `json:"id"`
	Reference      string `json:"reference"`
	Architecture   string `json:"architecture"`
	PlatformDigest string `json:"platform_digest"`
	ConfigDigest   string `json:"config_digest"`
}
type ImagePreparation struct {
	Choice     Image `json:"choice"`
	ApprovedAt int64 `json:"approved_at"`
	Reused     bool  `json:"reused"`
}

func imageChoice(c releases.ImageChoice) Image {
	return Image{ID: c.ID, Reference: c.Reference, Architecture: c.Platform.Architecture, PlatformDigest: c.Platform.Digest, ConfigDigest: c.Platform.ConfigDigest}
}
func images(p releases.Plan) []Image {
	out := []Image{}
	for _, image := range p.Manifest.Images {
		if !slices.Contains(p.Selected, "image-"+image.ID) {
			continue
		}
		for _, platform := range image.Platforms {
			if platform.OS == runtime.GOOS && platform.Architecture == runtime.GOARCH {
				out = append(out, imageChoice(releases.ImageChoice{ID: image.ID, Reference: image.Repository + "@" + image.Digest, Platform: platform, Evidence: image.Evidence}))
			}
		}
	}
	return out
}
func imageSelection(id string) (token, component string, panelStaging bool, ok bool) {
	if id != "nginx" {
		return "", "", false, false
	}
	token, ok = releases.ImageToken(id)
	return token, "nginx", false, ok
}
func (i Image) valid(repository string) bool {
	path := "nginx"
	if i.ID == "panel-launcher" {
		path = "panel"
	} else if i.ID != "nginx" {
		return false
	}
	prefix := "ghcr.io/" + strings.ToLower(repository) + "/" + path + "@sha256:"
	return i.Architecture == runtime.GOARCH && strings.HasPrefix(i.Reference, prefix) && digest(strings.TrimPrefix(i.Reference, prefix)) && strings.HasPrefix(i.PlatformDigest, "sha256:") && digest(strings.TrimPrefix(i.PlatformDigest, "sha256:")) && strings.HasPrefix(i.ConfigDigest, "sha256:") && digest(strings.TrimPrefix(i.ConfigDigest, "sha256:"))
}
func (s *Service) validateImageParent(ctx context.Context, tx *sql.Tx, principal string, in CreateInput, now int64) error {
	var state string
	var sealed []byte
	err := tx.QueryRowContext(ctx, "SELECT t.state,o.result FROM component_operations o JOIN tasks t ON t.id=o.task_id WHERE o.task_id=? AND o.principal=? AND t.kind='component.prepare'", in.PrepareTaskID, principal).Scan(&state, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound("面板准备任务不存在")
	}
	if err != nil {
		return err
	}
	token, _, _, ok := imageSelection(in.Input.ImageID)
	if !ok {
		return fault.Invalid("签名镜像组件无效")
	}
	if state != "succeeded" || len(sealed) == 0 {
		return fault.Conflict("须先完成签名镜像准备")
	}
	raw, err := s.Vault.Open(sealed, "components:result:"+in.PrepareTaskID)
	if err != nil {
		return err
	}
	var prepared Operation
	if err = json.Unmarshal(raw, &prepared); err != nil {
		return err
	}
	if err = prepared.Validate(Request{Protocol: prepared.Protocol, OperationID: prepared.ID, Input: prepared.Input}); err != nil {
		return err
	}
	r := prepared.Release
	if prepared.Input.Action != "prepare" || r == nil || !prepared.RuntimeReady || r.ExpiresAt <= now || in.Input.OfflineID != prepared.Input.OfflineID || in.Input.Tag != r.Tag || in.Input.Prerelease != prepared.Input.Prerelease || in.Input.PlanID != r.PlanID || in.Input.ManifestSHA256 != r.ManifestSHA256 || in.Input.TrustSHA256 != r.TrustSHA256 || !sameAssets(in.Input.Assets, []string{token}) || !sameAssets(in.Input.Assets, r.Selected) || len(r.Assets) != 0 || len(r.Images) != 1 || r.Images[0].ID != in.Input.ImageID {
		return fault.Conflict("镜像拉取请求与本人签名面板准备结果不一致或已过期")
	}
	return nil
}
func (m *Manager) imageSource(ctx context.Context, out *Operation, recover bool) (releases.Result, error) {
	in := out.Input
	token, allowed, panelStaging, ok := imageSelection(in.ImageID)
	if !ok || !sameAssets(in.Assets, []string{token}) {
		return releases.Result{}, errors.New("镜像准备选择与目标组件不一致")
	}
	sourceInput := releases.Input{TrustPath: m.TrustPath, Assets: []string{token}, AllowedComponents: []string{allowed}, AllowPrerelease: in.Prerelease, Host: m.host(), Receiver: receiver(), PanelStaging: panelStaging}
	var source releases.Result
	var err error
	if recover {
		if out.Image == nil || out.Release == nil {
			return source, errors.New("镜像下载尚未发布签名意图")
		}
		source, err = releases.Installed(ctx, sourceInput, in.PlanID, out.Image.ApprovedAt, out.Release.TrustSHA256)
	} else {
		source, err = releases.Prepared(ctx, sourceInput, in.PlanID)
	}
	if err != nil {
		return source, err
	}
	p := source.Plan
	if len(p.Assets) != 0 || !sameAssets(p.Selected, []string{token}) || p.ID != in.PlanID || p.ManifestSHA256 != in.ManifestSHA256 || p.TrustSHA256 != in.TrustSHA256 || releases.ManifestTag(p.Manifest) != in.Tag {
		return source, releases.ErrReleaseChanged
	}
	return source, nil
}
func (m *Manager) pullImage(ctx context.Context, out *Operation) error {
	source, err := m.imageSource(ctx, out, false)
	if err != nil {
		return err
	}
	reference := ""
	for _, image := range images(source.Plan) {
		if image.ID == out.Input.ImageID {
			reference = image.Reference
		}
	}
	if reference == "" {
		return errors.New("准备发行没有所选平台镜像")
	}
	approval, _, err := releases.AdmitImage(releases.ImageInput{TrustPath: m.TrustPath, ManifestPath: filepath.Join(source.Directory, "release-manifest.json"), SignaturePath: filepath.Join(source.Directory, "release-manifest.sig"), ExpectedManifestSHA256: out.Input.ManifestSHA256, AllowPrerelease: out.Input.Prerelease, PanelStaging: out.Input.ImageID == "panel-launcher"}, out.Input.ImageID, reference, nil)
	if err != nil {
		return err
	}
	if approval.TrustSHA256 != out.Input.TrustSHA256 {
		return releases.ErrReleaseChanged
	}
	r := release(source.Plan)
	out.Release = &r
	out.Image = &ImagePreparation{Choice: imageChoice(approval.Image), ApprovedAt: approval.ApprovedAt}
	out.Stage = "pulling"
	if err = m.write(out); err != nil {
		return err
	}
	reused, err := nginxcontainer.PullSignedImage(ctx, approval)
	if err != nil {
		return err
	}
	out.Image.Reused = reused
	// Reauthenticate current keys after the network operation before confirming.
	if _, err = m.imageSource(ctx, out, true); err != nil {
		return err
	}
	out.State, out.Stage, out.RuntimeReady = "succeeded", "image_ready", true
	return nil
}
func (m *Manager) reconcileImage(ctx context.Context, out *Operation) error {
	source, err := m.imageSource(ctx, out, true)
	if err != nil {
		return err
	}
	p := source.Plan
	var approval releases.ImageApproval
	for _, image := range p.Manifest.Images {
		if image.ID != out.Input.ImageID {
			continue
		}
		for _, platform := range image.Platforms {
			if platform.OS == runtime.GOOS && platform.Architecture == runtime.GOARCH {
				approval = releases.ImageApproval{Schema: releases.Schema, Repository: p.Manifest.Repository, Version: p.Manifest.Version, Commit: image.Commit, KeyID: p.KeyID, ManifestSHA256: p.ManifestSHA256, TrustSHA256: p.TrustSHA256, TrustPath: m.TrustPath, Prerelease: out.Input.Prerelease, ApprovedAt: out.Image.ApprovedAt, Image: releases.ImageChoice{ID: image.ID, Reference: image.Repository + "@" + image.Digest, Platform: platform, Evidence: image.Evidence}}
			}
		}
	}
	if out.Image.Choice != imageChoice(approval.Image) {
		return errors.New("镜像下载回执偏离原签名意图")
	}
	if err = nginxcontainer.InspectSignedImage(ctx, approval); err != nil {
		return err
	}
	out.Image.Reused = true
	out.State, out.Stage, out.ErrorCode, out.Error, out.RuntimeReady = "succeeded", "image_ready", "", "", true
	return nil
}
