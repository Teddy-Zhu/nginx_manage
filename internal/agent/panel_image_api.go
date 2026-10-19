package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
)

func hostedPanelImage(r Record, active bool) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := validPanelImage(r); err != nil {
		return zero, err
	}
	p := r.PanelImage
	if len(p.Authorizations) == 0 {
		return zero, fault.Conflict("此镜像替换不是托管 API 原操作")
	}
	i, a := p.Intent, p.Authorizations[len(p.Authorizations)-1].Request
	in := panelImageAPIInput(i.Input)
	o := imageupdates.Operation{Authorization: a, Protocol: Protocol, ID: r.OperationID, Input: in, RequestHash: imageupdates.Hash(r.OperationID, in), IntentSHA256: r.RequestHash, Sequence: a.Sequence, Command: a.Command, State: r.State, Stage: r.Stage, Error: r.Error, Failure: p.Failure, BeforeImage: i.Before.Image, TargetImage: i.Target.Image, BeforeImageID: i.Before.ImageID, TargetImageID: i.Target.ImageID, TargetVersion: i.Target.SignedImage.Version, PanelID: i.PanelID, Deadline: i.Deadline, UpdatedAt: r.UpdatedAt, Active: active, Finalized: panelImageTerminal(r)}
	if p.Ready != nil {
		o.ReadyEpoch = p.Ready.Application.Maintenance.Epoch
	}
	if p.RollbackReady != nil {
		o.ReadyEpoch = p.RollbackReady.Application.Maintenance.Epoch
	}
	if !active && !o.Finalized {
		o.State = "recovery_required"
		if o.Error == "" {
			o.Error = "独立镜像服务未运行，须显式续办原操作"
		}
	}
	return o, o.Validate(r.OperationID, in)
}
func (s *Server) imageUpgradeScope() error {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" || s.ReleaseTrust != "/etc/nginxpanel/release-trust.json" {
		return fault.Unavailable("镜像替换的宿主机范围或固定发布信任未配置")
	}
	return nil
}
func (s *Server) readPanelImageUpgrade(ctx context.Context, id string) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := s.imageUpgradeScope(); err != nil {
		return zero, err
	}
	if !validID(id) {
		return zero, fault.Invalid("面板镜像替换操作标识无效")
	}
	r, err := PanelImageStatus(s.DataDir, id)
	if os.IsNotExist(err) {
		return zero, fault.NotFound("面板镜像替换操作不存在")
	}
	if err != nil {
		return zero, err
	}
	_, active, err := panelImageHost(ctx, s.DataDir, id)
	if err != nil {
		return zero, err
	}
	return hostedPanelImage(r, active)
}

// Resolve both reference and offline paths from the exact root-owned prepared
// plan. A Web request cannot select a registry, path, trust file or timestamp.
func (s *Server) imageInput(ctx context.Context, req imageupdates.Request) (PanelImageInput, error) {
	var out PanelImageInput
	stage := panelruntime.StageInput{DataDir: s.DataDir, PlanID: req.Input.PlanID, TrustPath: s.ReleaseTrust, AllowPrerelease: req.Input.Prerelease}
	staged, err := panelruntime.Staged(ctx, stage)
	if err != nil {
		return out, err
	}
	a := staged.Approval
	source, err := releases.Installed(ctx, releases.Input{TrustPath: s.ReleaseTrust, Assets: []string{"panel-linux-" + runtime.GOARCH}, AllowedComponents: []string{"panel"}, AllowPrerelease: req.Input.Prerelease, Host: a.Host, Receiver: a.Receiver}, req.Input.PlanID, a.ApprovedAt, a.TrustSHA256)
	if err != nil {
		return out, err
	}
	image := ""
	for _, candidate := range source.Plan.Manifest.Images {
		if candidate.ID == req.Input.Component {
			image = candidate.Repository + "@" + candidate.Digest
		}
	}
	if image == "" {
		return out, errors.New("签名准备任务未提供所选组件镜像")
	}
	return PanelImageInput{Stage: stage, MaintenanceID: req.Input.MaintenanceID, Image: image, Signature: releases.ImageInput{TrustPath: s.ReleaseTrust, ManifestPath: filepath.Join(source.Directory, "release-manifest.json"), SignaturePath: filepath.Join(source.Directory, "release-manifest.sig"), ExpectedManifestSHA256: a.ManifestSHA256, AllowPrerelease: req.Input.Prerelease}}, nil
}

func (s *Server) queuePanelImageUpgrade(ctx context.Context, req imageupdates.Request) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := req.Validate(); err != nil {
		return zero, err
	}
	if req.Input.Component != imageupdates.Panel {
		return zero, fault.Invalid("面板镜像替换不能选择其他组件")
	}
	if err := s.imageUpgradeScope(); err != nil {
		return zero, err
	}
	r, err := PanelImageStatus(s.DataDir, req.OperationID)
	if err == nil {
		if _, err = hostedPanelImage(r, false); err != nil {
			return zero, err
		}
		a := r.PanelImage.Authorizations
		if req.Sequence <= len(a) {
			if a[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原面板镜像替换授权不能改变")
			}
			return s.readPanelImageUpgrade(ctx, req.OperationID)
		}
		if req.Input != panelImageAPIInput(r.PanelImage.Intent.Input) || r.PanelImage.Intent.Input.Stage.TrustPath != s.ReleaseTrust {
			return zero, fault.Conflict("原镜像目标、信任和维护会话不能改变")
		}
		_, err = resumePanelImage(ctx, s.DataDir, req.OperationID, req.Epoch, &req)
	} else if os.IsNotExist(err) {
		if req.Sequence != 1 || req.Command != "upgrade" {
			return zero, fault.NotFound("续办的原面板镜像替换不存在")
		}
		in, inputErr := s.imageInput(ctx, req)
		if inputErr != nil {
			// Only a root absence proved under the transaction locks is a definitive
			// preflight rejection. Other failures retain uncertain-dispatch semantics.
			_, unlock, lockErr := panelImageLocks(ctx, s.DataDir)
			if lockErr != nil {
				return zero, lockErr
			}
			defer unlock()
			_, readErr := PanelImageStatus(s.DataDir, req.OperationID)
			if os.IsNotExist(readErr) {
				return zero, fault.New(http.StatusConflict, "PANEL_IMAGE_REJECTED", panelRestoreError(inputErr))
			}
			if readErr != nil {
				return zero, readErr
			}
			return zero, fault.Conflict("原镜像替换已存在，请查询原操作")
		}
		_, err = queuePanelImage(ctx, in, req.OperationID, req.Epoch, &req)
	} else {
		return zero, err
	}
	if err != nil {
		return zero, err
	}
	return s.readPanelImageUpgrade(ctx, req.OperationID)
}

func (s *Server) panelImageHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/panel/images/upgrades/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, err := s.readPanelImageUpgrade(r.Context(), r.PathValue("id"))
		componentReply(w, o, err)
	})
	mux.HandleFunc("POST /v1/panel/images/upgrades", func(w http.ResponseWriter, r *http.Request) {
		var req imageupdates.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("面板镜像替换请求无效"))
			return
		}
		o, err := s.queuePanelImageUpgrade(r.Context(), req)
		componentReply(w, o, err)
	})
}
func imageUpgradePath(component string) (string, error) {
	switch component {
	case imageupdates.Panel:
		return "/v1/panel/images/upgrades", nil
	case imageupdates.Nginx:
		return "/v1/nginx/images/upgrades", nil
	default:
		return "", fault.Invalid("镜像组件无效")
	}
}
func (c *Client) ImageUpgrade(ctx context.Context, component, id string) (imageupdates.Operation, error) {
	var out imageupdates.Operation
	if !validID(id) {
		return out, fault.Invalid("镜像替换操作标识无效")
	}
	path, err := imageUpgradePath(component)
	if err != nil {
		return out, err
	}
	err = c.envelopeRequest(ctx, http.MethodGet, path+"/"+id, nil, &out)
	if err == nil {
		err = out.Validate(id, out.Input)
		if err == nil && out.Input.Component != component {
			err = fault.Conflict("镜像替换回执组件不一致")
		}
	}
	return out, err
}
func (c *Client) SubmitImageUpgrade(ctx context.Context, in imageupdates.Request) (imageupdates.Operation, error) {
	var out imageupdates.Operation
	if err := in.Validate(); err != nil {
		return out, err
	}
	path, err := imageUpgradePath(in.Input.Component)
	if err != nil {
		return out, err
	}
	err = c.envelopeRequest(ctx, http.MethodPost, path, in, &out)
	if err == nil {
		err = out.Validate(in.OperationID, in.Input)
	}
	return out, err
}
