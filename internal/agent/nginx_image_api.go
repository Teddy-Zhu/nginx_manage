package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/imageupdates"
	"os"
)

func hostedNginxImage(r Record, active bool) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := validNginxImage(r); err != nil {
		return zero, err
	}
	p := r.NginxImage
	if len(p.Authorizations) == 0 {
		return zero, fault.Conflict("此镜像替换不是托管 API 原操作")
	}
	i, a := p.Intent, p.Authorizations[len(p.Authorizations)-1].Request
	in := nginxImageAPIInput(i.Input)
	o := imageupdates.Operation{Authorization: a, Protocol: Protocol, ID: r.OperationID, Input: in, RequestHash: imageupdates.Hash(r.OperationID, in), IntentSHA256: r.RequestHash, Sequence: a.Sequence, Command: a.Command, State: r.State, Stage: r.Stage, Error: r.Error, Failure: p.Failure, BeforeImage: i.Before.Image, TargetImage: i.Target.Image, BeforeImageID: i.Before.ImageID, TargetImageID: i.Target.ImageID, TargetVersion: i.Target.Capabilities.Version, PanelID: i.PanelID, Deadline: i.Deadline, UpdatedAt: r.UpdatedAt, Active: active, Finalized: nginxImageTerminal(r)}
	if p.Confirmation != nil {
		o.ReadyEpoch = p.Confirmation.ReadyEpoch
	}
	if !active && !o.Finalized {
		o.State = "recovery_required"
		if o.Error == "" {
			o.Error = "独立镜像服务未运行，须显式续办原操作"
		}
	}
	return o, o.Validate(r.OperationID, in)
}
func (s *Server) readNginxImageUpgrade(ctx context.Context, id string) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := s.imageUpgradeScope(); err != nil {
		return zero, err
	}
	if !validID(id) {
		return zero, fault.Invalid("Nginx 镜像替换操作标识无效")
	}
	r, err := NginxImageStatus(s.DataDir, id)
	if os.IsNotExist(err) {
		return zero, fault.NotFound("Nginx 镜像替换操作不存在")
	}
	if err != nil {
		return zero, err
	}
	_, active, err := nginxImageHost(ctx, s.DataDir, id)
	if err != nil {
		return zero, err
	}
	return hostedNginxImage(r, active)
}

func (s *Server) queueNginxImageUpgrade(ctx context.Context, req imageupdates.Request) (imageupdates.Operation, error) {
	var zero imageupdates.Operation
	if err := req.Validate(); err != nil {
		return zero, err
	}
	if req.Input.Component != imageupdates.Nginx {
		return zero, fault.Invalid("Nginx 镜像替换不能选择其他组件")
	}
	if err := s.imageUpgradeScope(); err != nil {
		return zero, err
	}
	r, err := NginxImageStatus(s.DataDir, req.OperationID)
	if err == nil {
		if _, err = hostedNginxImage(r, false); err != nil {
			return zero, err
		}
		a := r.NginxImage.Authorizations
		if req.Sequence <= len(a) {
			if a[req.Sequence-1].Request != req {
				return zero, fault.Conflict("原 Nginx 镜像替换授权不能改变")
			}
			return s.readNginxImageUpgrade(ctx, req.OperationID)
		}
		if req.Input != nginxImageAPIInput(r.NginxImage.Intent.Input) || r.NginxImage.Intent.Input.Stage.TrustPath != s.ReleaseTrust {
			return zero, fault.Conflict("原镜像目标、信任和维护会话不能改变")
		}
		_, err = resumeNginxImage(ctx, s.DataDir, req.OperationID, req.Epoch, &req)
	} else if os.IsNotExist(err) {
		if req.Sequence != 1 || req.Command != "upgrade" {
			return zero, fault.NotFound("续办的原 Nginx 镜像替换不存在")
		}
		in, inputErr := s.imageInput(ctx, req)
		if inputErr != nil {
			// Only a root absence proved under the transaction locks is a definitive
			// preflight rejection. Other failures retain uncertain-dispatch semantics.
			_, unlock, lockErr := nginxImageLocks(ctx, s.DataDir)
			if lockErr != nil {
				return zero, lockErr
			}
			defer unlock()
			_, readErr := NginxImageStatus(s.DataDir, req.OperationID)
			if os.IsNotExist(readErr) {
				return zero, fault.New(http.StatusConflict, "NGINX_IMAGE_REJECTED", panelRestoreError(inputErr))
			}
			if readErr != nil {
				return zero, readErr
			}
			return zero, fault.Conflict("原镜像替换已存在，请查询原操作")
		}
		_, err = queueNginxImage(ctx, NginxImageInput{Stage: in.Stage, Signature: in.Signature, Image: in.Image, MaintenanceID: in.MaintenanceID, AllowDowntime: req.Input.AllowDowntime}, req.OperationID, req.Epoch, &req)
	} else {
		return zero, err
	}
	if err != nil {
		return zero, err
	}
	return s.readNginxImageUpgrade(ctx, req.OperationID)
}

func (s *Server) nginxImageHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/nginx/images/upgrades/{id}", func(w http.ResponseWriter, r *http.Request) {
		o, err := s.readNginxImageUpgrade(r.Context(), r.PathValue("id"))
		componentReply(w, o, err)
	})
	mux.HandleFunc("POST /v1/nginx/images/upgrades", func(w http.ResponseWriter, r *http.Request) {
		var req imageupdates.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("Nginx 镜像替换请求无效"))
			return
		}
		o, err := s.queueNginxImageUpgrade(r.Context(), req)
		componentReply(w, o, err)
	})
}
