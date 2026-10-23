package transport

import (
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) installationsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Installations == nil {
		s.fail(w, r, fault.Unavailable("首次安装服务未配置"))
		return false
	}
	return true
}
func (s *Server) ListNginxInstallations(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.installationsReady(w, r) {
		return
	}
	out, err := s.Installations.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetNginxInstallation(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, "read", "components.manage")
	if !ok || !s.installationsReady(w, r) {
		return
	}
	out, err := s.Installations.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateNginxInstallation(w http.ResponseWriter, r *http.Request, params apigen.CreateNginxInstallationParams) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.installationsReady(w, r) {
		return
	}
	var in struct {
		MaintenanceID string `json:"maintenance_id"`
		PrepareTaskID string `json:"prepare_task_id"`
		AssetID       string `json:"asset_id"`
		Start         *bool  `json:"start"`
		Enable        *bool  `json:"enable"`
	}
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Start == nil || in.Enable == nil {
		s.fail(w, r, fault.Invalid("须明确是否立即启动和设置开机启动"))
		return
	}
	out, err := s.Installations.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, nginxinstall.CreateInput{MaintenanceID: in.MaintenanceID, PrepareTaskID: in.PrepareTaskID, AssetID: in.AssetID, Start: *in.Start, Enable: *in.Enable})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "首次安装任务已受理", out)
}
func (s *Server) installationControl(w http.ResponseWriter, r *http.Request, id, key, command string) {
	p, ok := s.authorize(w, r, "components.manage", "system.write")
	if !ok || !s.installationsReady(w, r) {
		return
	}
	out, err := s.Installations.Control(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, command)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原安装控制请求已受理", out)
}
func (s *Server) ResumeNginxInstallation(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumeNginxInstallationParams) {
	s.installationControl(w, r, id, params.IdempotencyKey, "resume")
}
func (s *Server) CancelNginxInstallation(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.CancelNginxInstallationParams) {
	s.installationControl(w, r, id, params.IdempotencyKey, "cancel")
}
