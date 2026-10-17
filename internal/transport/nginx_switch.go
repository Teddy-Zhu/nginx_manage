package transport

import (
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxswitch"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) switchesReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Switches == nil {
		s.fail(w, r, fault.Unavailable("组件切换服务未配置"))
		return false
	}
	return true
}
func (s *Server) ListNginxSwitches(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.switchesReady(w, r) {
		return
	}
	out, err := s.Switches.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetNginxSwitch(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.switchesReady(w, r) {
		return
	}
	out, err := s.Switches.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateNginxSwitch(w http.ResponseWriter, r *http.Request, params apigen.CreateNginxSwitchParams) {
	p, ok := s.authorize(w, r, true, "components.manage", "system.write")
	if !ok || !s.switchesReady(w, r) {
		return
	}
	var in struct {
		MaintenanceID      string  `json:"maintenance_id"`
		PrepareTaskID      string  `json:"prepare_task_id"`
		AssetID            string  `json:"asset_id"`
		AllowDowntime      *bool   `json:"allow_downtime"`
		ExpectedSHA256     string  `json:"expected_sha256"`
		ExpectedRevision   *string `json:"expected_revision"`
		ExpectedDeployment *string `json:"expected_deployment"`
	}
	if err := decodeLimit(w, r, &in, 4096); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.AllowDowntime == nil || !*in.AllowDowntime || in.ExpectedRevision == nil || in.ExpectedDeployment == nil {
		s.fail(w, r, fault.Invalid("须明确停机确认和当前完整发布标识"))
		return
	}
	out, err := s.Switches.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, nginxswitch.CreateInput{MaintenanceID: in.MaintenanceID, PrepareTaskID: in.PrepareTaskID, AssetID: in.AssetID, AllowDowntime: *in.AllowDowntime, ExpectedSHA256: in.ExpectedSHA256, ExpectedRevision: *in.ExpectedRevision, ExpectedDeployment: *in.ExpectedDeployment})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "组件切换任务已受理", out)
}
func (s *Server) nginxSwitchControl(w http.ResponseWriter, r *http.Request, id, key, command string) {
	p, ok := s.authorize(w, r, true, "components.manage", "system.write")
	if !ok || !s.switchesReady(w, r) {
		return
	}
	out, err := s.Switches.Control(r.Context(), p, r.Context().Value(requestIDKey).(string), key, id, command)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "原切换控制请求已受理", out)
}
func (s *Server) ResumeNginxSwitch(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.ResumeNginxSwitchParams) {
	s.nginxSwitchControl(w, r, id, params.IdempotencyKey, "resume")
}
func (s *Server) RollbackNginxSwitch(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.RollbackNginxSwitchParams) {
	s.nginxSwitchControl(w, r, id, params.IdempotencyKey, "rollback")
}
