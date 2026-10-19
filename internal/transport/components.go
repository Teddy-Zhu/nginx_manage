package transport

import (
	"net/http"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) componentsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.Components == nil {
		s.fail(w, r, fault.Unavailable("组件服务未配置"))
		return false
	}
	return true
}
func (s *Server) GetComponents(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	out, err := s.Components.Overview(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) ListComponentTasks(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	out, err := s.Components.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateComponentTask(w http.ResponseWriter, r *http.Request, params apigen.CreateComponentTaskParams) {
	p, ok := s.authorize(w, r, true, "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	var in components.CreateInput
	if err := decodeLimit(w, r, &in, 16<<10); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Input.Action == "activate" {
		s.fail(w, r, fault.Invalid("前端激活须使用独立确认入口"))
		return
	}
	out, err := s.Components.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "组件任务已排队", out)
}

func (s *Server) CreateFrontendActivation(w http.ResponseWriter, r *http.Request, params apigen.CreateFrontendActivationParams) {
	p, ok := s.authorize(w, r, true, "components.manage", "system.write")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	var in components.CreateInput
	if err := decodeLimit(w, r, &in, 16<<10); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Input.Action != "activate" {
		s.fail(w, r, fault.Invalid("此入口只接受独立前端激活"))
		return
	}
	out, err := s.Components.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusAccepted, "OK", "前端激活任务已排队", out)
}
