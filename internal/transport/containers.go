package transport

import (
	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) containersReady(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := s.authorize(w, r, "read", "components.manage"); !ok {
		return false
	}
	if s.Agent == nil {
		s.fail(w, r, fault.Unavailable("Docker 容器管理服务未连接"))
		return false
	}
	return true
}
func (s *Server) GetDockerContainers(w http.ResponseWriter, r *http.Request) {
	if !s.containersReady(w, r) {
		return
	}
	out, err := s.Agent.DockerContainers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetDockerContainer(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	if !s.containersReady(w, r) {
		return
	}
	out, err := s.Agent.DockerContainer(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) GetDockerContainerLogs(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.GetDockerContainerLogsParams) {
	if !s.containersReady(w, r) {
		return
	}
	tail := 200
	if params.Tail != nil {
		tail = *params.Tail
	}
	out, err := s.Agent.DockerLogs(r.Context(), id, tail)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
