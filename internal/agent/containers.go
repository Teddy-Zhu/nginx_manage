package agent

import (
	"context"
	"net/http"
	"strconv"

	"nginxpanel/internal/containers"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/software"
)

func (s *Server) containersReady() error {
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" {
		return fault.Unavailable("当前环境无法管理宿主机 Docker 容器")
	}
	return nil
}
func (s *Server) containerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/docker/containers", func(w http.ResponseWriter, r *http.Request) {
		if err := s.containersReady(); err != nil {
			componentReply(w, nil, err)
			return
		}
		out, err := containers.List(r.Context())
		componentReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/docker/containers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.containersReady(); err != nil {
			componentReply(w, nil, err)
			return
		}
		out, err := containers.Inspect(r.Context(), r.PathValue("id"))
		componentReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/docker/containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if err := s.containersReady(); err != nil {
			componentReply(w, nil, err)
			return
		}
		tail, err := strconv.Atoi(r.URL.Query().Get("tail"))
		if err != nil {
			componentReply(w, nil, fault.Invalid("日志行数无效"))
			return
		}
		out, err := containers.ReadLogs(r.Context(), r.PathValue("id"), tail)
		componentReply(w, out, err)
	})
}
func (s *Server) manageDockerContainer(ctx context.Context, r software.Request, progress software.Progress) (software.Result, error) {
	if err := s.containersReady(); err != nil {
		return software.Result{}, err
	}
	if r.Container == nil {
		return software.Result{}, fault.Invalid("容器操作参数缺失")
	}
	message, err := containers.Run(ctx, *r.Container, progress)
	return software.Result{Message: message, Log: message}, err
}
func (c *Client) DockerContainers(ctx context.Context) (containers.Overview, error) {
	var out containers.Overview
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/docker/containers", nil, &out)
	return out, err
}
func (c *Client) DockerContainer(ctx context.Context, id string) (containers.Detail, error) {
	var out containers.Detail
	if !containers.ValidID(id) {
		return out, fault.Invalid("容器标识无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/docker/containers/"+id, nil, &out)
	return out, err
}
func (c *Client) DockerLogs(ctx context.Context, id string, tail int) (containers.Logs, error) {
	var out containers.Logs
	if !containers.ValidID(id) || tail < 1 || tail > 500 {
		return out, fault.Invalid("容器或日志行数无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/docker/containers/"+id+"/logs?tail="+strconv.Itoa(tail), nil, &out)
	return out, err
}
