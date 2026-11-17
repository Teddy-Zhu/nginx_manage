package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"nginxpanel/internal/components"
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/frpscontainer"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/software"
)

func componentReply(w http.ResponseWriter, data any, err error) {
	status, code, message := 200, "OK", "成功"
	if err != nil {
		status, code, message = 503, "COMPONENT_UNAVAILABLE", "组件操作记录或执行器不可用"
		var known *fault.Error
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, struct {
		Protocol int    `json:"protocol"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		Data     any    `json:"data"`
	}{Protocol, code, message, data})
}
func (s *Server) componentHandlers(mux *http.ServeMux, m *components.Manager) {
	s.componentVersionHandlers(mux, m)
	s.containerHandlers(mux)
	s.componentOfflineHandlers(mux, m)
	s.fail2banContainerHandler(mux)
	mux.HandleFunc("GET /v1/components", func(w http.ResponseWriter, r *http.Request) {
		out := m.Overview()
		out.Versions = map[string]componentversions.Version{}
		if binding, err := nginxcontainer.Read(s.DataDir); err == nil && releases.VersionChannel(binding.SignedImage.Version) != "" {
			v := binding.SignedImage.Version
			out.Versions["nginx"] = componentversions.Version{ID: "nginx-v" + v, Version: v, SoftwareVersion: binding.Capabilities.Version, Channel: releases.VersionChannel(v)}
		}
		for _, app := range []string{"frps", "fail2ban"} {
			catalog, err := s.builtinVersions(r.Context(), componentversions.Query{SourceID: "builtin", AppID: app, Channel: "stable", Page: 1})
			if err != nil {
				out.Software.Error = err.Error()
			} else if catalog.Current != nil {
				out.Versions[app] = *catalog.Current
			}
		}
		if !s.Dev && s.ComponentScope == "host" {
			call, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			status := frpscontainer.Status(call, s.DataDir)
			out.Frps = &status
			cancel()
		}
		if !s.Dev && out.Software.Error == "" {
			call, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			software.Observe(call, s.DataDir, &out.Software)
			cancel()
		}
		out.Installation = s.Installation
		out.SwitchReason = "仅已运行的原生 Nginx 支持组件维护切换"
		if !s.Dev && s.ComponentScope == "host" && s.MaintenanceScope == "host" && s.Installation != nil && s.Nginx != nil && s.Nginx.Container == nil {
			if err := nginxSwitchServiceTemplate(s.DataDir); err == nil {
				out.SwitchAvailable, out.SwitchReason = true, ""
			} else {
				out.SwitchReason = "须由当前原生安装器登记独立切换服务"
			}
		}
		out.InstallReason = "仅当前原生未安装节点支持首次安装"
		if !s.Dev && s.ComponentScope == "host" && s.MaintenanceScope == "host" && s.Installation == nil {
			if err := installationTemplate(s.DataDir); err == nil {
				out.InstallAvailable, out.InstallReason = true, ""
			} else {
				out.InstallReason = "须由当前原生安装器登记独立安装服务"
			}
		}
		if s.Nginx != nil {
			call, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			state := s.Nginx.State(call)
			out.Running, out.RuntimeReason = state.Running, state.Reason
		} else {
			out.RuntimeReason = "未接入受管 Nginx 实例"
		}
		componentReply(w, out, nil)
	})
	mux.HandleFunc("GET /v1/components/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := m.Status(r.PathValue("id"))
		componentReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/components/operations", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		defer r.Body.Close()
		var in components.Request
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			componentReply(w, nil, fault.Invalid("组件操作请求格式无效"))
			return
		}
		out, err := m.Submit(in)
		componentReply(w, out, err)
	})
}
func (c *Client) ReadComponents(ctx context.Context) (components.Overview, error) {
	var out components.Overview
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components", nil, &out)
	return out, err
}
func (c *Client) SubmitComponent(ctx context.Context, in components.Request) (components.Operation, error) {
	var out components.Operation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/components/operations", in, &out)
	return out, err
}
func (c *Client) ComponentOperation(ctx context.Context, id string) (components.Operation, error) {
	if !components.ValidID(id) {
		return components.Operation{}, fault.Invalid("组件操作标识无效")
	}
	var out components.Operation
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components/operations/"+id, nil, &out)
	return out, err
}
