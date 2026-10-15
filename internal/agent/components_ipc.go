package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
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
	mux.HandleFunc("GET /v1/components", func(w http.ResponseWriter, r *http.Request) { componentReply(w, m.Overview(), nil) })
	mux.HandleFunc("GET /v1/components/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := m.Status(r.PathValue("id"))
		componentReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/components/operations", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
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
