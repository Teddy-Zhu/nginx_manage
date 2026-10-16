package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/secure"
)

type listenerRequest struct {
	Protocol     int                 `json:"protocol"`
	OperationID  string              `json:"operation_id"`
	Input        *remotelisten.Input `json:"input,omitempty"`
	Action       string              `json:"action,omitempty"`
	ConnectionID string              `json:"connection_id,omitempty"`
}

func listenerReply(w http.ResponseWriter, data any, err error) {
	if os.IsNotExist(err) {
		err = fault.New(404, "LISTENER_OPERATION_MISSING", "监听操作记录不存在")
	}
	// Reuse the internal Agent envelope; it never exposes unknown root errors.
	if err != nil {
		if _, ok := err.(*fault.Error); !ok {
			err = fault.Unavailable("独立监听操作不可用，请从回环入口检查状态")
		}
	}
	dnsReply(w, data, err)
}
func (s *Server) listenerHandlers(mux *http.ServeMux, m *remoteListener) {
	mux.HandleFunc("GET /v1/management-listener", func(w http.ResponseWriter, r *http.Request) { listenerReply(w, m.view(), nil) })
	mux.HandleFunc("GET /v1/management-listener/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			listenerReply(w, nil, fault.Invalid("监听操作 ID 无效"))
			return
		}
		out, err := m.operation(id)
		listenerReply(w, out, err)
	})
	for _, action := range []string{"apply", "decide"} {
		mux.HandleFunc("POST /v1/management-listener/"+action, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 40<<10)
			defer r.Body.Close()
			var in listenerRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Protocol != Protocol || !validID(in.OperationID) || in.ConnectionID != "" && !validID(in.ConnectionID) {
				listenerReply(w, nil, fault.Invalid("监听请求协议无效"))
				return
			}
			if action == "apply" {
				if in.Input == nil || in.Action != "" {
					listenerReply(w, nil, fault.Invalid("监听配置请求无效"))
					return
				}
				encoded, err := json.Marshal(in.Input)
				if err != nil {
					listenerReply(w, nil, err)
					return
				}
				out, err := m.apply(in.OperationID, secure.Hash(encoded), *in.Input, in.ConnectionID)
				listenerReply(w, out, err)
			} else {
				if in.Input != nil {
					listenerReply(w, nil, fault.Invalid("监听确认请求无效"))
					return
				}
				out, err := m.decide(in.OperationID, in.Action, in.ConnectionID)
				listenerReply(w, out, err)
			}
		})
	}
}
func (c *Client) ManagementListener(ctx context.Context) (remotelisten.View, error) {
	var out remotelisten.View
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/management-listener", nil, &out)
	return out, err
}
func (c *Client) ListenerOperation(ctx context.Context, id string) (remotelisten.Operation, error) {
	if !validID(id) {
		return remotelisten.Operation{}, fault.Invalid("监听操作 ID 无效")
	}
	var out remotelisten.Operation
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/management-listener/operations/"+id, nil, &out)
	return out, err
}
func (c *Client) ApplyListener(ctx context.Context, id string, in remotelisten.Input, connection string) (remotelisten.Operation, error) {
	var out remotelisten.Operation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/management-listener/apply", listenerRequest{Protocol: Protocol, OperationID: id, Input: &in, ConnectionID: connection}, &out)
	return out, err
}
func (c *Client) DecideListener(ctx context.Context, id, action, connection string) (remotelisten.Operation, error) {
	var out remotelisten.Operation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/management-listener/decide", listenerRequest{Protocol: Protocol, OperationID: id, Action: action, ConnectionID: connection}, &out)
	return out, err
}
