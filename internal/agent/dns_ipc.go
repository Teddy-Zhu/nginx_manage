package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/hostdns"
)

type dnsRequest struct {
	Protocol    int                `json:"protocol"`
	OperationID string             `json:"operation_id"`
	Input       *hostdns.PlanInput `json:"input,omitempty"`
	Plan        *hostdns.Plan      `json:"plan,omitempty"`
	Action      string             `json:"action,omitempty"`
}

func dnsReply(w http.ResponseWriter, data any, err error) {
	status, code, message := 200, "OK", "成功"
	if err != nil {
		status, code, message = 503, "DNS_UNAVAILABLE", "宿主机 DNS 操作不可用"
		var known *fault.Error
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		}
		if os.IsNotExist(err) {
			status, code, message = 404, "DNS_OPERATION_MISSING", "DNS 操作记录不存在"
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
func (s *Server) dnsHandlers(mux *http.ServeMux, d *HostDNS, ctx context.Context) {
	mux.HandleFunc("GET /v1/host-dns", func(w http.ResponseWriter, r *http.Request) { dnsReply(w, d.Read(), nil) })
	mux.HandleFunc("GET /v1/host-dns/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !validID(r.PathValue("id")) {
			dnsReply(w, nil, fault.Invalid("DNS 操作 ID 无效"))
			return
		}
		out, err := d.Status(r.PathValue("id"))
		dnsReply(w, out, err)
	})
	for _, action := range []string{"plan", "apply", "decide"} {
		mux.HandleFunc("POST /v1/host-dns/"+action, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
			defer r.Body.Close()
			var in dnsRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Protocol != Protocol {
				dnsReply(w, nil, fault.Invalid("DNS 请求协议无效"))
				return
			}
			switch action {
			case "plan":
				if in.Input == nil || in.Plan != nil || in.OperationID != "" || in.Action != "" {
					dnsReply(w, nil, fault.Invalid("DNS 计划请求无效"))
					return
				}
				out, err := d.Plan(*in.Input)
				dnsReply(w, out, err)
			case "apply":
				if in.Plan == nil || in.Input != nil || in.Action != "" {
					dnsReply(w, nil, fault.Invalid("DNS 应用请求无效"))
					return
				}
				out, err := d.Apply(in.OperationID, *in.Plan)
				dnsReply(w, out, err)
			case "decide":
				if in.Plan != nil || in.Input != nil || !validID(in.OperationID) {
					dnsReply(w, nil, fault.Invalid("DNS 确认请求无效"))
					return
				}
				out, err := d.Decide(ctx, in.OperationID, in.Action)
				dnsReply(w, out, err)
			}
		})
	}
}
func (c *Client) envelopeRequest(ctx context.Context, method, path string, in, out any) error {
	var reply struct {
		Protocol int             `json:"protocol"`
		Code     string          `json:"code"`
		Data     json.RawMessage `json:"data"`
	}
	if err := c.request(ctx, method, path, in, &reply); err != nil {
		return err
	}
	if reply.Protocol != Protocol || reply.Code != "OK" {
		return fault.Unavailable("Agent 响应协议不匹配")
	}
	return json.Unmarshal(reply.Data, out)
}
func (c *Client) ReadHostDNS(ctx context.Context) (hostdns.Observation, error) {
	var out hostdns.Observation
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/host-dns", nil, &out)
	return out, err
}
func (c *Client) PlanHostDNS(ctx context.Context, input hostdns.PlanInput) (hostdns.Plan, error) {
	var out hostdns.Plan
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/host-dns/plan", dnsRequest{Protocol: Protocol, Input: &input}, &out)
	return out, err
}
func (c *Client) ApplyHostDNS(ctx context.Context, id string, plan hostdns.Plan) (hostdns.Status, error) {
	var out hostdns.Status
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/host-dns/apply", dnsRequest{Protocol: Protocol, OperationID: id, Plan: &plan}, &out)
	return out, err
}
func (c *Client) HostDNSOperation(ctx context.Context, id string) (hostdns.Status, error) {
	if !validID(id) {
		return hostdns.Status{}, fault.Invalid("DNS 操作 ID 无效")
	}
	var out hostdns.Status
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/host-dns/operations/"+id, nil, &out)
	return out, err
}
func (c *Client) DecideHostDNS(ctx context.Context, id, action string) (hostdns.Status, error) {
	var out hostdns.Status
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/host-dns/decide", dnsRequest{Protocol: Protocol, OperationID: id, Action: action}, &out)
	return out, err
}
