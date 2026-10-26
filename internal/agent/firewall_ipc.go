package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/firewall"
)

type firewallRequest struct {
	Protocol     int                    `json:"protocol"`
	OperationID  string                 `json:"operation_id,omitempty"`
	PlanID       string                 `json:"plan_id,omitempty"`
	Version      int64                  `json:"version,omitempty"`
	PolicyHash   string                 `json:"policy_hash,omitempty"`
	Input        *firewall.RuntimeInput `json:"input,omitempty"`
	Action       string                 `json:"action,omitempty"`
	ConnectionID string                 `json:"connection_id,omitempty"`
}

func firewallReply(w http.ResponseWriter, data any, err error) {
	if os.IsNotExist(err) {
		err = fault.New(404, "FIREWALL_OPERATION_MISSING", "防火墙操作记录不存在")
	}
	if err != nil {
		if _, known := err.(*fault.Error); !known {
			err = fault.Unavailable("宿主机防火墙操作未完成，请查询原操作或由本机 root 检查")
		}
	}
	dnsReply(w, data, err)
}

func firewallControlHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(firewall.ControlRequestTimeout)
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
			firewallReply(w, nil, fault.Unavailable("防火墙连接无法设置响应时限"))
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline.Add(-5*time.Second))
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) firewallRuntimeHandlers(mux *http.ServeMux, f *hostFirewall) {
	mux.HandleFunc("GET /v1/firewall/runtime", firewallControlHandler(func(w http.ResponseWriter, r *http.Request) {
		out := f.View()
		out.Shortcuts = f.shortcutPorts(r.Context())
		firewallReply(w, out, nil)
	}))
	mux.HandleFunc("GET /v1/firewall/operations/{id}", firewallControlHandler(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			firewallReply(w, nil, fault.Invalid("防火墙操作 ID 无效"))
			return
		}
		out, err := f.Operation(id)
		firewallReply(w, out, err)
	}))
	for _, action := range []string{"plan", "apply", "decide"} {
		mux.HandleFunc("POST /v1/firewall/"+action, firewallControlHandler(func(w http.ResponseWriter, r *http.Request) {
			budget := int64(firewall.PolicyBytes + 4096)
			if action == "plan" {
				budget += firewall.DockerTargetBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, budget)
			defer r.Body.Close()
			var in firewallRequest
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Protocol != Protocol || in.ConnectionID != "" && !validID(in.ConnectionID) {
				firewallReply(w, nil, fault.Invalid("防火墙请求协议无效"))
				return
			}
			timeout := 10 * time.Second
			if validIPTablesBackend(f.owner) {
				timeout = firewall.ControlOperationTimeout
			}
			switch action {
			case "plan":
				if in.Input == nil || in.OperationID != "" || in.PlanID != "" || in.Action != "" || in.Version != 0 || in.PolicyHash != "" {
					firewallReply(w, nil, fault.Invalid("防火墙计划请求无效"))
					return
				}
				call, cancel := context.WithTimeout(r.Context(), timeout)
				defer cancel()
				out, err := f.Plan(call, *in.Input, in.ConnectionID)
				firewallReply(w, out, err)
			case "apply":
				if in.Input != nil || (in.Action != "apply" && in.Action != "remove") || in.Version < 1 || len(in.PolicyHash) != 64 {
					firewallReply(w, nil, fault.Invalid("防火墙应用请求无效"))
					return
				}
				call, cancel := context.WithTimeout(r.Context(), timeout)
				defer cancel()
				out, err := f.Apply(call, in.OperationID, in.PlanID, in.Version, in.PolicyHash, in.Action, in.ConnectionID)
				firewallReply(w, out, err)
			case "decide":
				if in.Input != nil || in.PlanID != "" || in.Version != 0 || in.PolicyHash != "" || !validID(in.OperationID) {
					firewallReply(w, nil, fault.Invalid("防火墙确认请求无效"))
					return
				}
				out, err := f.Decide(r.Context(), in.OperationID, in.Action, in.ConnectionID)
				firewallReply(w, out, err)
			}
		}))
	}
}

func (c *Client) firewallControlRequest(ctx context.Context, method, path string, input, output any) error {
	client, httpClient := *c, *c.http
	httpClient.Timeout = firewall.ControlRequestTimeout
	client.http = &httpClient
	return client.envelopeRequest(ctx, method, path, input, output)
}

func (c *Client) FirewallRuntime(ctx context.Context) (firewall.RuntimeView, error) {
	var out firewall.RuntimeView
	err := c.firewallControlRequest(ctx, http.MethodGet, "/v1/firewall/runtime", nil, &out)
	return out, err
}
func (c *Client) PlanFirewall(ctx context.Context, input firewall.RuntimeInput, connection string) (firewall.Plan, error) {
	var out firewall.Plan
	err := c.firewallControlRequest(ctx, http.MethodPost, "/v1/firewall/plan", firewallRequest{Protocol: Protocol, Input: &input, ConnectionID: connection}, &out)
	if err == nil && !validDockerPlan(out, input) {
		err = errors.New("invalid Docker firewall target plan")
	}
	return out, err
}
func (c *Client) ApplyFirewall(ctx context.Context, id string, in firewall.ApplyInput, hash, connection string) (firewall.Operation, error) {
	var out firewall.Operation
	err := c.firewallControlRequest(ctx, http.MethodPost, "/v1/firewall/apply", firewallRequest{Protocol: Protocol, OperationID: id, PlanID: in.PlanID, Version: in.Version, PolicyHash: hash, Action: in.Action, ConnectionID: connection}, &out)
	return out, err
}
func (c *Client) FirewallOperation(ctx context.Context, id string) (firewall.Operation, error) {
	if !validID(id) {
		return firewall.Operation{}, fault.Invalid("防火墙操作 ID 无效")
	}
	var out firewall.Operation
	err := c.firewallControlRequest(ctx, http.MethodGet, "/v1/firewall/operations/"+id, nil, &out)
	return out, err
}
func (c *Client) DecideFirewall(ctx context.Context, id, action, connection string) (firewall.Operation, error) {
	var out firewall.Operation
	err := c.firewallControlRequest(ctx, http.MethodPost, "/v1/firewall/decide", firewallRequest{Protocol: Protocol, OperationID: id, Action: action, ConnectionID: connection}, &out)
	return out, err
}
