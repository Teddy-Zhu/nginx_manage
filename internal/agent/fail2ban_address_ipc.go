package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

func (s *Server) fail2banAddressHandlers(mux *http.ServeMux) {
	if s.fail2banNginx != nil {
		s.fail2banNginx.addressHandlers(mux)
		return
	}
	for _, route := range []string{"GET /v1/fail2ban/addresses/status", "POST /v1/fail2ban/addresses", "GET /v1/fail2ban/addresses/operations/{id}"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			fail2banNginxReply(w, nil, fault.Unavailable("本机手动封禁执行器不可用"))
		})
	}
}
func (f *fail2banNginxExecutor) addressHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/fail2ban/addresses/status", func(w http.ResponseWriter, r *http.Request) {
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.addressStatus(call, r.URL.Query().Get("jail"), r.URL.Query().Get("ip"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/addresses/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.addressOperation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/addresses", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		defer r.Body.Close()
		var in fail2ban.AddressRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			fail2banNginxReply(w, nil, fault.Invalid("手动封禁请求格式无效"))
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.submitAddress(call, in)
		var known *fault.Error
		if err != nil && !errors.As(err, &known) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrRuntimeUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			err = fault.New(409, "FAIL2BAN_ADDRESS_REJECTED", err.Error())
		}
		fail2banNginxReply(w, out, err)
	})
}
func (c *Client) ReadFail2banAddress(ctx context.Context, jail, ip string) (fail2ban.AddressStatus, error) {
	var out fail2ban.AddressStatus
	address, err := fail2ban.Address(ip)
	if err != nil || !fail2ban.ManagedJailName(jail) {
		return out, fault.Invalid("jail 或地址格式无效")
	}
	err = c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/addresses/status?"+url.Values{"jail": {jail}, "ip": {address}}.Encode(), nil, &out)
	if err == nil && (out.At <= 0 || out.Jail != jail || out.IP != address || !validFail2banAddressState(out.EngineState) || out.ExpiresAt < 0 || out.Available && (!fail2banDigest.MatchString(out.Target) || !fail2banDigest.MatchString(out.Generation) || out.EngineState == "unknown" || out.ActionState != "clear" && out.ActionState != "denied" || out.BanTime != -1 && out.BanTime <= 0) || !out.Available && (out.EngineState != "unknown" || out.ActionState != "unknown" || out.CanBan)) {
		err = errors.New("手动地址状态合同无效")
	}
	return out, err
}
func validFail2banAddressState(state string) bool {
	return state == "unknown" || state == "banned" || state == "clear"
}
func (c *Client) ChangeFail2banAddress(ctx context.Context, in fail2ban.AddressRequest) (fail2ban.AddressOperation, error) {
	var out fail2ban.AddressOperation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/addresses", in, &out)
	if err == nil {
		err = validateFail2banAddressOperation(out, in.OperationID)
	}
	return out, err
}
func (c *Client) Fail2banAddressOperation(ctx context.Context, id string) (fail2ban.AddressOperation, error) {
	var out fail2ban.AddressOperation
	if !validID(id) {
		return out, fault.Invalid("操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/addresses/operations/"+id, nil, &out)
	if err == nil {
		err = validateFail2banAddressOperation(out, id)
	}
	return out, err
}
func validateFail2banAddressOperation(out fail2ban.AddressOperation, id string) error {
	if out.ID != id || !fail2banDigest.MatchString(out.RequestHash) || out.Input.Validate() != nil || !validFail2banAddressState(out.EngineState) || out.ObservedAt < 0 || out.ExpiresAt < 0 {
		return errors.New("手动封禁操作合同无效")
	}
	if out.State != "running" && out.State != "succeeded" && out.State != "failed" {
		return errors.New("手动封禁操作状态未知")
	}
	switch out.Submission {
	case "not_sent", "not_needed", "unknown", "acknowledged":
	default:
		return errors.New("手动封禁派发状态未知")
	}
	return nil
}
