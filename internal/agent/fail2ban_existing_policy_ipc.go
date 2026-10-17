package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

var _ fail2ban.ExistingPolicyExecutor = (*Client)(nil)

func (f *fail2banJailsExecutor) existingPolicyHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/fail2ban/existing/resources", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.existingResources(r.Context())
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/existing/resources/{name}", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.existingResource(r.Context(), r.PathValue("name"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/existing/submit", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		var in fail2ban.ExistingPolicyRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			fail2banNginxReply(w, nil, fault.Invalid("已有 jail 参数请求格式无效"))
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.submitExistingPolicy(call, in)
		var known *fault.Error
		if err != nil && !errors.As(err, &known) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrRuntimeUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			err = fault.New(409, "FAIL2BAN_EXISTING_REJECTED", err.Error())
		}
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/existing/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := f.existingPolicyOperation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/existing/operations/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := f.cancelExistingPolicy(call, r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
}

func (c *Client) ReadFail2banExistingResources(ctx context.Context) ([]fail2ban.ExistingResource, error) {
	var out []fail2ban.ExistingResource
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/existing/resources", nil, &out)
	if err == nil {
		if out == nil || len(out) > 64 {
			return nil, errors.New("已有 jail 清单格式无效")
		}
		seen := map[string]bool{}
		for _, item := range out {
			if !fail2banJailName.MatchString(item.Name) || !validID(item.AdoptionID) || !validID(item.BindingID) || seen[item.Name] {
				return nil, errors.New("已有 jail 清单身份无效")
			}
			seen[item.Name] = true
		}
	}
	return out, err
}

func (c *Client) ReadFail2banExistingResource(ctx context.Context, name string) (fail2ban.ExistingResourcePolicy, error) {
	var out fail2ban.ExistingResourcePolicy
	if !fail2banJailName.MatchString(name) {
		return out, fault.Invalid("已有 jail 名称无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/existing/resources/"+name, nil, &out)
	if err == nil {
		p, policyErr := out.Policy.Normalize()
		if out.Name != name || out.Profile.Name != name || out.Profile.Validate() != nil || !validID(out.AdoptionID) || !validID(out.BindingID) || !validID(out.SelectedID) || policyErr != nil || !equalFail2banExistingPolicy(p, out.Policy) {
			err = errors.New("已有 jail 保存参数格式无效")
		}
	}
	return out, err
}

func (c *Client) SubmitFail2banExistingPolicy(ctx context.Context, input fail2ban.ExistingPolicyRequest) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	in, err := input.Normalize()
	if err != nil {
		return out, err
	}
	err = c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/existing/submit", in, &out)
	if err == nil && (!out.Valid() || out.ID != in.OperationID || out.RequestHash != in.Hash() || out.Action != in.Action || out.AdoptionID != in.AdoptionID || in.Target != "" && out.Target != in.Target || out.Plan != nil && !equalFail2banExistingPolicy(out.Plan.After, in.Policy)) {
		err = errors.New("已有 jail 排队结果与请求不一致")
	}
	return out, err
}

func (c *Client) Fail2banExistingPolicyOperation(ctx context.Context, id string) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	if !validID(id) {
		return out, fault.Invalid("已有 jail 操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/existing/operations/"+id, nil, &out)
	if err == nil && (!out.Valid() || out.ID != id) {
		err = errors.New("已有 jail 参数操作结果无效")
	}
	return out, err
}

func (c *Client) CancelFail2banExistingPolicy(ctx context.Context, id string) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	if !validID(id) {
		return out, fault.Invalid("已有 jail 操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/existing/operations/"+id+"/cancel", nil, &out)
	if err == nil && (!out.Valid() || out.ID != id) {
		err = errors.New("已有 jail 取消请求结果无效")
	}
	return out, err
}
