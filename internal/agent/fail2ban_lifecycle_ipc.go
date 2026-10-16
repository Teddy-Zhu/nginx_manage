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

func (l *fail2banLifecycle) handlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/fail2ban/lifecycle/preview", func(w http.ResponseWriter, r *http.Request) {
		var in fail2ban.LifecyclePreviewInput
		if err := decodeLifecycle(w, r, &in); err != nil {
			fail2banNginxReply(w, nil, err)
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := l.preview(call, in)
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("POST /v1/fail2ban/lifecycle", func(w http.ResponseWriter, r *http.Request) {
		var in fail2ban.LifecycleRequest
		if err := decodeLifecycle(w, r, &in); err != nil {
			fail2banNginxReply(w, nil, err)
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := l.submit(call, in)
		var known *fault.Error
		if err != nil && !errors.As(err, &known) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrRuntimeUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			err = fault.New(409, "FAIL2BAN_LIFECYCLE_REJECTED", err.Error())
		}
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/lifecycle/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := l.operation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
}
func decodeLifecycle(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return fault.Invalid("Fail2ban 实例操作请求格式无效")
	}
	return nil
}
func (c *Client) PreviewFail2banLifecycle(ctx context.Context, in fail2ban.LifecyclePreviewInput) (fail2ban.LifecyclePlan, error) {
	var out fail2ban.LifecyclePlan
	if err := in.Validate(); err != nil {
		return out, err
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/lifecycle/preview", in, &out)
	if err == nil && (out.At <= 0 || out.Input.Validate() != nil || out.Input.LifecyclePreviewInput != in || !fail2ban.ValidManaged(out.Managed) || !validLifecycleServiceID(out.Input, out.Service.ID) || !out.Service.Available || out.Service.MainPID == nil || out.Jails == nil || len(out.Jails) > 64 || len(out.Impacts) == 0 || len(out.Impacts) > 8) {
		err = errors.New("Fail2ban 实例预览合同无效")
	}
	if err == nil {
		for _, name := range out.Jails {
			if !fail2banJailName.MatchString(name) {
				err = errors.New("受管 jail 影响范围无效")
				break
			}
		}
	}
	return out, err
}
func (c *Client) ChangeFail2banLifecycle(ctx context.Context, in fail2ban.LifecycleRequest) (fail2ban.LifecycleOperation, error) {
	var out fail2ban.LifecycleOperation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/lifecycle", in, &out)
	if err == nil {
		err = validateLifecycleOperation(out, in.OperationID)
	}
	return out, err
}
func (c *Client) Fail2banLifecycleOperation(ctx context.Context, id string) (fail2ban.LifecycleOperation, error) {
	var out fail2ban.LifecycleOperation
	if !validID(id) {
		return out, fault.Invalid("操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/lifecycle/operations/"+id, nil, &out)
	if err == nil {
		err = validateLifecycleOperation(out, id)
	}
	return out, err
}
func validateLifecycleOperation(out fail2ban.LifecycleOperation, id string) error {
	if out.ID != id || !fail2banDigest.MatchString(out.RequestHash) || out.Input.Validate() != nil || out.At <= 0 || !fail2ban.ValidManaged(out.Managed) || !validLifecycleServiceID(out.Input, out.Service.ID) || out.Service.Available && out.Service.MainPID == nil {
		return errors.New("Fail2ban 实例操作合同无效")
	}
	if out.State != "running" && out.State != "recovery_required" && out.State != "succeeded" && out.State != "failed" {
		return errors.New("Fail2ban 实例操作状态未知")
	}
	if out.Submission != "not_sent" && out.Submission != "unknown" && out.Submission != "acknowledged" {
		return errors.New("受管引擎派发状态未知")
	}
	return nil
}
func validLifecycleServiceID(input fail2ban.LifecycleInput, id string) bool {
	if input.EngineOwner == "managed" {
		return id == fail2banManagedService
	}
	return input.EngineOwner == "existing" && fail2banUnit.MatchString(id) && id != fail2banManagedService
}
