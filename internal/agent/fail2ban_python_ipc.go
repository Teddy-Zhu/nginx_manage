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

func (p *fail2banPythonTasks) handlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/fail2ban/python", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		defer r.Body.Close()
		var in fail2ban.PythonTaskRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			fail2banNginxReply(w, nil, fault.Invalid("Python 依赖请求格式无效"))
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := p.submit(call, in)
		var known *fault.Error
		if err != nil && !errors.As(err, &known) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrRuntimeUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			err = fault.New(409, "FAIL2BAN_PYTHON_REJECTED", err.Error())
		}
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/python/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := p.operation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
}
func (c *Client) ChangeFail2banPython(ctx context.Context, in fail2ban.PythonTaskRequest) (fail2ban.PythonTaskOperation, error) {
	var out fail2ban.PythonTaskOperation
	if !in.Valid() {
		return out, fault.Invalid("Python 依赖请求合同无效")
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/python", in, &out)
	if err == nil && (!fail2ban.ValidPythonTaskOperation(out) || out.ID != in.OperationID || out.RequestHash != in.Hash() || out.Input != in.Input) {
		err = errors.New("Python 依赖操作结果合同无效")
	}
	return out, err
}
func (c *Client) Fail2banPythonOperation(ctx context.Context, id string) (fail2ban.PythonTaskOperation, error) {
	var out fail2ban.PythonTaskOperation
	if !validID(id) {
		return out, fault.Invalid("操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/python/operations/"+id, nil, &out)
	if err == nil && (!fail2ban.ValidPythonTaskOperation(out) || out.ID != id) {
		err = errors.New("Python 依赖操作结果合同无效")
	}
	return out, err
}
