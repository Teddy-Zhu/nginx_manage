package agent

import (
	"context"
	"errors"
	"net/http"

	"nginxpanel/internal/fail2ban"
)

func (u *fail2banUpgradeTasks) handlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/fail2ban/upgrade", func(w http.ResponseWriter, r *http.Request) {
		var in fail2ban.UpgradeRequest
		if err := decodeLifecycle(w, r, &in); err != nil {
			fail2banNginxReply(w, nil, err)
			return
		}
		out, err := u.submit(r.Context(), in)
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/upgrade/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := u.operation(r.PathValue("id"))
		fail2banNginxReply(w, out, err)
	})
}
func (c *Client) ChangeFail2banUpgrade(ctx context.Context, in fail2ban.UpgradeRequest) (fail2ban.UpgradeOperation, error) {
	var out fail2ban.UpgradeOperation
	if !in.Valid() {
		return out, errors.New("升级请求合同无效")
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/upgrade", in, &out)
	if err == nil && (!out.Valid() || out.ID != in.OperationID || out.RequestHash != in.Hash() || out.Input != in.Input) {
		err = errors.New("升级受理合同与原请求不匹配")
	}
	return out, err
}
func (c *Client) Fail2banUpgradeOperation(ctx context.Context, id string) (fail2ban.UpgradeOperation, error) {
	var out fail2ban.UpgradeOperation
	if !validID(id) {
		return out, errors.New("升级操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/upgrade/operations/"+id, nil, &out)
	if err == nil && (!out.Valid() || out.ID != id) {
		err = errors.New("升级操作合同无法核对")
	}
	return out, err
}
