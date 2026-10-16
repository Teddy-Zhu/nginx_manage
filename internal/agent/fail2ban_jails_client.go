package agent

import (
	"context"
	"errors"
	"net/http"

	"nginxpanel/internal/fail2ban"
)

func (c *Client) ReadFail2banJailsRuntime(ctx context.Context) (fail2ban.JailsRuntime, error) {
	var out fail2ban.JailsRuntime
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/nginx/jails/status", nil, &out)
	if err == nil {
		_, policyErr := out.Policy.Normalize()
		if policyErr != nil || out.Pending == nil || out.Resources == nil || len(out.Pending) > 1 || len(out.Resources) > 32 || out.SelectedID != "" && !validID(out.SelectedID) || out.Available && !fail2banDigest.MatchString(out.Target) {
			err = errors.New("受管 jail 运行基准格式无效")
		}
		for _, id := range out.Resources {
			if !validID(id) {
				err = errors.New("受管 jail 资源格式无效")
			}
		}
	}
	return out, err
}

func (c *Client) ApplyFail2banJails(ctx context.Context, in fail2ban.JailsRequest) (fail2ban.JailsOperation, error) {
	var out fail2ban.JailsOperation
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/nginx/jails/apply", in, &out)
	if err == nil {
		err = validateFail2banJailsOperation(out, in.OperationID)
	}
	return out, err
}
func (c *Client) Fail2banJailsOperation(ctx context.Context, id string) (fail2ban.JailsOperation, error) {
	var out fail2ban.JailsOperation
	if !validID(id) {
		return out, errors.New("受管 jail 操作 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/nginx/jails/operations/"+id, nil, &out)
	if err == nil {
		err = validateFail2banJailsOperation(out, id)
	}
	return out, err
}
func validateFail2banJailsOperation(out fail2ban.JailsOperation, id string) error {
	if out.ID != id || out.AfterID != id || out.BeforeID != "" && !validID(out.BeforeID) || !fail2banDigest.MatchString(out.RequestHash) || !fail2banDigest.MatchString(out.Target) {
		return errors.New("受管 jail 操作合同无效")
	}
	switch out.State {
	case "running", "compensating", "recovery_required", "succeeded", "failed":
		return nil
	}
	return errors.New("受管 jail 操作状态未知")
}
