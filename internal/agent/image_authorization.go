package agent

import (
	"errors"
	"nginxpanel/internal/imageupdates"
	"time"
)

type ImageAuthorization struct {
	Request    imageupdates.Request `json:"request"`
	AcceptedAt int64                `json:"accepted_at"`
	ClaimedAt  int64                `json:"claimed_at"`
}

func validateImageAuthorization(req imageupdates.Request, id string, in imageupdates.Input, epoch string, sequence int) error {
	if err := req.Validate(); err != nil {
		return err
	}
	now := time.Now().Unix()
	if req.OperationID != id || req.Input != in || req.Epoch != epoch || req.Sequence != sequence || req.AuthorizationUntil <= now || req.AuthorizationUntil > now+305 {
		return errors.New("镜像替换授权与原操作不一致或已过期")
	}
	return nil
}
func validImageAuthorizations(as []ImageAuthorization, id string, in imageupdates.Input, originalEpoch, currentEpoch string, terminal bool) error {
	if len(as) > 32 {
		return errors.New("镜像替换授权超过保留上限")
	}
	for n, a := range as {
		q := a.Request
		if q.ValidateStored() != nil || q.OperationID != id || q.Input != in || q.Sequence != n+1 || a.AcceptedAt <= 0 || a.AcceptedAt >= q.AuthorizationUntil || q.AuthorizationUntil > a.AcceptedAt+305 || a.ClaimedAt != 0 && (a.ClaimedAt < a.AcceptedAt || a.ClaimedAt >= q.AuthorizationUntil) || n == 0 && q.Epoch != originalEpoch || n > 0 && a.AcceptedAt < as[n-1].AcceptedAt {
			return errors.New("镜像替换持久授权与原事务不一致")
		}
	}
	if len(as) > 0 {
		last := as[len(as)-1]
		if last.Request.Epoch != currentEpoch || terminal && last.ClaimedAt == 0 {
			return errors.New("镜像替换终态或维护 epoch 缺少原授权")
		}
	}
	return nil
}
