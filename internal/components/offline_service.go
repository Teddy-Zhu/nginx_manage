package components

import (
	"context"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

func (s *Service) offlineHost(p auth.Principal, read bool) (OfflineHost, error) {
	scopes := []string{"components.manage"}
	if read {
		scopes = append(scopes, "read")
	}
	if err := p.Require(scopes...); err != nil {
		return nil, err
	}
	h, ok := s.Agent.(OfflineHost)
	if !ok {
		return nil, fault.Unavailable("未连接离线组件接收器")
	}
	return h, nil
}
func (s *Service) OfflineUploads(ctx context.Context, p auth.Principal) ([]OfflineUpload, error) {
	h, err := s.offlineHost(p, true)
	if err != nil {
		return nil, err
	}
	return h.ListOfflineUploads(ctx)
}
func (s *Service) StartOffline(ctx context.Context, p auth.Principal, requestID, key string, in OfflineInput) (OfflineUpload, error) {
	h, err := s.offlineHost(p, false)
	if err != nil {
		return OfflineUpload{}, err
	}
	if !ValidID(key) {
		return OfflineUpload{}, fault.Invalid("离线上传的幂等键须为 UUID")
	}
	if err = in.Validate(); err != nil {
		return OfflineUpload{}, err
	}
	out, err := h.CreateOfflineUpload(ctx, OfflineRequest{Protocol: protocol.Agent, ID: key, Input: in})
	if err != nil {
		return out, err
	}
	err = s.offlineAudit(ctx, p, requestID, "component.offline.upload", out.ID, "authenticated")
	return out, err
}
func (s *Service) UploadOfflineChunk(ctx context.Context, p auth.Principal, id, asset string, in OfflineChunk) (OfflineUpload, error) {
	h, err := s.offlineHost(p, false)
	if err != nil {
		return OfflineUpload{}, err
	}
	if !ValidID(id) || asset == "" || len(asset) > 128 {
		return OfflineUpload{}, fault.Invalid("离线上传或资产标识无效")
	}
	if err = (Input{Action: "check", Assets: []string{asset}}).Validate(); err != nil {
		return OfflineUpload{}, err
	}
	if err = in.Validate(); err != nil {
		return OfflineUpload{}, err
	}
	return h.WriteOfflineChunk(ctx, id, asset, in)
}
func (s *Service) ClearOffline(ctx context.Context, p auth.Principal, requestID, id string) (OfflineUpload, error) {
	h, err := s.offlineHost(p, false)
	if err != nil {
		return OfflineUpload{}, err
	}
	if !ValidID(id) {
		return OfflineUpload{}, fault.Invalid("离线上传 UUID 无效")
	}
	var pending int
	if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE kind IN ('component.check','component.prepare','component.activate') AND state IN ('queued','running','recovery_required')").Scan(&pending); err != nil {
		return OfflineUpload{}, err
	}
	if pending != 0 {
		return OfflineUpload{}, fault.Conflict("组件任务尚未结束，不能清除上传")
	}
	out, err := h.DiscardOfflineUpload(ctx, id)
	if err != nil {
		return out, err
	}
	err = s.offlineAudit(ctx, p, requestID, "component.offline.discard", id, "discarded")
	return out, err
}
func (s *Service) offlineAudit(ctx context.Context, p auth.Principal, requestID, action, id, outcome string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), requestID, p.ID, action, id, outcome, time.Now().Unix())
	return err
}
