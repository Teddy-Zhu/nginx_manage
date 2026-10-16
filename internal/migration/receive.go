package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

func (s *Service) Receiver(ctx context.Context, p auth.Principal) (Receiver, error) {
	out := Receiver{Schema: Schema, NodeID: s.NodeID, Scopes: append([]string{}, p.Scopes...)}
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"); err != nil {
		return out, err
	}
	err := s.DB.QueryRowContext(ctx, "SELECT version FROM config_head WHERE id=1").Scan(&out.Version)
	return out, err
}

// Receive uses the sender's immutable transfer ID for both creation and recovery.
// The receipt and plan are committed together before any execution can begin.
func (s *Service) Receive(ctx context.Context, p auth.Principal, requestID, id string, in ImportInput) (Plan, error) {
	if err := p.Require("backup.restore", "backup.secrets", "config.write", "config.secrets", "security.write"); err != nil {
		return Plan{}, err
	}
	if !validTransferID(id) {
		return Plan{}, fault.Invalid("迁移标识无效")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return Plan{}, err
	}
	hash := secure.Hash(raw)
	if !s.mu.TryLock() {
		return Plan{}, fault.Conflict("已有迁移包正在处理")
	}
	defer s.mu.Unlock()
	var owner, prior string
	err = s.DB.QueryRowContext(ctx, "SELECT p.principal,r.request_hash FROM migration_receives r JOIN migration_plans p ON p.id=r.plan_id WHERE r.plan_id=?", id).Scan(&owner, &prior)
	if err == nil {
		if owner != p.ID && !p.Has("auth.manage") {
			return Plan{}, auth.ErrForbidden
		}
		if prior != hash {
			return Plan{}, fault.Conflict("同一迁移标识不能用于不同配置包或目标参数")
		}
		return s.Get(ctx, p, id)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Plan{}, err
	}
	var exists bool
	if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM migration_plans WHERE id=?)", id).Scan(&exists); err != nil {
		return Plan{}, err
	}
	if exists {
		return Plan{}, fault.Conflict("迁移标识已被其他计划占用")
	}
	manifest, payload, err := decodeArchive(in.Content, in.Passphrase)
	if err != nil {
		return Plan{}, err
	}
	return s.prepare(ctx, p, requestID, manifest, payload, in.BaseVersion, in.Mappings, in.Firewall, in.Fail2ban, in.Monitoring, in.HostDNS, nil, &receiveReservation{ID: id, Digest: hash, PackageSHA256: secure.Hash(in.Content)})
}
