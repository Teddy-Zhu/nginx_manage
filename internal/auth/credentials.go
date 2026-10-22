package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type CredentialView struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedSources []string `json:"allowed_sources"`
	ExpiresAt      int64    `json:"expires_at"`
	Revoked        bool     `json:"revoked"`
}

func (s *Service) ListCredentials(ctx context.Context, p Principal) ([]CredentialView, error) {
	if err := p.Require("auth.manage"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,scopes,allowed_sources,expires_at,revoked_at IS NOT NULL FROM api_credentials WHERE revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 100", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := []CredentialView{}
	for rows.Next() {
		var v CredentialView
		var scopes, sources string
		if err := rows.Scan(&v.ID, &v.Name, &scopes, &sources, &v.ExpiresAt, &v.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &v.Scopes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(sources), &v.AllowedSources); err != nil {
			return nil, err
		}
		data = append(data, v)
	}
	return data, rows.Err()
}

func (s *Service) RevokeCredential(ctx context.Context, p Principal, id string) error {
	if err := p.Require("auth.manage"); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", time.Now().Unix(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fault.NotFound("凭据不存在")
	}
	return nil
}

func (s *Service) CredentialExpiry(ctx context.Context, p Principal) (int64, error) {
	if !p.Machine {
		return 0, ErrForbidden
	}
	var expires int64
	err := s.DB.QueryRowContext(ctx, "SELECT expires_at FROM api_credentials WHERE id=? AND revoked_at IS NULL", p.ID).Scan(&expires)
	if err == sql.ErrNoRows {
		return 0, ErrUnauthorized
	}
	return expires, err
}

// Self-revocation is available to the presented machine credential without
// auth.manage. The revocation and its audit event must commit together.
func (s *Service) RevokeOwnCredential(ctx context.Context, p Principal, requestID string) error {
	if !p.Machine {
		return ErrForbidden
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(ctx, "UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", time.Now().Unix(), p.ID)
	if err != nil {
		return err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fault.NotFound("当前凭据不存在")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'revoked',?)", secure.ID(), requestID, p.ID, "auth.revoke_self", p.ID, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
