package nodes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const columns = "id,node_id,name,endpoint,fingerprint,credential_id,token,scopes,expires_at,api_version,capabilities,state,last_error,checked_at,created_at,updated_at,COALESCE(removed_at,0),revocation,version"

type scanner interface{ Scan(...any) error }

func read(row scanner) (Connection, error) {
	var c Connection
	var scopes string
	var capabilities []byte
	err := row.Scan(&c.ID, &c.NodeID, &c.Name, &c.URL, &c.Fingerprint, &c.CredentialID, &c.token, &scopes, &c.ExpiresAt, &c.APIVersion, &capabilities, &c.State, &c.Error, &c.CheckedAt, &c.CreatedAt, &c.UpdatedAt, &c.RemovedAt, &c.Revocation, &c.Version)
	if err == nil {
		err = json.Unmarshal([]byte(scopes), &c.Scopes)
	}
	c.Capabilities = capabilities
	if err == nil && c.State == "connected" {
		if c.ExpiresAt <= time.Now().Unix() {
			c.State, c.Error = "authorization_failed", "目标授权已到期"
			c.Capabilities = nil
		} else if c.CheckedAt < time.Now().Add(-5*time.Minute).Unix() {
			c.State, c.Error = "stale", "状态已过期，请重新检查连接"
			c.Capabilities = nil
		}
	}
	return c, err
}

func (s *Service) get(ctx context.Context, id string) (Connection, error) {
	if !uuid.MatchString(id) {
		return Connection{}, fault.Invalid("节点连接标识无效")
	}
	c, err := read(s.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM nodes WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, fault.NotFound("节点连接不存在")
	}
	return c, err
}

func (s *Service) Get(ctx context.Context, p auth.Principal, id string) (Connection, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return Connection{}, err
	}
	return s.get(ctx, id)
}

func (s *Service) List(ctx context.Context, p auth.Principal) ([]Connection, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+columns+" FROM nodes ORDER BY COALESCE(removed_at,0),created_at DESC,id LIMIT 128")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Connection{}
	for rows.Next() {
		c, err := read(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func requestHash(action string, in any) string {
	raw, _ := json.Marshal(struct {
		Action string
		Input  any
	}{action, in})
	return secure.Hash(raw)
}

func validKey(key string) error {
	if len(key) == 0 || len(key) > 128 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00\r\n") {
		return fault.Invalid("幂等键无效")
	}
	return nil
}

func (s *Service) replay(ctx context.Context, p auth.Principal, key, action, hash string) (Connection, bool, error) {
	var original, id, kind string
	err := s.DB.QueryRowContext(ctx, "SELECT request_hash,connection_id,action FROM node_requests WHERE principal=? AND key=?", p.ID, key).Scan(&original, &id, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, false, nil
	}
	if err != nil {
		return Connection{}, false, err
	}
	if original != hash || kind != action {
		return Connection{}, false, fault.Conflict("同一幂等键不能用于不同节点操作")
	}
	c, err := s.get(ctx, id)
	return c, true, err
}

func audit(ctx context.Context, tx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, trace, actor, action, id, outcome string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), trace, actor, action, id, outcome, time.Now().Unix())
	return err
}

func reserve(ctx context.Context, tx *sql.Tx, p auth.Principal, key, action, hash, id string) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM node_requests").Scan(&count); err != nil {
		return err
	}
	if count >= 1024 {
		return fault.Conflict("节点操作记录已达上限，须本机归档后继续")
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO node_requests(principal,key,action,request_hash,connection_id,created_at) VALUES(?,?,?,?,?,?)", p.ID, key, action, hash, id, time.Now().Unix())
	return err
}
