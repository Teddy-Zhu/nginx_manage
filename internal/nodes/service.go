package nodes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
)

func (s *Service) slot() (func(), error) {
	if s.active.Add(1) > 4 {
		s.active.Add(-1)
		return nil, fault.New(http.StatusTooManyRequests, "NODE_CHECK_BUSY", "节点连接检查繁忙，请稍后重试")
	}
	return func() { s.active.Add(-1) }, nil
}

func (s *Service) lock(id string) (func(), error) {
	value, _ := s.locks.LoadOrStore(id, &sync.RWMutex{})
	mu := value.(*sync.RWMutex)
	if !mu.TryLock() {
		return nil, fault.Conflict("此节点正在检查或删除，请稍后重试")
	}
	return mu.Unlock, nil
}

func (s *Service) Create(ctx context.Context, p auth.Principal, trace, key string, in CreateInput) (Connection, error) {
	return s.create(ctx, p, trace, key, in, "", "")
}

func (s *Service) create(ctx context.Context, p auth.Principal, trace, key string, in CreateInput, expected, credential string) (Connection, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return Connection{}, err
	}
	if err := validKey(key); err != nil {
		return Connection{}, err
	}
	if in.Name == "" || len(in.Name) > 100 || strings.TrimSpace(in.Name) != in.Name || strings.ContainsAny(in.Name, "\x00\r\n") || in.Fingerprint != "" && !pin.MatchString(strings.ToLower(in.Fingerprint)) || len(in.APIKey) < 20 || len(in.APIKey) > 193 || strings.TrimSpace(in.APIKey) != in.APIKey {
		return Connection{}, fault.Invalid("连接名称或 API 密钥无效")
	}
	hash := requestHash("create", in)
	if c, found, err := s.replay(ctx, p, key, "create", hash); found || err != nil {
		return c, err
	}
	done, err := s.slot()
	if err != nil {
		return Connection{}, err
	}
	defer done()
	endpoint := remoteapi.Endpoint{URL: in.URL, APIKey: in.APIKey, Fingerprint: in.Fingerprint}
	client, base, err := remoteapi.Client(endpoint)
	if err != nil {
		return Connection{}, err
	}
	client.CloseIdleConnections()
	id := secure.ID()
	if err = audit(ctx, s.DB, trace, p.ID, "nodes.connect", id, "started"); err != nil {
		return Connection{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	var identity Identity
	var caps json.RawMessage
	if expected == "" {
		endpoint, err = remoteapi.Resolve(callCtx, endpoint)
	}
	if err == nil {
		identity, caps, err = probe(callCtx, endpoint, expected, credential)
	}
	cancel()
	if err != nil {
		state, message := probeFailure(err)
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if auditErr := audit(finish, s.DB, trace, p.ID, "nodes.connect", id, state); auditErr != nil {
			return Connection{}, auditErr
		}
		return Connection{}, fault.New(http.StatusBadGateway, "NODE_CONNECTION_FAILED", message)
	}
	if identity.NodeID == s.NodeID {
		return Connection{}, fault.Invalid("不能将当前节点登记为远程节点")
	}
	now := time.Now().Unix()
	c := Connection{ID: id, NodeID: identity.NodeID, Name: in.Name, URL: base, Fingerprint: endpoint.Fingerprint, CredentialID: identity.CredentialID, Scopes: identity.Scopes, ExpiresAt: identity.ExpiresAt, APIVersion: identity.APIVersion, Capabilities: caps, State: "connected", CheckedAt: now, CreatedAt: now, UpdatedAt: now, Version: 1}
	scopes, _ := json.Marshal(c.Scopes)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	// A concurrent retry may have registered the same key during the probe.
	var prior string
	err = tx.QueryRowContext(ctx, "SELECT connection_id FROM node_requests WHERE principal=? AND key=?", p.ID, key).Scan(&prior)
	if err == nil {
		tx.Rollback()
		old, _, err := s.replay(ctx, p, key, "create", hash)
		return old, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Connection{}, err
	}
	var active, total, duplicate int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(removed_at IS NULL),0),COALESCE(SUM(node_id=? AND removed_at IS NULL),0) FROM nodes", c.NodeID).Scan(&total, &active, &duplicate); err != nil {
		return Connection{}, err
	}
	if active >= 32 || total >= 128 {
		return Connection{}, fault.Conflict("节点连接已达上限（活动 32、含撤销记录共 128）")
	}
	if duplicate != 0 {
		return Connection{}, fault.Conflict("此永久节点身份已登记，请使用已有连接")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO nodes(id,node_id,name,endpoint,fingerprint,credential_id,token,scopes,expires_at,api_version,capabilities,state,checked_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'connected',?,?,?)", c.ID, c.NodeID, c.Name, c.URL, c.Fingerprint, c.CredentialID, s.Vault.Seal([]byte(in.APIKey), "node-token:"+c.ID), string(scopes), c.ExpiresAt, c.APIVersion, []byte(caps), now, now, now)
	if err != nil {
		return Connection{}, err
	}
	if err = reserve(ctx, tx, p, key, "create", hash, c.ID); err != nil {
		return Connection{}, err
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.create", c.ID, "succeeded"); err != nil {
		return Connection{}, err
	}
	return c, tx.Commit()
}

func (s *Service) Refresh(ctx context.Context, p auth.Principal, trace, id string) (Connection, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return Connection{}, err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return c, err
	}
	unlock, err := s.lock(id)
	if err != nil {
		return c, err
	}
	defer unlock()
	c, err = s.get(ctx, id)
	if err != nil {
		return c, err
	}
	if c.RemovedAt != 0 || c.State == "removing" {
		return c, fault.Conflict("连接正在删除或已删除")
	}
	done, err := s.slot()
	if err != nil {
		return c, err
	}
	defer done()
	token, err := s.Vault.Open(c.token, "node-token:"+id)
	if err != nil {
		return c, err
	}
	if err = audit(ctx, s.DB, trace, p.ID, "nodes.check", id, "started"); err != nil {
		return c, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	identity, caps, probeErr := probe(callCtx, endpoint(c, token), c.NodeID, c.CredentialID)
	cancel()
	state, message := "connected", ""
	if probeErr != nil {
		state, message = probeFailure(probeErr)
		caps = nil
	} else {
		c.Scopes, c.ExpiresAt, c.APIVersion = identity.Scopes, identity.ExpiresAt, identity.APIVersion
	}
	scopes, _ := json.Marshal(c.Scopes)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	changed, err := tx.ExecContext(ctx, "UPDATE nodes SET scopes=?,expires_at=?,api_version=?,capabilities=?,state=?,last_error=?,checked_at=?,updated_at=?,version=version+1 WHERE id=? AND version=? AND removed_at IS NULL AND state<>'removing'", string(scopes), c.ExpiresAt, c.APIVersion, []byte(caps), state, message, now, now, id, c.Version)
	if err != nil {
		return c, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return c, err
	}
	if n != 1 {
		return c, fault.Conflict("连接已发生变化，请重新读取")
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.check", id, state); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	return s.get(ctx, id)
}

func (s *Service) Delete(ctx context.Context, p auth.Principal, trace, key, id string) (Connection, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return Connection{}, err
	}
	if err := validKey(key); err != nil {
		return Connection{}, err
	}
	c, err := s.get(ctx, id)
	if err != nil {
		return c, err
	}
	unlock, err := s.lock(id)
	if err != nil {
		return c, err
	}
	defer unlock()
	hash := requestHash("delete", id)
	prior, found, err := s.replay(ctx, p, key, "delete", hash)
	if err != nil {
		return c, err
	}
	if found && prior.State == "removed" {
		return prior, nil
	}
	c, err = s.get(ctx, id)
	if err != nil {
		return c, err
	}
	var token []byte
	if c.State != "removed" {
		done, err := s.slot()
		if err != nil {
			return c, err
		}
		defer done()
		token, err = s.Vault.Open(c.token, "node-token:"+id)
		if err != nil {
			return c, err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	if !found {
		var priorHash, priorID, priorAction string
		err = tx.QueryRowContext(ctx, "SELECT request_hash,connection_id,action FROM node_requests WHERE principal=? AND key=?", p.ID, key).Scan(&priorHash, &priorID, &priorAction)
		if err == nil {
			if priorHash != hash || priorID != id || priorAction != "delete" {
				return c, fault.Conflict("同一幂等键不能用于不同节点操作")
			}
			found = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return c, err
		}
	}
	if !found {
		if err = reserve(ctx, tx, p, key, "delete", hash, id); err != nil {
			return c, err
		}
	}
	if c.State == "removed" {
		if err = audit(ctx, tx, trace, p.ID, "nodes.delete", id, "already_removed"); err != nil {
			return c, err
		}
		return c, tx.Commit()
	}
	changed, err := tx.ExecContext(ctx, "UPDATE nodes SET state='removing',last_error='',version=version+1,updated_at=? WHERE id=? AND version=? AND removed_at IS NULL", time.Now().Unix(), id, c.Version)
	if err != nil {
		return c, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return c, err
	}
	if n != 1 {
		return c, fault.Conflict("连接已发生变化，请重新读取")
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.delete", id, "started"); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	// The local intent is durable before the only remote mutation. An unknown
	// result is kept as pending revocation, never silently reported as revoked.
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	body, remoteErr := call(callCtx, endpoint(c, token), c.NodeID, http.MethodDelete, "/remote/authorization")
	cancel()
	revocation, message := "pending", "未确认目标授权撤销，请在目标节点撤销所列凭据编号"
	var receipt struct {
		CredentialID string `json:"credential_id"`
		Revoked      bool   `json:"revoked"`
	}
	if remoteErr == nil && json.Unmarshal(body.Data, &receipt) == nil && receipt.CredentialID == c.CredentialID && receipt.Revoked {
		revocation, message = "revoked", ""
	}
	// Persist the outcome even when the browser disconnected after dispatch.
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	tx, err = s.DB.BeginTx(finish, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	changed, err = tx.ExecContext(finish, "UPDATE nodes SET state='removed',token=NULL,capabilities=NULL,revocation=?,last_error=?,removed_at=?,updated_at=?,version=version+1 WHERE id=? AND state='removing' AND version=? AND removed_at IS NULL", revocation, message, now, now, id, c.Version+1)
	if err != nil {
		return c, err
	}
	n, err = changed.RowsAffected()
	if err != nil {
		return c, err
	}
	if n != 1 {
		return c, fault.Conflict("删除结果尚未持久确认，请重新读取原连接")
	}
	if err = audit(finish, tx, trace, p.ID, "nodes.delete", id, revocation); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	return s.get(finish, id)
}
