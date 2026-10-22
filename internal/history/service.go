package history

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type Service struct {
	DB     *sql.DB
	Vault  *secure.Vault
	NodeID string
	key    [32]byte
	slots  chan struct{}
}

func New(db *sql.DB, vault *secure.Vault, node string) (*Service, error) {
	s := &Service{DB: db, Vault: vault, NodeID: node, slots: make(chan struct{}, 2)}
	_, err := rand.Read(s.key[:])
	return s, err
}

type grant struct {
	Owner     string `json:"owner"`
	NodeID    string `json:"node_id"`
	Filter    Filter `json:"filter"`
	SHA256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Service) enter() (func(), error) {
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, nil
	default:
		return nil, fault.New(429, "HISTORY_BUSY", "历史维护读取已达并发上限")
	}
}

func (s *Service) Preview(ctx context.Context, p auth.Principal, f Filter) (Preview, error) {
	if err := p.Require("system.write", "config.write", "config.secrets"); err != nil {
		return Preview{}, err
	}
	if err := f.Validate(); err != nil {
		return Preview{}, err
	}
	if f.MigrationKeep != 0 {
		if err := p.Require("backup.restore", "backup.secrets"); err != nil {
			return Preview{}, err
		}
	}
	done, err := s.enter()
	if err != nil {
		return Preview{}, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Preview{}, err
	}
	defer tx.Rollback()
	out, err := collect(ctx, tx, s.NodeID, f, p)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out.ExpiresAt = time.Now().Unix() + 600
	raw, err := json.Marshal(grant{Owner: p.ID, NodeID: s.NodeID, Filter: f, SHA256: out.SHA256, ExpiresAt: out.ExpiresAt})
	if err != nil {
		return out, err
	}
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write(raw)
	out.Token = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return out, nil
}

func (s *Service) decode(token string, p auth.Principal) (grant, error) {
	var g grant
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return g, fault.Invalid("历史维护预览凭据无效")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return g, fault.Invalid("历史维护预览凭据无效")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return g, fault.Invalid("历史维护预览凭据无效")
	}
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write(raw)
	if !hmac.Equal(signature, mac.Sum(nil)) || json.Unmarshal(raw, &g) != nil || g.Owner != p.ID || g.NodeID != s.NodeID || g.Filter.Validate() != nil {
		return g, fault.Conflict("历史维护预览已失效，请重新预览")
	}
	return g, nil
}

func (s *Service) Execute(ctx context.Context, p auth.Principal, requestID, key string, in ExecuteInput) (Result, error) {
	if err := p.Require("system.write", "config.write", "config.secrets"); err != nil {
		return Result{}, err
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") || len(in.Token) < 1 || len(in.Token) > 4096 {
		return Result{}, fault.Invalid("历史维护幂等键或预览凭据无效")
	}
	done, err := s.enter()
	if err != nil {
		return Result{}, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, _ := json.Marshal(in)
	digest := secure.Hash(append([]byte("history.cleanup\x00"), raw...))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	var prior string
	var response []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &response)
	if err == nil {
		if prior != digest {
			return Result{}, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, e := s.Vault.Open(response, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return Result{}, e
		}
		var out Result
		e = json.Unmarshal(plain, &out)
		if e == nil {
			for _, scope := range out.Scopes {
				if scope.Kind == "migration" {
					e = p.Require("backup.restore", "backup.secrets")
					break
				}
			}
		}
		return out, e
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	g, err := s.decode(in.Token, p)
	if err != nil {
		return Result{}, err
	}
	if g.ExpiresAt <= time.Now().Unix() {
		return Result{}, fault.Conflict("历史维护预览已过期，请重新预览")
	}
	if g.Filter.MigrationKeep != 0 {
		if err := p.Require("backup.restore", "backup.secrets"); err != nil {
			return Result{}, err
		}
	}
	current, err := collect(ctx, tx, s.NodeID, g.Filter, p)
	if err != nil {
		return Result{}, err
	}
	if current.SHA256 != g.SHA256 {
		return Result{}, fault.Conflict("候选材料或配置引用已变化，请重新预览")
	}
	if len(current.Items) == 0 {
		return Result{}, fault.Conflict("没有可清理的历史材料")
	}
	now := time.Now().Unix()
	for _, item := range current.Items {
		if err = prune(ctx, tx, item, now); err != nil {
			return Result{}, err
		}
	}
	out := Result{ID: secure.ID(), NodeID: s.NodeID, SHA256: current.SHA256, CompletedAt: now, Scopes: current.Scopes}
	response, err = json.Marshal(out)
	if err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,'succeeded',?)", secure.ID(), requestID, p.ID, "history.cleanup", out.ID, now); err != nil {
		return Result{}, err
	}
	return out, tx.Commit()
}

func prune(ctx context.Context, tx *sql.Tx, item Item, now int64) error {
	var query string
	switch item.Kind {
	case "revision":
		for _, table := range []string{"nginx_certificate_references", "nginx_resource_bindings", "nginx_config_files"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE revision_id=?", item.ID); err != nil {
				return err
			}
		}
		query = "UPDATE config_revisions SET pruned_at=? WHERE id=? AND pruned_at=0"
	case "certificate":
		query = "UPDATE certificate_versions SET pruned_at=?,fullchain=zeroblob(0),private_key=zeroblob(0) WHERE id=? AND pruned_at=0"
	case "order":
		if _, err := tx.ExecContext(ctx, "UPDATE acme_dns_records SET payload=zeroblob(0) WHERE order_id=? AND state='cleaned'", item.ID); err != nil {
			return err
		}
		query = "UPDATE acme_orders SET pruned_at=?,credentials=zeroblob(0),private_key=zeroblob(0),csr=zeroblob(0) WHERE id=? AND pruned_at=0"
	case "migration":
		if _, err := tx.ExecContext(ctx, "UPDATE migration_dependencies SET payload=zeroblob(0) WHERE plan_id=?", item.ID); err != nil {
			return err
		}
		query = "UPDATE migration_plans SET pruned_at=?,payload=zeroblob(0),state=CASE WHEN state='planned' THEN 'failed' ELSE state END,last_error=CASE WHEN state='planned' THEN '计划已过期，历史材料已清理' ELSE last_error END WHERE id=? AND pruned_at=0"
	case "maintenance":
		query = "UPDATE maintenance_sessions SET archived_at=? WHERE task_id=? AND archived_at=0 AND phase IN('released','failed')"
	default:
		return errors.New("invalid history material kind")
	}
	result, err := tx.ExecContext(ctx, query, now, item.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fault.Conflict("历史材料已变化，请重新预览")
	}
	return nil
}
