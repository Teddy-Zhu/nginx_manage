package fail2ban

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type PolicyService struct {
	DB         *sql.DB
	Vault      *secure.Vault
	Agent      PolicyObserver
	previewing atomic.Bool
	runtimeMu  sync.Mutex
}

func policyAAD(version int64) string { return fmt.Sprintf("fail2ban:policy:%d", version) }

type PolicyReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *PolicyService) Policy(ctx context.Context) (PolicyView, error) {
	return s.ReadPolicy(ctx, s.DB)
}
func (s *PolicyService) ReadPolicy(ctx context.Context, q PolicyReader) (PolicyView, error) {
	out := PolicyView{Policy: DefaultPolicy()}
	var sealed []byte
	e := q.QueryRowContext(ctx, "SELECT version,payload,updated_at FROM fail2ban_policy WHERE id=1").Scan(&out.Version, &sealed, &out.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	raw, e := s.Vault.Open(sealed, policyAAD(out.Version))
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(raw, &out.Policy); e != nil {
		return out, e
	}
	normalized, e := out.Policy.Normalize()
	if e != nil || normalized.Hash() != out.Policy.Hash() || out.Version < 1 {
		return PolicyView{}, fault.Unavailable("已保存的 Fail2ban jail 配置无效，须检查存储")
	}
	return out, nil
}
func (s *PolicyService) Save(ctx context.Context, p auth.Principal, requestID, key string, in PolicyInput) (PolicyView, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var out PolicyView
	if e := p.Require("security.write"); e != nil {
		return out, e
	}
	if in.BaseVersion < 0 || in.BaseVersion == math.MaxInt64 || key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("策略版本或幂等键无效")
	}
	normalized, e := in.Policy.Normalize()
	if e != nil {
		return out, e
	}
	in.Policy = normalized
	raw, e := json.Marshal(struct {
		Action string
		Input  PolicyInput
	}{"fail2ban.policy.save", in})
	if e != nil {
		return out, e
	}
	digest := secure.Hash(raw)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	e = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if e == nil {
		if prior != digest {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, e := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		e = json.Unmarshal(plain, &out)
		return out, e
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e = s.migrationIdle(ctx, tx); e != nil {
		return out, e
	}
	out, e = s.StorePolicy(ctx, tx, in.BaseVersion, in.Policy)
	if e != nil {
		return out, e
	}
	now := time.Now().Unix()
	response, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, digest, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,'fail2ban.policy.save','host','saved',?)", secure.ID(), requestID, p.ID, now); e != nil {
		return out, e
	}
	return out, tx.Commit()
}
