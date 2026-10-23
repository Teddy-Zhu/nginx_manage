package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
)

var ErrUnauthorized = errors.New("身份认证失败")
var ErrForbidden = errors.New("权限不足")
var ErrRateLimited = errors.New("登录尝试过多，请稍后重试")
var AllScopes = []string{"read", "config.write", "config.secrets", "security.write", "system.write", "host.dns.write", "monitoring.write", "components.manage", "auth.manage", "backup.export", "backup.secrets", "backup.restore", "update.execute", "nodes.manage", "notifications.write"}

type Principal struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Scopes       []string `json:"scopes"`
	Machine      bool     `json:"machine"`
	Delegated    bool     `json:"-"`
	GrantScopes  []string `json:"-"`
	SessionEpoch int64    `json:"-"`
}

func (p Principal) Has(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
func (p Principal) Require(scopes ...string) error {
	for _, s := range scopes {
		if !p.Has(s) {
			return ErrForbidden
		}
	}
	return nil
}

type bucket struct {
	Count int
	Until time.Time
}
type Service struct {
	DB            *sql.DB
	Sessions      *scs.SessionManager
	mu            sync.Mutex
	attempts      map[string]bucket
	passwordSlots chan struct{}
}

func New(db *sql.DB, dev bool) *Service {
	sessions := scs.New()
	sessions.Store = SessionStore{db}
	sessions.Lifetime = 12 * time.Hour
	sessions.IdleTimeout = 30 * time.Minute
	sessions.Cookie.Name = "nginxpanel_session"
	sessions.Cookie.HttpOnly = true
	sessions.Cookie.Secure = !dev
	sessions.Cookie.SameSite = http.SameSiteStrictMode
	sessions.Cookie.Persist = true
	sessions.HashTokenInStore = true
	return &Service{DB: db, Sessions: sessions, attempts: map[string]bucket{}, passwordSlots: make(chan struct{}, 2)}
}

func (s *Service) CSRF(ctx context.Context) string {
	token := s.Sessions.GetString(ctx, "csrf")
	if token == "" {
		token = secure.Token()
		s.Sessions.Put(ctx, "csrf", token)
	}
	return token
}
func (s *Service) CheckCSRF(r *http.Request) bool {
	want := s.Sessions.GetString(r.Context(), "csrf")
	got := r.Header.Get("X-CSRF-Token")
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
func (s *Service) rate(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.attempts {
		if now.After(v.Until) {
			delete(s.attempts, k)
		}
	}
	b, ok := s.attempts[ip]
	if !ok {
		if len(s.attempts) >= 1024 {
			return ErrRateLimited
		}
		b.Until = now.Add(time.Minute)
	}
	if b.Count >= 5 {
		return ErrRateLimited
	}
	b.Count++
	s.attempts[ip] = b
	return nil
}

func (s *Service) check(ctx context.Context, ip, username, password string) (dbgen.User, error) {
	if err := s.rate(ip); err != nil {
		return dbgen.User{}, err
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	default:
		return dbgen.User{}, ErrRateLimited
	}
	u, err := dbgen.New(s.DB).GetUser(ctx)
	if err != nil && err != sql.ErrNoRows {
		return u, err
	}
	if err == sql.ErrNoRows {
		return u, ErrUnauthorized
	}
	valid := CheckPassword(u.PasswordHash, password)
	if !valid || subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) != 1 {
		return u, ErrUnauthorized
	}
	return u, nil
}

func (s *Service) Login(ctx context.Context, ip, username, password string) error {
	u, err := s.check(ctx, ip, username, password)
	if err != nil {
		return err
	}
	if err := s.Sessions.RenewToken(ctx); err != nil {
		return err
	}
	s.Sessions.Put(ctx, "user", u.Username)
	s.Sessions.Put(ctx, "epoch", u.SessionEpoch)
	s.Sessions.Put(ctx, "csrf", secure.Token())
	return nil
}
func (s *Service) Authenticate(r *http.Request) (Principal, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(header, "Bearer ") || len(header) > 200 {
			return Principal{}, ErrUnauthorized
		}
		hash := secure.Hash([]byte(strings.TrimPrefix(header, "Bearer ")))
		var id, name, scopes, sources string
		err := s.DB.QueryRowContext(r.Context(), "SELECT id,name,scopes,allowed_sources FROM api_credentials WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?", hash, time.Now().Unix()).Scan(&id, &name, &scopes, &sources)
		if err == sql.ErrNoRows {
			return Principal{}, ErrUnauthorized
		}
		if err != nil {
			return Principal{}, err
		}
		var allowed []string
		if err := json.Unmarshal([]byte(sources), &allowed); err != nil {
			return Principal{}, err
		}
		if len(allowed) > 0 {
			ip := net.ParseIP(ClientIP(r))
			matched := false
			for _, cidr := range allowed {
				_, network, err := net.ParseCIDR(cidr)
				if err == nil && network.Contains(ip) {
					matched = true
				}
			}
			if !matched {
				return Principal{}, ErrUnauthorized
			}
		}
		p := Principal{ID: id, Username: name, Machine: true}
		if err := json.Unmarshal([]byte(scopes), &p.Scopes); err != nil {
			return p, err
		}
		p.GrantScopes = append([]string(nil), p.Scopes...)
		if r.Header.Get(remoteapi.HopHeader) != "" {
			var allowed []string
			if r.Header.Get(remoteapi.HopHeader) != "1" || len(r.Header.Get(remoteapi.ScopesHeader)) > 4096 || json.Unmarshal([]byte(r.Header.Get(remoteapi.ScopesHeader)), &allowed) != nil || len(allowed) > len(AllScopes) {
				return Principal{}, ErrForbidden
			}
			grant := p.Scopes
			p.Scopes = []string{}
			seen := map[string]bool{}
			for _, scope := range allowed {
				if seen[scope] {
					return Principal{}, ErrForbidden
				}
				seen[scope] = true
				known := false
				for _, candidate := range AllScopes {
					if candidate == scope {
						known = true
						break
					}
				}
				if !known {
					return Principal{}, ErrForbidden
				}
				for _, candidate := range grant {
					if candidate == scope {
						p.Scopes = append(p.Scopes, scope)
						break
					}
				}
			}
			p.Delegated = true
		}
		if _, err := s.DB.ExecContext(r.Context(), "UPDATE api_credentials SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at<?)", time.Now().Unix(), id, time.Now().Add(-time.Minute).Unix()); err != nil {
			return Principal{}, err
		}
		return p, nil
	}
	username := s.Sessions.GetString(r.Context(), "user")
	if username == "" {
		return Principal{}, ErrUnauthorized
	}
	u, err := dbgen.New(s.DB).GetUser(r.Context())
	if err != nil {
		return Principal{}, err
	}
	if u.Username != username || u.SessionEpoch != s.Sessions.GetInt64(r.Context(), "epoch") {
		return Principal{}, ErrUnauthorized
	}
	return Principal{ID: "administrator", Username: username, Scopes: AllScopes, SessionEpoch: u.SessionEpoch}, nil
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Service) BootstrapRequired(ctx context.Context) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count == 0, err
}

func (s *Service) Bootstrap(ctx context.Context, token, username, password string) error {
	if len(username) < 1 || len(username) > 64 || strings.TrimSpace(username) != username || strings.ContainsAny(username, "\r\n\t\x00") {
		return fault.Invalid("用户名须为 1–64 个字符且不含控制字符")
	}
	var want string
	err := s.DB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='bootstrap_hash'").Scan(&want)
	if err == sql.ErrNoRows {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	got := secure.Hash([]byte(token))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return ErrUnauthorized
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM settings WHERE key='bootstrap_hash' AND value=?", want)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUnauthorized
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,created_at) VALUES(1,?,?,?)", username, hash, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

type CredentialInput struct {
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedSources []string `json:"allowed_sources"`
	ExpiresAt      int64    `json:"expires_at"`
}

func (s *Service) CreateCredential(ctx context.Context, p Principal, in CredentialInput) (string, string, error) {
	if err := ValidateCredential(p, in); err != nil {
		return "", "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	id, token, err := CreateCredentialTx(ctx, tx, p, in)
	if err == nil {
		err = tx.Commit()
	}
	return id, token, err
}

func ValidateCredential(p Principal, in CredentialInput) error {
	if err := p.Require("auth.manage"); err != nil {
		return err
	}
	if in.Name == "" || len(in.Name) > 100 || len(in.Scopes) == 0 || len(in.Scopes) > len(AllScopes) || len(in.AllowedSources) > 32 || in.ExpiresAt <= time.Now().Unix() || in.ExpiresAt > time.Now().Add(366*24*time.Hour).Unix() {
		return fault.Invalid("无效凭据名称、权限、来源或到期时间")
	}
	seen := map[string]bool{}
	for _, scope := range in.Scopes {
		if !p.Has(scope) {
			return ErrForbidden
		}
		known := false
		for _, candidate := range AllScopes {
			if candidate == scope {
				known = true
				break
			}
		}
		if !known || seen[scope] {
			return fault.Invalid("凭据权限无效或重复")
		}
		seen[scope] = true
	}
	for _, source := range in.AllowedSources {
		if _, _, err := net.ParseCIDR(source); err != nil {
			return fault.Invalid("允许来源须为 CIDR")
		}
	}
	return nil
}

// Pairing publishes the credential and its consumed offer in one transaction.
func CreateCredentialTx(ctx context.Context, tx *sql.Tx, p Principal, in CredentialInput) (string, string, error) {
	if err := ValidateCredential(p, in); err != nil {
		return "", "", err
	}
	id, token := secure.ID(), secure.Token()
	scopes, err := json.Marshal(in.Scopes)
	if err != nil {
		return "", "", err
	}
	if in.AllowedSources == nil {
		in.AllowedSources = []string{}
	}
	sources, err := json.Marshal(in.AllowedSources)
	if err != nil {
		return "", "", err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_credentials WHERE revoked_at IS NULL AND expires_at>?", time.Now().Unix()).Scan(&count); err != nil {
		return "", "", err
	}
	if count >= 100 {
		return "", "", fault.Conflict("有效机器凭据已达上限，请先撤销旧凭据")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO api_credentials(id,name,token_hash,scopes,allowed_sources,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", id, in.Name, secure.Hash([]byte(token)), string(scopes), string(sources), time.Now().Unix(), in.ExpiresAt)
	return id, token, err
}

func (s *Service) ChangePassword(ctx context.Context, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE users SET password_hash=?,session_epoch=session_epoch+1 WHERE id=1", hash)
	if err != nil {
		return err
	}
	return s.Sessions.Destroy(ctx)
}

func (s *Service) RevokeSessions(ctx context.Context, p Principal) error {
	if err := p.Require("auth.manage"); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE users SET session_epoch=session_epoch+1 WHERE id=1"); err != nil {
		return err
	}
	if !p.Machine {
		return s.Sessions.Destroy(ctx)
	}
	return nil
}
