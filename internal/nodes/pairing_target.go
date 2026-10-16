package nodes

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

var pairingSecret = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type pairBucket struct {
	count int
	until time.Time
}

const pairingColumns = "p.id,p.principal,p.issuer_machine,p.issuer_epoch,p.name,p.controller_node_id,p.scopes,p.allowed_sources,p.credential_expires_at,p.secret_hash,COALESCE(p.claim_hash,''),COALESCE(p.credential_id,''),p.token,p.state,p.created_at,p.expires_at,COALESCE(p.claimed_at,0),COALESCE(p.confirmed_at,0),COALESCE(p.revoked_at,c.revoked_at,0)"
const pairingFrom = " FROM node_pairings p LEFT JOIN api_credentials c ON c.id=p.credential_id"

func (s *Service) readPairing(row scanner) (Pairing, error) {
	var p Pairing
	var scopes, sources string
	err := row.Scan(&p.ID, &p.principal, &p.machine, &p.epoch, &p.Name, &p.ControllerNodeID, &scopes, &sources, &p.CredentialExpiresAt, &p.secretHash, &p.claimHash, &p.CredentialID, &p.token, &p.State, &p.CreatedAt, &p.ExpiresAt, &p.ClaimedAt, &p.ConfirmedAt, &p.RevokedAt)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal([]byte(scopes), &p.Scopes); err != nil {
		return p, err
	}
	if err = json.Unmarshal([]byte(sources), &p.AllowedSources); err != nil {
		return p, err
	}
	p.NodeID = s.NodeID
	if p.RevokedAt != 0 {
		p.State = "revoked"
	} else if p.State != "confirmed" && p.ExpiresAt <= time.Now().Unix() || p.CredentialExpiresAt <= time.Now().Unix() {
		p.State = "expired"
	}
	return p, nil
}

func (s *Service) ListPairings(ctx context.Context, principal auth.Principal) ([]Pairing, error) {
	if err := principal.Require("nodes.manage", "read", "auth.manage"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+pairingColumns+pairingFrom+" ORDER BY p.created_at DESC,p.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Pairing{}
	for rows.Next() {
		p, err := s.readPairing(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// The code is displayed once. Replaying creation returns only the saved offer.
func (s *Service) CreatePairing(ctx context.Context, p auth.Principal, trace, key string, in PairingInput) (PairingOffer, error) {
	var out PairingOffer
	if err := p.Require("nodes.manage", "read", "auth.manage"); err != nil {
		return out, err
	}
	if err := validKey(key); err != nil {
		return out, err
	}
	if !uuid.MatchString(in.ControllerNodeID) || in.ControllerNodeID == s.NodeID || !p.Has("read") || len(in.AllowedSources) == 0 || strings.TrimSpace(in.Name) != in.Name || strings.ContainsAny(in.Name, "\x00\r\n") {
		return out, fault.Invalid("须指定其他控制节点永久编号、名称及允许来源")
	}
	if err := auth.ValidateCredential(p, in.credential()); err != nil {
		return out, err
	}
	hasRead := false
	for _, scope := range in.Scopes {
		if scope == "read" {
			hasRead = true
		}
	}
	if !hasRead {
		return out, fault.Invalid("配对授权须包含 read")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	hash := requestHash("pairing.offer", in)
	var previous, oldHash string
	err = tx.QueryRowContext(ctx, "SELECT id,request_hash FROM node_pairings WHERE principal=? AND create_key=?", p.ID, key).Scan(&previous, &oldHash)
	if err == nil {
		if oldHash != hash {
			return out, fault.Conflict("同一幂等键不能用于不同配对授权")
		}
		out.Pairing, err = s.readPairing(tx.QueryRowContext(ctx, "SELECT "+pairingColumns+pairingFrom+" WHERE p.id=?", previous))
		return out, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM node_pairings").Scan(&count); err != nil {
		return out, err
	}
	if count >= 128 {
		return out, fault.Conflict("配对记录已达上限，须本机归档后继续")
	}
	var epoch int64
	if !p.Machine {
		if err = tx.QueryRowContext(ctx, "SELECT session_epoch FROM users WHERE id=1").Scan(&epoch); err != nil {
			return out, err
		}
		if epoch != p.SessionEpoch {
			return out, auth.ErrUnauthorized
		}
	} else {
		var expiry int64
		if err = tx.QueryRowContext(ctx, "SELECT expires_at FROM api_credentials WHERE id=? AND revoked_at IS NULL AND expires_at>?", p.ID, time.Now().Unix()).Scan(&expiry); err != nil {
			return out, err
		}
		if in.CredentialExpiresAt > expiry {
			return out, fault.Invalid("配对授权不能晚于签发凭据的有效期")
		}
	}
	now := time.Now().Unix()
	id, secret := secure.ID(), secure.Token()
	scopes, _ := json.Marshal(in.Scopes)
	sources, _ := json.Marshal(in.AllowedSources)
	out.Pairing = Pairing{ID: id, NodeID: s.NodeID, Name: in.Name, ControllerNodeID: in.ControllerNodeID, Scopes: in.Scopes, AllowedSources: in.AllowedSources, CredentialExpiresAt: in.CredentialExpiresAt, State: "offered", CreatedAt: now, ExpiresAt: now + 300}
	if _, err = tx.ExecContext(ctx, "INSERT INTO node_pairings(id,principal,issuer_machine,issuer_epoch,create_key,request_hash,name,controller_node_id,scopes,allowed_sources,credential_expires_at,secret_hash,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'offered',?,?)", id, p.ID, p.Machine, epoch, key, hash, in.Name, in.ControllerNodeID, string(scopes), string(sources), in.CredentialExpiresAt, secure.Hash([]byte(secret)), now, now+300); err != nil {
		return out, err
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.pairing.offer", id, "succeeded"); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out.Secret = secret
	return out, nil
}

func (s *Service) pairingRate(peer string) error {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	now := time.Now()
	if s.pairAttempts == nil {
		s.pairAttempts = map[string]pairBucket{}
	}
	for key, value := range s.pairAttempts {
		if !now.Before(value.until) {
			delete(s.pairAttempts, key)
		}
	}
	value, exists := s.pairAttempts[peer]
	if !exists && len(s.pairAttempts) >= 1024 {
		return fault.New(http.StatusTooManyRequests, "PAIRING_BUSY", "配对请求繁忙，请稍后重试")
	}
	if !exists {
		value.until = now.Add(time.Minute)
	}
	value.count++
	s.pairAttempts[peer] = value
	if value.count > 30 {
		return fault.New(http.StatusTooManyRequests, "PAIRING_RATE_LIMIT", "配对请求过于频繁，请稍后重试")
	}
	return nil
}

func pairingUnavailable() error {
	return fault.New(http.StatusUnauthorized, "PAIRING_UNAVAILABLE", "配对信息无效、已过期或已撤销")
}

func pairingPeer(p Pairing, peer string) bool {
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, source := range p.AllowedSources {
		_, network, err := net.ParseCIDR(source)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) pairingIssuer(ctx context.Context, tx *sql.Tx, p Pairing) (auth.Principal, error) {
	issuer := auth.Principal{ID: p.principal, Machine: p.machine, Scopes: auth.AllScopes}
	if p.machine {
		var scopes string
		var expiry int64
		if err := tx.QueryRowContext(ctx, "SELECT scopes,expires_at FROM api_credentials WHERE id=? AND revoked_at IS NULL AND expires_at>?", p.principal, time.Now().Unix()).Scan(&scopes, &expiry); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return issuer, pairingUnavailable()
			}
			return issuer, err
		}
		if err := json.Unmarshal([]byte(scopes), &issuer.Scopes); err != nil {
			return issuer, err
		}
		if expiry < p.CredentialExpiresAt {
			return issuer, pairingUnavailable()
		}
	} else {
		var epoch int64
		if err := tx.QueryRowContext(ctx, "SELECT session_epoch FROM users WHERE id=1").Scan(&epoch); err != nil {
			return issuer, err
		}
		if epoch != p.epoch {
			return issuer, pairingUnavailable()
		}
	}
	if err := issuer.Require("auth.manage", "nodes.manage", "read"); err != nil {
		return issuer, pairingUnavailable()
	}
	for _, scope := range p.Scopes {
		if !issuer.Has(scope) {
			return issuer, pairingUnavailable()
		}
	}
	return issuer, nil
}

func (s *Service) ExchangePairing(ctx context.Context, trace, id, peer string, in PairingClaim) (PairingExchange, error) {
	var out PairingExchange
	if err := s.pairingRate(peer); err != nil {
		return out, err
	}
	if !uuid.MatchString(id) || !uuid.MatchString(in.ControllerNodeID) || !pairingSecret.MatchString(in.Secret) || !pairingSecret.MatchString(in.Claim) {
		return out, pairingUnavailable()
	}
	release, err := s.slot()
	if err != nil {
		return out, err
	}
	defer release()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	p, err := s.readPairing(tx.QueryRowContext(ctx, "SELECT "+pairingColumns+pairingFrom+" WHERE p.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return out, pairingUnavailable()
	}
	if err != nil {
		return out, err
	}
	hash := secure.Hash([]byte(in.Secret))
	claim := secure.Hash([]byte(in.Claim))
	if subtle.ConstantTimeCompare([]byte(hash), []byte(p.secretHash)) != 1 || p.ControllerNodeID != in.ControllerNodeID || !pairingPeer(p, peer) || (p.State != "offered" && p.State != "claimed") {
		return out, pairingUnavailable()
	}
	issuer, err := s.pairingIssuer(ctx, tx, p)
	if err != nil {
		return out, err
	}
	if p.State == "claimed" {
		if subtle.ConstantTimeCompare([]byte(claim), []byte(p.claimHash)) != 1 {
			return out, pairingUnavailable()
		}
		token, err := s.Vault.Open(p.token, "pairing-token:"+id)
		if err != nil {
			return out, err
		}
		out = PairingExchange{Pairing: p, Token: string(token)}
		if err = audit(ctx, tx, trace, "pairing:"+p.ControllerNodeID, "nodes.pairing.exchange", id, "replayed"); err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
	// Until confirmation the credential expires with the offer, bounding an
	// orphaned exchange whose response never reached the controller.
	expiry := min(p.ExpiresAt, p.CredentialExpiresAt)
	credential, token, err := auth.CreateCredentialTx(ctx, tx, issuer, auth.CredentialInput{Name: p.Name, Scopes: p.Scopes, AllowedSources: p.AllowedSources, ExpiresAt: expiry})
	if err != nil {
		return out, err
	}
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "UPDATE node_pairings SET state='claimed',claim_hash=?,credential_id=?,token=?,claimed_at=? WHERE id=? AND state='offered'", claim, credential, s.Vault.Seal([]byte(token), "pairing-token:"+id), now, id); err != nil {
		return out, err
	}
	if err = audit(ctx, tx, trace, "pairing:"+p.ControllerNodeID, "nodes.pairing.exchange", id, "succeeded"); err != nil {
		return out, err
	}
	p.State, p.CredentialID, p.ClaimedAt = "claimed", credential, now
	out = PairingExchange{Pairing: p, Token: token}
	return out, tx.Commit()
}

func (s *Service) ConfirmPairing(ctx context.Context, p auth.Principal, trace, id string, in PairingConfirmation) (Pairing, error) {
	if err := p.Require("read"); err != nil {
		return Pairing{}, err
	}
	if !p.Machine || p.Delegated || !uuid.MatchString(id) || !pairingSecret.MatchString(in.Claim) {
		return Pairing{}, auth.ErrForbidden
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Pairing{}, err
	}
	defer tx.Rollback()
	pair, err := s.readPairing(tx.QueryRowContext(ctx, "SELECT "+pairingColumns+pairingFrom+" WHERE p.id=?", id))
	if err != nil {
		return pair, err
	}
	claim := secure.Hash([]byte(in.Claim))
	if pair.CredentialID != p.ID || pair.ControllerNodeID != in.ControllerNodeID || subtle.ConstantTimeCompare([]byte(claim), []byte(pair.claimHash)) != 1 || (pair.State != "claimed" && pair.State != "confirmed") {
		return pair, pairingUnavailable()
	}
	if pair.State == "confirmed" {
		return pair, nil
	}
	if _, err = s.pairingIssuer(ctx, tx, pair); err != nil {
		return pair, err
	}
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, "UPDATE api_credentials SET expires_at=? WHERE id=? AND revoked_at IS NULL AND expires_at>?", pair.CredentialExpiresAt, p.ID, now)
	if err != nil {
		return pair, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return pair, err
	}
	if n != 1 {
		return pair, pairingUnavailable()
	}
	if _, err = tx.ExecContext(ctx, "UPDATE node_pairings SET state='confirmed',token=NULL,confirmed_at=? WHERE id=?", now, id); err != nil {
		return pair, err
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.pairing.confirm", id, "succeeded"); err != nil {
		return pair, err
	}
	pair.State, pair.ConfirmedAt = "confirmed", now
	return pair, tx.Commit()
}

func (s *Service) RevokePairing(ctx context.Context, p auth.Principal, trace, id string) (Pairing, error) {
	if err := p.Require("nodes.manage", "read", "auth.manage"); err != nil {
		return Pairing{}, err
	}
	if !uuid.MatchString(id) {
		return Pairing{}, fault.Invalid("配对标识无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Pairing{}, err
	}
	defer tx.Rollback()
	pair, err := s.readPairing(tx.QueryRowContext(ctx, "SELECT "+pairingColumns+pairingFrom+" WHERE p.id=?", id))
	if err != nil {
		return pair, err
	}
	now := time.Now().Unix()
	if pair.RevokedAt != 0 {
		now = pair.RevokedAt
	}
	if pair.CredentialID != "" {
		if _, err = tx.ExecContext(ctx, "UPDATE api_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", now, pair.CredentialID); err != nil {
			return pair, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE node_pairings SET state='revoked',token=NULL,revoked_at=COALESCE(revoked_at,?) WHERE id=?", now, id); err != nil {
		return pair, err
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.pairing.revoke", id, "succeeded"); err != nil {
		return pair, err
	}
	pair.State, pair.RevokedAt = "revoked", now
	return pair, tx.Commit()
}
