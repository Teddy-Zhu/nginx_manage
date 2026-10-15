package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"time"
)

type SessionStore struct{ DB *sql.DB }

// Long-lived responses must consult the store again; the request's loaded
// session alone cannot observe logout or renewal from another request.
func (s *Service) SessionAlive(ctx context.Context) (bool, error) {
	token := s.Sessions.Token(ctx)
	if token == "" {
		return false, nil
	}
	if s.Sessions.HashTokenInStore {
		sum := sha256.Sum256([]byte(token))
		token = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	_, found, err := s.Sessions.Store.Find(token)
	return found, err
}

func (s SessionStore) Delete(token string) error {
	_, err := s.DB.Exec("DELETE FROM sessions WHERE token=?", token)
	return err
}
func (s SessionStore) Find(token string) ([]byte, bool, error) {
	var data []byte
	err := s.DB.QueryRow("SELECT data FROM sessions WHERE token=? AND expiry>?", token, time.Now().Unix()).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return data, err == nil, err
}
func (s SessionStore) Commit(token string, data []byte, expiry time.Time) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM sessions WHERE expiry<=?", time.Now().Unix()); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM sessions WHERE token<>?", token).Scan(&count); err != nil {
		return err
	}
	if count >= 1024 {
		return ErrRateLimited
	}
	if _, err := tx.Exec("INSERT INTO sessions(token,data,expiry) VALUES(?,?,?) ON CONFLICT(token) DO UPDATE SET data=excluded.data,expiry=excluded.expiry", token, data, expiry.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
