package auth

import (
	"database/sql"
	"time"
)

type SessionStore struct{ DB *sql.DB }

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
