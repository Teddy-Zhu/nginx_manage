package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/fault"
)

const insertAdmin = "INSERT INTO users(id,username,password_hash,created_at) VALUES(1,?,?,?)"

// InitialAdmin carries the password hash used to resume an interrupted installation.
type InitialAdmin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

func validateUsername(username string) error {
	if len(username) < 1 || len(username) > 64 || !utf8.ValidString(username) || strings.TrimSpace(username) != username || strings.ContainsFunc(username, unicode.IsControl) {
		return fault.Invalid("请输入 1–64 字节的用户名，请去掉首尾空格及控制字符")
	}
	return nil
}

func PrepareInitialAdmin(username, password string) (InitialAdmin, error) {
	if err := validateUsername(username); err != nil {
		return InitialAdmin{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return InitialAdmin{}, err
	}
	return InitialAdmin{Username: username, PasswordHash: hash}, nil
}

func (a InitialAdmin) Install(ctx context.Context, db *sql.DB) error {
	if err := validateUsername(a.Username); err != nil {
		return err
	}
	if salt, _ := decodePasswordHash(a.PasswordHash); salt == nil {
		return errors.New("安装记录中的密码摘要无效")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing InitialAdmin
	err = tx.QueryRowContext(ctx, "SELECT username,password_hash FROM users WHERE id=1").Scan(&existing.Username, &existing.PasswordHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, insertAdmin, a.Username, a.PasswordHash, time.Now().Unix()); err != nil {
			return err
		}
	case err != nil:
		return err
	case existing != a:
		return errors.New("管理员已存在，无法使用安装向导更改")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM settings WHERE key='bootstrap_hash'"); err != nil {
		return err
	}
	return tx.Commit()
}
