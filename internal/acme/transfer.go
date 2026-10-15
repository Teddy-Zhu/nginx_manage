package acme

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
)

var transferUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

type TransferCredential struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Secrets  map[string]string `json:"secrets"`
}

func (s *Service) ExportCredentials(ctx context.Context, tx *sql.Tx) ([]TransferCredential, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id,name,provider,secrets FROM dns_credentials ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TransferCredential{}
	for rows.Next() {
		var c TransferCredential
		var sealed []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.Provider, &sealed); err != nil {
			return nil, err
		}
		plain, err := s.Vault.Open(sealed, "acme:dns:"+c.ID)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(plain, &c.Secrets); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func ValidateTransferCredentials(items []TransferCredential) error {
	if len(items) > limits.DNSCredentials {
		return fault.Invalid("DNS 凭据数量超过限制")
	}
	seen := map[string]bool{}
	for _, c := range items {
		if !transferUUID.MatchString(c.ID) || seen[c.ID] || !utf8.ValidString(c.Name) || strings.TrimSpace(c.Name) == "" || len(c.Name) > 128 || strings.ContainsAny(c.Name, "\x00\r\n") {
			return fault.Invalid("迁移 DNS 凭据无效")
		}
		seen[c.ID] = true
		if _, err := validateSecrets(c.Provider, c.Secrets); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ImportCredentials(ctx context.Context, tx *sql.Tx, items []TransferCredential, ids map[string]string) error {
	if err := ValidateTransferCredentials(items); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_credentials").Scan(&count); err != nil {
		return err
	}
	if count+len(items) > limits.DNSCredentials {
		return fault.Conflict("目标 DNS 凭据容量不足")
	}
	for _, c := range items {
		id := ids[c.ID]
		if !transferUUID.MatchString(id) {
			return fault.Invalid("DNS 凭据映射无效")
		}
		names, err := validateSecrets(c.Provider, c.Secrets)
		if err != nil {
			return err
		}
		fields, err := json.Marshal(names)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(c.Secrets)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "INSERT INTO dns_credentials(id,name,provider,version,secrets,field_names,created_at,updated_at) VALUES(?,?,?,1,?,?,?,?)", id, c.Name, c.Provider, s.Vault.Seal(raw, "acme:dns:"+id), string(fields), now, now); err != nil {
			return err
		}
	}
	return nil
}
