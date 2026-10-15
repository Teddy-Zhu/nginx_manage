package certificates

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
)

type Transfer struct {
	Name     string   `json:"name"`
	Notes    string   `json:"notes"`
	Latest   bool     `json:"latest"`
	Material Material `json:"material"`
}

func (s *Service) Export(ctx context.Context, tx *sql.Tx, references []string) ([]Transfer, error) {
	paths := append([]string{}, references...)
	rows, err := tx.QueryContext(ctx, "SELECT id,latest_version_id FROM certificates ORDER BY id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, version string
		if err = rows.Scan(&id, &version); err != nil {
			rows.Close()
			return nil, err
		}
		paths = append(paths, Path(id, version, "fullchain"))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// Existing per-publication material budgets also bound a migration export.
	materials, err := s.Materials(ctx, tx, paths)
	if err != nil {
		return nil, err
	}
	out := make([]Transfer, 0, len(materials))
	for _, m := range materials {
		t := Transfer{Material: m}
		if err := tx.QueryRowContext(ctx, "SELECT name,notes,latest_version_id=? FROM certificates WHERE id=?", m.VersionID, m.CertificateID).Scan(&t.Name, &t.Notes, &t.Latest); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func ValidateTransfer(items []Transfer) error {
	if len(items) > limits.CertificateReferences {
		return fault.Invalid("迁移证书版本过多")
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	latest := map[string]int{}
	total := 0
	for _, item := range items {
		m := item.Material
		total += len(m.FullchainPEM) + len(m.PrivateKeyPEM)
		counts[m.CertificateID]++
		if !m.ValidIdentity() || seen[m.VersionID] || counts[m.CertificateID] > limits.CertificateVersions || total > limits.CertificateBundleBytes || !utf8.ValidString(item.Name) || !utf8.ValidString(item.Notes) || strings.TrimSpace(item.Name) == "" || len(item.Name) > 128 || len(item.Notes) > 2048 || strings.ContainsAny(item.Name+item.Notes, "\x00") {
			return fault.Invalid("迁移证书身份、名称、数量或大小无效")
		}
		seen[m.VersionID] = true
		if item.Latest {
			latest[m.CertificateID]++
		}
		if _, err := Parse(m.FullchainPEM, m.PrivateKeyPEM); err != nil {
			return fault.Invalid(err.Error())
		}
	}
	for id := range counts {
		if latest[id] != 1 {
			return fault.Invalid("每个迁移证书须有一个明确的最新版本")
		}
	}
	return nil
}

// Import creates new logical resources; no source ciphertext or identity is reused.
func (s *Service) Import(ctx context.Context, tx *sql.Tx, items []Transfer, ids, versions map[string]string) error {
	if err := ValidateTransfer(items); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&count); err != nil {
		return err
	}
	if count+len(ids) > limits.Certificates {
		return fault.Conflict("目标证书容量不足")
	}
	ordinals := map[string]int{}
	now := time.Now().Unix()
	for _, item := range items {
		m := item.Material
		id, version := ids[m.CertificateID], versions[m.VersionID]
		if !uuid.MatchString(id) || !uuid.MatchString(version) {
			return fault.Invalid("证书映射无效")
		}
		pair, err := Parse(m.FullchainPEM, m.PrivateKeyPEM)
		if err != nil {
			return err
		}
		summary, err := json.Marshal(pair.Summary)
		if err != nil {
			return err
		}
		ordinals[id]++
		if ordinals[id] == 1 {
			if _, err := tx.ExecContext(ctx, "INSERT INTO certificates(id,name,notes,version,latest_version_id,source,created_at,updated_at) VALUES(?,?,?,1,?,'manual',?,?)", id, item.Name, item.Notes, version, now, now); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO certificate_versions(id,certificate_id,ordinal,fullchain,private_key,summary,created_at,environment) VALUES(?,?,?,?,?,?,?,?)", version, id, ordinals[id], s.Vault.Seal([]byte(pair.ChainPEM), purpose(id, version, "chain")), s.Vault.Seal([]byte(pair.KeyPEM), purpose(id, version, "key")), string(summary), now, m.Environment); err != nil {
			return err
		}
		if item.Latest {
			if _, err := tx.ExecContext(ctx, "UPDATE certificates SET latest_version_id=? WHERE id=?", version, id); err != nil {
				return err
			}
		}
	}
	return nil
}
