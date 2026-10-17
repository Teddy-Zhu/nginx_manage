package certificates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"nginxpanel/internal/limits"
)

// StoreIssued participates in the order transaction: a certificate version and
// the order pointing to it become durable together, before DNS cleanup finishes.
func (s *Service) StoreIssued(ctx context.Context, tx *sql.Tx, id, versionID, name, notes, chain, key, environment string) error {
	if !uuid.MatchString(id) || !uuid.MatchString(versionID) || (environment != "production" && environment != "staging") {
		return errors.New("invalid issued certificate identity")
	}
	pair, err := Parse(chain, key)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := pair.ValidateEnvironment(now, environment); err != nil {
		return err
	}
	var ordinal int64
	err = tx.QueryRowContext(ctx, "SELECT version FROM certificates WHERE id=?", id).Scan(&ordinal)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&count); err != nil {
			return err
		}
		if count >= limits.Certificates {
			return errors.New("certificate quota reached")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO certificates(id,name,notes,version,latest_version_id,source,created_at,updated_at) VALUES(?,?,?,1,?,'acme',?,?)", id, name, notes, versionID, now.Unix(), now.Unix()); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id=? AND pruned_at=0", id).Scan(&count); err != nil {
			return err
		}
		if count >= limits.CertificateVersions {
			return errors.New("certificate version quota reached")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE certificates SET name=?,notes=?,source='acme',version=version+1,latest_version_id=?,updated_at=? WHERE id=?", name, notes, versionID, now.Unix(), id); err != nil {
			return err
		}
	}
	summary, err := json.Marshal(pair.Summary)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO certificate_versions(id,certificate_id,ordinal,fullchain,private_key,summary,created_at,environment) VALUES(?,?,?,?,?,?,?,?)", versionID, id, ordinal+1, s.Vault.Seal([]byte(pair.ChainPEM), purpose(id, versionID, "chain")), s.Vault.Seal([]byte(pair.KeyPEM), purpose(id, versionID, "key")), string(summary), now.Unix(), environment)
	return err
}
