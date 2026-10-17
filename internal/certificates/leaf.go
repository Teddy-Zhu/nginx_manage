package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Leaf reads only the public chain. ARI never needs to decrypt a private key.
func (s *Service) Leaf(ctx context.Context, q reader, id, version string) (*x509.Certificate, error) {
	var sealed []byte
	if err := q.QueryRowContext(ctx, "SELECT fullchain FROM certificate_versions WHERE certificate_id=? AND id=? AND pruned_at=0", id, version).Scan(&sealed); err != nil {
		return nil, err
	}
	chain, err := s.Vault.Open(sealed, purpose(id, version, "chain"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("stored certificate chain is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}
