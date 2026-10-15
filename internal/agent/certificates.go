package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/certificates"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

// Certificate versions are never overwritten. Partial preparation cannot change
// the active revision; the journal is durable before the first version write.
func (n *Nginx) prepareCertificates(p *nginxconfig.Parsed, materials []certificates.Material) error {
	uses, err := p.CertificateUses()
	if err != nil {
		return err
	}
	wanted := map[string]string{}
	for _, use := range uses {
		id, version, _, _ := certificates.Reference(use.Path)
		if prior, exists := wanted[version]; exists && prior != id {
			return errors.New("certificate version identity mismatch")
		}
		wanted[version] = id
	}
	if len(materials) != len(wanted) {
		return errors.New("certificate bundle does not match revision")
	}
	total := 0
	seen := map[string]bool{}
	for _, material := range materials {
		total += len(material.FullchainPEM) + len(material.PrivateKeyPEM)
		if !material.ValidIdentity() || wanted[material.VersionID] != material.CertificateID || seen[material.VersionID] || total > limits.CertificateBundleBytes {
			return errors.New("invalid certificate material bundle")
		}
		seen[material.VersionID] = true
	}
	if err := p.ValidateTLS(materials); err != nil {
		return err
	}
	for _, material := range materials {
		pair, err := certificates.Parse(material.FullchainPEM, material.PrivateKeyPEM)
		if err != nil {
			return err
		}
		if err := n.storeCertificate(material.CertificateID, material.VersionID, pair); err != nil {
			return err
		}
	}
	return nil
}
func (n *Nginx) storeCertificate(id, version string, pair *certificates.Pair) error {
	root := filepath.Join(n.DataDir, "certificates")
	parent := filepath.Join(root, id)
	target := filepath.Join(parent, version)
	if err := secure.RootDirectory(parent, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(target); err == nil {
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 2 {
			return ErrExternalChange
		}
		for kind, want := range map[string]string{"fullchain": pair.ChainPEM, "privatekey": pair.KeyPEM} {
			data, err := n.certificateFile(certificates.Path(id, version, kind))
			if err != nil || !bytes.Equal(data, []byte(want)) {
				return ErrExternalChange
			}
		}
		for _, dir := range []string{target, parent, root, n.DataDir} {
			if err := syncDir(dir); err != nil {
				return err
			}
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if entry.Name() != "ca" {
			count++
		}
	}
	if count > limits.Certificates {
		return errors.New("certificate directory quota reached")
	}
	entries, err = os.ReadDir(parent)
	if err != nil {
		return err
	}
	if len(entries) >= limits.CertificateVersions {
		return errors.New("certificate version quota reached")
	}
	tmp := filepath.Join(parent, ".tmp-"+secure.ID())
	if err := os.Mkdir(tmp, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := durableFile(filepath.Join(tmp, "fullchain.pem"), []byte(pair.ChainPEM), 0600, 0); err != nil {
		return err
	}
	if err := durableFile(filepath.Join(tmp, "privatekey.pem"), []byte(pair.KeyPEM), 0600, 0); err != nil {
		return err
	}
	if err := syncDir(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	for _, dir := range []string{parent, root, n.DataDir} {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}
